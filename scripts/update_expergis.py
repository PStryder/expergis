"""User-operated offline update; never execute --apply/--rollback from agent tools."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PureWindowsPath
import re
import subprocess
import sys
import time
import zipfile


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def regular(path):
    for part in (path, *path.parents):
        if part.is_symlink() or (part.exists() and getattr(part.lstat(), 'st_file_attributes', 0) & 0x400):
            raise ValueError('REPARSE_PATH_REFUSED')
    if path.exists() and path.is_file() and path.stat().st_nlink != 1:
        raise ValueError('HARDLINK_REFUSED')


def verify_bundle(bundle, expected):
    regular(bundle/'manifest.json')
    if not re.fullmatch('[0-9a-f]{64}', expected) or digest(bundle/'manifest.json') != expected:
        raise ValueError('MANIFEST_MISMATCH')
    data = json.loads((bundle/'manifest.json').read_text())
    if (not re.fullmatch('[0-9a-f]{40}', data['from_commit'])
            or not re.fullmatch('[0-9a-f]{40}', data['to_commit'])):
        raise ValueError('INVALID_COMMIT')
    if data.get('profile', 'monitoring_v2') not in ('monitoring_v2', 'job_inbox_code_only', 'catalog_diagnostics_only'):
        raise ValueError('UNKNOWN_UPDATE_PROFILE')
    required = {'activation_helper.py', 'new/expergis-0.1.0-py3-none-any.whl',
        'old/expergis-0.1.0-py3-none-any.whl', 'new/requirements.lock', 'old/requirements.lock'}
    if set(data['files']) != required:
        raise ValueError('INVALID_BUNDLE_LAYOUT')
    for name, checksum in data['files'].items():
        path = bundle/name
        regular(path)
        if not path.is_file() or digest(path) != checksum:
            raise ValueError('BUNDLE_FILE_MISMATCH')
    return data


def helper_from(bundle):
    spec = importlib.util.spec_from_file_location('verified_activation', bundle/'activation_helper.py')
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    return helper


def approved_root_list(values):
    if not isinstance(values, list) or not 1 <= len(values) <= 16:
        raise ValueError('APPROVED_ROOTS_REQUIRED')
    for value in values:
        if not isinstance(value, str) or not value or len(value) > 32768:
            raise ValueError('INVALID_APPROVED_ROOT')
        path = PureWindowsPath(value) if PureWindowsPath(value).drive else Path(value)
        if not path.is_absolute() or value.startswith(('\\\\', '//')) or '..' in path.parts:
            raise ValueError('INVALID_APPROVED_ROOT')
    if len({value.casefold() for value in values}) != len(values):
        raise ValueError('DUPLICATE_APPROVED_ROOT')
    return list(values)


def updated_config(original, signals, profile='monitoring_v2', approved_roots=None):
    result = json.loads(json.dumps(original))
    options = result['expergis']['mcp_events']
    if profile == 'catalog_diagnostics_only':
        if (options.get('allow_job_event_contents') is not True
                or options.get('job_event_inbox') != str(signals/'job-events')):
            raise ValueError('UNEXPECTED_EXISTING_SCOPE')
        base=json.loads(json.dumps(original))
        base['expergis']['mcp_events'].pop('allow_job_event_contents')
        base['expergis']['mcp_events'].pop('job_event_inbox')
        updated_config(base,signals,profile='job_inbox_code_only',approved_roots=approved_roots)
        return result  # Preserve the already approved inbox and all other configuration.
    if profile == 'job_inbox_code_only':
        roots = approved_root_list(options.get('allowed_roots'))
        if approved_roots is not None and roots != approved_root_list(approved_roots):
            raise ValueError('UNEXPECTED_EXISTING_SCOPE')
        if (options.get('monitoring_policy_version') != 2
                or options.get('allowed_process_names') != []
                or options.get('allow_selected_processes') is not True
                or options.get('allowed_service_names') != ['SemSearch']
                or options.get('allow_schedules') is not False
                or options.get('allow_job_event_contents', False) is not False):
            raise ValueError('UNEXPECTED_EXISTING_SCOPE')
        return result  # Package only: no content-read permission or inbox creation.
    if profile != 'monitoring_v2':
        raise ValueError('UNKNOWN_UPDATE_PROFILE')
    if (options.get('allowed_roots') != [str(signals)]
            or options.get('allowed_process_names') != []
            or options.get('allow_schedules') is not False
            or options.get('monitoring_policy_version') is not None):
        raise ValueError('UNEXPECTED_EXISTING_SCOPE')
    roots = approved_root_list(approved_roots)
    if str(signals) not in roots:
        raise ValueError('EXISTING_SIGNALS_ROOT_REQUIRED')
    options.update(monitoring_policy_version=2,
        allowed_roots=roots,
        allow_selected_processes=True, allowed_service_names=['SemSearch'])
    return result


def installed_matches(helper, wheel):
    package = helper.ROOT/'venv/Lib/site-packages'
    with zipfile.ZipFile(wheel) as archive:
        names = [n for n in archive.namelist() if n.startswith('expergis/') and n.endswith('.py')]
        expected = {Path(n).as_posix() for n in names}
        actual = {p.relative_to(package).as_posix() for p in (package/'expergis').rglob('*.py')}
        if not names or actual != expected:
            raise ValueError('INSTALLED_PACKAGE_MISMATCH')
        for name in names:
            target = package/name
            regular(target)
            if digest(target) != hashlib.sha256(archive.read(name)).hexdigest():
                raise ValueError('INSTALLED_PACKAGE_MISMATCH')


def command(helper, args):
    result = subprocess.run([str(helper.PYTHON), '-I', *map(str, args)], check=False)
    if result.returncode:
        raise ValueError('OFFLINE_COMMAND_FAILED')


def trusted_runtime(helper, bundle, action):
    # Recovery also works if a failed pip replacement removed the installed module.
    command(helper, ['-c',
        'import sys;sys.path.insert(0,sys.argv.pop(1));from expergis.windows_runtime import main;raise SystemExit(main())',
        bundle/'old/expergis-0.1.0-py3-none-any.whl', action, '--directory', helper.ROOT])


def stop(helper, bundle):
    task = helper.task_info()
    if not helper.verify_task(task):
        raise ValueError('TASK_IDENTITY_MISMATCH')
    if task['state'] == 'Ready':
        return
    trusted_runtime(helper, bundle, 'stop')
    deadline = time.monotonic()+45
    while time.monotonic() < deadline:
        task = helper.task_info()
        if not helper.verify_task(task):
            raise ValueError('TASK_CHANGED')
        if task['state'] == 'Ready':
            return
        time.sleep(1)
    raise ValueError('GRACEFUL_STOP_TIMEOUT_NO_FILES_CHANGED')


def install(helper, bundle, which):
    command(helper, ['-m', 'pip', '--isolated', 'install', '--no-index', '--no-deps',
        '--force-reinstall', '--require-hashes', '--find-links', bundle/which,
        '-r', bundle/which/'requirements.lock'])
    installed_matches(helper, bundle/which/'expergis-0.1.0-py3-none-any.whl')
    command(helper, ['-m', 'pip', '--isolated', 'check'])


def atomic_config(path, data):
    temporary = path.with_name('update-config.tmp')
    regular(path)
    regular(temporary)
    with temporary.open('xb') as out:
        out.write(data)
    temporary.replace(path)


def start(helper):
    # A readiness timestamp must postdate this launch, not just be recently cached.
    launched = datetime.now(timezone.utc)
    result = helper.ps("Start-ScheduledTask -TaskName 'Expergis User Runtime' -ErrorAction Stop")
    if result.returncode:
        raise ValueError('TASK_START_FAILED')
    deadline = time.monotonic()+120
    while time.monotonic() < deadline:
        status = helper.ROOT/'status.json'
        regular(status)
        if status.exists():
            value = json.loads(status.read_text())
            if datetime.fromisoformat(value['updated_at']) >= launched:
                if value.get('state') == 'failed':
                    raise ValueError('RUNTIME_FAILED')
                if value.get('state') == 'ready':
                    task = helper.task_info()
                    if not helper.verify_task(task) or task['state'] != 'Running':
                        raise ValueError('TASK_NOT_RUNNING_AS_CONFIGURED')
                    print('READY: fresh runtime heartbeat; original Interactive/Limited task verified.')
                    return
        time.sleep(2)
    raise ValueError('READINESS_TIMEOUT')


def execute(helper, bundle, manifest, *, rollback=False):
    helper.user_context()
    if not helper.verify_task(helper.task_info()):
        raise ValueError('TASK_IDENTITY_MISMATCH')
    trusted_runtime(helper, bundle, 'preflight')
    config = helper.ROOT/'runtime.json'
    regular(config)
    backup = helper.ROOT/('update-backup-'+manifest['to_commit'][:12])
    regular(backup)
    if rollback:
        old = backup/'runtime-before.json'
        regular(old)
        original = old.read_bytes()
        expected = updated_config(json.loads(original), helper.SIGNALS, profile=manifest.get('profile', 'monitoring_v2'),
            approved_roots=manifest.get('approved_roots'))
        if json.loads(config.read_bytes()) not in (json.loads(original), expected):
            raise ValueError('CONFIG_CHANGED_ROLLBACK_REFUSED')
        stop(helper, bundle)
        install(helper, bundle, 'old')
        atomic_config(config, original)
        command(helper, ['-m', 'expergis.windows_runtime', 'preflight', '--directory', helper.ROOT])
        start(helper)
        print('ROLLED_BACK:', manifest['from_commit'])
        return
    installed_matches(helper, bundle/'old/expergis-0.1.0-py3-none-any.whl')
    original = config.read_bytes()
    updated = updated_config(json.loads(original), helper.SIGNALS, profile=manifest.get('profile', 'monitoring_v2'),
            approved_roots=manifest.get('approved_roots'))
    if backup.exists():
        raise ValueError('EXISTING_UPDATE_BACKUP_USE_ROLLBACK_OR_REVIEW')
    # Preflight new roots before taking the working runtime down.
    for value in updated['expergis']['mcp_events']['allowed_roots']:
        root = Path(value)
        regular(root)
        if not root.is_dir():
            raise ValueError('APPROVED_ROOT_UNAVAILABLE')
    stop(helper, bundle)
    backup.mkdir()
    (backup/'runtime-before.json').write_bytes(original)
    (backup/'checkpoint.json').write_text(json.dumps({k:manifest[k] for k in ('from_commit','to_commit')}))
    try:
        install(helper, bundle, 'new')
        if updated != json.loads(original):
            atomic_config(config, json.dumps(updated, indent=2).encode())
        command(helper, ['-m', 'expergis.windows_runtime', 'preflight', '--directory', helper.ROOT])
        start(helper)
    except Exception:
        print('Update did not confirm readiness; restoring the previous package and scope.')
        stop(helper, bundle)
        install(helper, bundle, 'old')
        atomic_config(config, original)
        start(helper)
        raise ValueError('UPDATE_FAILED_PREVIOUS_CHECKPOINT_RESTORED') from None
    print('UPDATED:', manifest['to_commit'])
    if manifest.get('profile') == 'catalog_diagnostics_only':
        print('Existing configuration preserved; no permissions changed.')
    elif manifest.get('profile') == 'job_inbox_code_only':
        print('Approved scope preserved; structured-content access not enabled by this update.')
    else:
        print('Scope v2 enabled; schedules disabled.')
    print('No watcher, subscription, inbox or test event created.')
    print('Credentials, database, policy, tunnel bundle and task definition were not modified.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', required=True, type=Path)
    parser.add_argument('--manifest-sha256', required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--apply', action='store_true')
    mode.add_argument('--rollback', action='store_true')
    args = parser.parse_args()
    try:
        manifest = verify_bundle(args.bundle, args.manifest_sha256)
        print('Verified offline update:', manifest['from_commit'], '->', manifest['to_commit'])
        if not (args.apply or args.rollback):
            print('VERIFY ONLY: no installed runtime files, credentials, processes or tasks accessed.')
            return 0
        if os.name != 'nt' or not sys.stdin.isatty():
            raise ValueError('NORMAL_INTERACTIVE_WINDOWS_TERMINAL_REQUIRED')
        execute(helper_from(args.bundle), args.bundle, manifest, rollback=args.rollback)
        return 0
    except Exception as exc:
        reason = str(exc) if isinstance(exc, ValueError) and re.fullmatch('[A-Z_0-9]+', str(exc)) else type(exc).__name__
        print('UPDATE STOPPED:', reason)
        print('Keep the verified bundle and backup. Do not re-enter or expose the stored key.')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
