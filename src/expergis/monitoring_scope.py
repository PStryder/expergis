"""Opt-in task monitoring policy. No machine discovery or credential reads."""
import fnmatch
import re
import time
from pathlib import Path

from expergis.watch_scope import checked_local_path

DENIED_PARTS = {'.ssh', '.aws', '.azure', '.gnupg', '.codex', '.git',
    'expergisruntime', 'credentials', 'secrets', 'browser', 'user data',
    'firefox', 'chrome', 'chromium', 'edge', 'brave-browser', 'profiles'}
DENIED_NAMES = ('.env*', '*.pem', '*.key', '*.pfx', '*.p12', '*.kdbx',
    '*credential*', '*secret*', 'id_rsa*', 'id_ed25519*', 'id_ecdsa*',
    'cookies*', 'login data*', 'key4.db', 'logins.json', 'ntuser.dat*')
GENERIC_IMAGES = {'python', 'pythonw', 'node', 'cmd', 'powershell', 'pwsh',
                  'bash', 'sh', 'wscript', 'cscript', 'java', 'dotnet', 'perl', 'ruby',
                  'wsl', 'mshta', 'rundll32', 'regsvr32', 'conhost'}


def safe_metadata_path(value, *, missing=False):
    path = Path(value)
    # ADS, device aliases and NT namespaces are never monitoring targets.
    if ':' in str(path)[len(path.drive):] or any(p.endswith((' ', '.')) for p in path.parts):
        raise PermissionError('Ambiguous path')
    if any(p.lower() in DENIED_PARTS for p in path.parts) or any(
            fnmatch.fnmatchcase(path.name.lower(), pattern) for pattern in DENIED_NAMES):
        raise PermissionError('Private location excluded')
    path = checked_local_path(str(path), allow_missing_leaf=missing)
    try:
        info = path.stat()
        if path.is_file() and info.st_nlink != 1:
            raise PermissionError('Hard-linked files excluded')
    except FileNotFoundError:
        if not missing:
            raise
    return path


def image_name(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', value):
        raise ValueError('Exact executable basename required')
    return value.lower() if value.lower().endswith('.exe') else value.lower() + '.exe'


def validate_watch(args, options, *, restore=False, now=None):
    """Validate before setup and replay; internal fields cannot come from callers."""
    settings = args.get('config')
    if not isinstance(settings, dict):
        raise ValueError('Configuration required')
    if not restore and any(k.startswith('_') for k in settings):
        raise ValueError('Reserved configuration key')
    now = time.time() if now is None else now
    ttl = settings.get('ttl_seconds', 86400)
    coalesce = settings.get('coalesce_seconds', 5)
    if type(ttl) is not int or not 60 <= ttl <= 604800:
        raise ValueError('ttl_seconds must be 60..604800')
    if type(coalesce) is not int or not 1 <= coalesce <= 60:
        raise ValueError('coalesce_seconds must be 1..60')
    expiry = settings.get('_expires_at') if restore else None
    if expiry is not None and (type(expiry) not in (int, float) or not 0 < expiry <= now + 604800):
        raise ValueError('Invalid saved expiry')
    settings['_expires_at'] = expiry if expiry is not None else now + ttl
    settings['_monitoring_v2'] = True
    settings['coalesce_seconds'] = coalesce
    if restore and settings['_expires_at'] <= now:
        return  # Audit-only expired definitions never inspect or restart their old paths.
    kind = args.get('plugin_type')
    if kind == 'file_watcher':
        roots = [checked_local_path(p) for p in options.get('allowed_roots', [])]
        paths = settings.get('paths')
        patterns = settings.get('patterns', ['*'])
        if (not isinstance(paths, list) or not 1 <= len(paths) <= 32
                or not isinstance(patterns, list) or not 1 <= len(patterns) <= 32
                or any(not isinstance(p, str) or not p or len(p) > 256 or '/' in p or '\\' in p for p in patterns)
                or settings.get('recursive', False)):
            raise ValueError('Bounded nonrecursive paths required')
        for value in paths:
            path = safe_metadata_path(value, missing=restore)
            if not any(path == root or root in path.parents for root in roots):
                raise PermissionError('Path outside approved roots')
            if path in roots and any(any(c in p for c in '*?[') for p in patterns):
                raise PermissionError('Select a file or subdirectory, not a blanket root watch')
            if path.is_dir():
                for pattern in patterns:
                    if not any(c in pattern for c in '*?['):
                        safe_metadata_path(str(path / pattern), missing=True)
        settings['_strict_local_paths'] = True
    elif kind == 'process_watcher':
        if not options.get('allow_selected_processes', False):
            raise PermissionError('Process monitoring disabled')
        names = settings.get('process_names', [])
        identities = settings.get('processes', [])
        if (not isinstance(names, list) or not isinstance(identities, list)
                or not 1 <= len(names) + len(identities) <= 16):
            raise ValueError('Select at most 16 processes')
        for name in names:
            if image_name(name)[:-4] in GENERIC_IMAGES or re.fullmatch(r'pythonw?[0-9.]*', image_name(name)[:-4]):
                raise PermissionError('Generic runtimes require PID and creation_time')
        for item in identities:
            if (not isinstance(item, dict) or set(item) != {'pid', 'creation_time'}
                    or type(item['pid']) is not int or not 1 <= item['pid'] <= 0xffffffff
                    or not isinstance(item['creation_time'], str)
                    or not re.fullmatch(r'[1-9][0-9]{0,19}', item['creation_time'])):
                raise ValueError('PID and decimal Windows FILETIME creation_time required')
        interval = settings.get('poll_interval_ms', 5000)
        if type(interval) is not int or not 1000 <= interval <= 3600000:
            raise ValueError('Process interval must be at least one second')
    elif kind == 'service_watcher':
        names = settings.get('service_names')
        allowed = options.get('allowed_service_names', [])
        if names != ['SemSearch'] or 'SemSearch' not in allowed:
            raise PermissionError('Only explicitly approved SemSearch status is supported')
    else:
        raise PermissionError('Watcher type outside task monitoring policy')
