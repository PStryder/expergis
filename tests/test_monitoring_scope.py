import asyncio
import json
import os
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from expergis.monitoring_scope import validate_watch, safe_metadata_path


def file_args(path, **settings):
    return {'watcher_id': 'job-test', 'plugin_type': 'file_watcher',
            'config': {'paths': [str(path)], **settings}}


def test_root_requires_specific_file(tmp_path):
    options = {'allowed_roots': [str(tmp_path)]}
    with pytest.raises(PermissionError):
        validate_watch(file_args(tmp_path), options)
    args = file_args(tmp_path, patterns=['future.txt'])
    validate_watch(args, options, now=1000)
    assert args['config']['_expires_at'] == 87400
    validate_watch(args, options, restore=True, now=2000)
    assert args['config']['_expires_at'] == 87400
    with pytest.raises(ValueError):
        validate_watch(args, options)


@pytest.mark.parametrize('name', ['.env', 'server.pem', 'secret.txt', 'id_rsa', 'login data', '.ssh/a.txt', 'Profiles/a.txt'])
def test_sensitive_names_excluded(tmp_path, name):
    path = tmp_path/name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch()
    with pytest.raises(PermissionError):
        safe_metadata_path(str(path))


def test_hardlink_excluded(tmp_path):
    path = tmp_path/'plain.txt'
    path.touch()
    os.link(path, tmp_path/'second.txt')
    with pytest.raises(PermissionError):
        safe_metadata_path(str(path))


def test_scope_scan_no_contents_and_exclusions(tmp_path, monkeypatch):
    from expergis.plugins.file_watcher import FileWatcherPlugin
    sub = tmp_path/'job'
    sub.mkdir()
    (sub/'ok.txt').touch()
    (sub/'.env').touch()
    (sub/'nested').mkdir()
    (sub/'nested'/'hidden.txt').touch()
    args = file_args(sub)
    validate_watch(args, {'allowed_roots': [str(tmp_path)]})
    plugin = FileWatcherPlugin('job-test', args['config'])
    plugin.paths, plugin.patterns = [sub], ['*']
    assert list(plugin._scan()) == [str(sub/'ok.txt')]
    os.link(sub/'ok.txt', sub/'alias.txt')
    assert plugin._scan() == {}


@pytest.mark.parametrize('settings', [
    {'recursive': True}, {'patterns': ['../a']}, {'ttl_seconds': 0},
    {'ttl_seconds': True}, {'coalesce_seconds': 0}, {'_expires_at': 1}])
def test_bad_file_settings(tmp_path, settings):
    with pytest.raises((ValueError, PermissionError)):
        validate_watch(file_args(tmp_path, **settings), {'allowed_roots': [str(tmp_path)]})


@pytest.mark.parametrize('name', ['python', 'python3.11.exe', 'node', 'pwsh.exe', '*', '../task.exe'])
def test_generic_or_ambiguous_process_rejected(name):
    args = {'plugin_type': 'process_watcher', 'config': {'process_names': [name]}}
    with pytest.raises((ValueError, PermissionError)):
        validate_watch(args, {'allow_selected_processes': True})


def test_process_identity_and_service_scope():
    args = {'plugin_type': 'process_watcher', 'config': {'processes': [{'pid': 123, 'creation_time': '123456789'}]}}
    validate_watch(args, {'allow_selected_processes': True})
    service = {'plugin_type': 'service_watcher', 'config': {'service_names': ['SemSearch']}}
    validate_watch(service, {'allowed_service_names': ['SemSearch']})
    for name in ('Other', 'semsearch'):
        with pytest.raises(PermissionError):
            validate_watch({'plugin_type': 'service_watcher', 'config': {'service_names': [name]}}, {'allowed_service_names': ['SemSearch']})
    with pytest.raises(PermissionError):
        validate_watch({'plugin_type': 'schedule_watcher', 'config': {'cron': '* * * * *'}}, {'allow_schedules': True})


def test_selected_query_and_pid_reuse(monkeypatch):
    from expergis import windows_observers as obs
    calls = []
    def output(command, **kwargs):
        calls.append(command)
        return '"build.exe","100","Console","1","1 K"'
    monkeypatch.setattr(obs.subprocess, 'check_output', output)
    monkeypatch.setattr(obs, 'process_identity', lambda pid: {'pid': pid, 'creation_time': '222', 'process_name': 'build.exe'})
    assert obs.selected_processes([], [{'pid': 100, 'creation_time': '111'}]) == {}
    assert obs.selected_processes(['build.exe'], [])[(100,'222')]['pid'] == 100
    assert '/FI' in calls[0] and 'IMAGENAME eq build.exe' in calls[0]


@pytest.mark.asyncio
async def test_process_stop_identity_and_failure(monkeypatch):
    from expergis.plugins.process_watcher import ProcessWatcherPlugin
    plugin = ProcessWatcherPlugin('job-test', {'_monitoring_v2': True})
    item = {'pid': 10, 'creation_time': '111', 'process_name': 'python.exe'}
    plugin._selected = {(10, '111'): item}
    plugin.poll_interval_ms = 1
    plugin._scan_selected = lambda: {}
    events=[]
    async def emit(event):
        events.append(event)
        plugin._running = False
    await plugin.watch(emit)
    assert len(events) == 1 and events[0].details == item
    plugin._selected = {(10, '111'): item}
    def denied():
        raise PermissionError('synthetic')
    plugin._scan_selected = denied
    with pytest.raises(PermissionError):
        await plugin.watch(emit)
    assert len(events) == 1


@pytest.mark.asyncio
async def test_expiry_revocation_coalescing_and_restart(monkeypatch):
    from expergis import server as srv
    from expergis.plugins.base import Event
    config={'_monitoring_v2': True, '_expires_at': time.time()+.03, 'coalesce_seconds': 5}
    plugin = SimpleNamespace(watch=AsyncMock(side_effect=lambda emit: None), teardown=AsyncMock())
    async def idle(emit):
        await asyncio.sleep(60)
    plugin.watch = idle
    entry=srv.WatcherEntry('job-test', plugin, 'file_watcher', '', config)
    service=SimpleNamespace(authorize=lambda *args: True)
    dispatcher=SimpleNamespace(event_service=service, owner='synthetic', dispatch=AsyncMock())
    monkeypatch.setattr(srv, '_dispatcher', dispatcher)
    for _ in range(2):
        await srv._emit_event(entry, Event('file_watcher','job-test','created','synthetic'))
    assert dispatcher.dispatch.await_count == 1 and entry.coalesced_count == 1
    await srv._run_watcher(entry)
    assert entry.status == 'expired'
    plugin.teardown.assert_awaited_once()
    await srv._emit_event(entry, Event('file_watcher','job-test','created','later'))
    assert dispatcher.dispatch.await_count == 1
    config['_expires_at'] = time.time()+60
    service.authorize=lambda *args: False
    await srv._run_watcher(entry)
    assert entry.status == 'revoked'


@pytest.mark.asyncio
async def test_expired_registration_does_not_start_plugin(monkeypatch):
    from expergis import server as srv
    fake = SimpleNamespace(setup=AsyncMock(), teardown=AsyncMock())
    monkeypatch.setitem(srv.PLUGIN_REGISTRY, 'synthetic', lambda *a: fake)
    monkeypatch.setattr(srv, '_watchers', {})
    monkeypatch.setattr(srv, '_dispatcher', SimpleNamespace(event_service=None))
    result = await srv._handle_watch({'watcher_id':'job-expired','plugin_type':'synthetic',
        'config':{'_monitoring_v2':True,'_expires_at':time.time()-1}})
    assert json.loads(result[0].text)['status'] == 'watching'
    assert srv._watchers['job-expired'].status == 'expired'
    fake.setup.assert_not_awaited()


@pytest.mark.asyncio
async def test_service_states_use_synthetic_queries(monkeypatch):
    from expergis.plugins.service_watcher import ServiceWatcherPlugin
    plugin = ServiceWatcherPlugin('job-test', {'service_names':['SemSearch']})
    monkeypatch.setattr(plugin, 'scan', lambda: {'state':'running','exit_code':None})
    await plugin.setup()
    plugin.interval = 1
    monkeypatch.setattr(plugin, 'scan', lambda: {'state':'stopped','exit_code':5})
    async def emit(event):
        assert event.details['previous_state'] == 'running' and event.details['exit_code'] == 5
        raise asyncio.CancelledError
    with pytest.raises(asyncio.CancelledError):
        await plugin.watch(emit)


@pytest.mark.skipif(os.name != 'nt', reason='Windows read-only synthetic child identity')
def test_native_process_identity_only_synthetic_child():
    import subprocess
    import sys
    from expergis.windows_observers import process_identity
    child = subprocess.Popen([sys.executable, '-I', '-c', 'import time; time.sleep(20)'],
        env={'SystemRoot': r'C:\Windows'}, creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        first = process_identity(child.pid)
        second = process_identity(child.pid)
        assert first == second and first['pid'] == child.pid
        assert first['creation_time'].isdigit()
        assert set(first) == {'pid', 'creation_time', 'process_name'}
    finally:
        child.terminate()
        child.wait(timeout=5)


def test_scm_only_query_rights(monkeypatch):
    from expergis import windows_observers as obs
    import ctypes
    class Function:
        def __init__(self, fn): self.fn=fn
        def __call__(self, *args): return self.fn(*args)
    rights=[]
    closed=[]
    def query(handle, level, buffer, size, needed):
        status=ctypes.cast(buffer, ctypes.POINTER(obs.ServiceStatus)).contents
        status.state=4
        return 1
    api=SimpleNamespace(
        OpenSCManagerW=Function(lambda a,b,right: rights.append(('manager',right)) or 1),
        OpenServiceW=Function(lambda h,name,right: rights.append((name,right)) or 2),
        CloseServiceHandle=Function(lambda h: closed.append(h)),
        QueryServiceStatusEx=Function(query))
    monkeypatch.setattr(obs,'libraries',lambda: (None,api))
    assert obs.service_status('SemSearch')['state']=='running'
    assert rights==[('manager',1),('SemSearch',4)] and closed==[2,1]
    with pytest.raises(PermissionError): obs.service_status('Other')


def test_expiry_survives_database_reopen_and_missing_target(tmp_path):
    from expergis.event_store import EventStore
    from .test_events import TestProtector
    target=tmp_path/'selected.txt'
    target.touch()
    args=file_args(target,ttl_seconds=60)
    options={'allowed_roots':[str(tmp_path)]}
    validate_watch(args, options, now=1000)
    path=tmp_path/'synthetic.db'
    store=EventStore(path,protector=TestProtector())
    store.save_watcher('synthetic','job-test',args)
    store.close()
    target.unlink()
    store=EventStore(path,protector=TestProtector())
    try:
        saved=store.watchers('synthetic')[0]
        validate_watch(saved,options,restore=True,now=1030)
        assert saved['config']['_expires_at']==1060
        validate_watch(saved,options,restore=True,now=1100)
        assert saved['config']['_expires_at']==1060
    finally: store.close()
