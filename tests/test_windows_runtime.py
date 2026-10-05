"""Operational tests use synthetic configuration, temporary storage and fake processes."""
import asyncio
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from expergis.watch_scope import checked_local_path
from expergis.auth0 import OwnerPolicy


def test_managed_prefix_is_explicit_and_revocable(tmp_path):
    path=tmp_path/'policy.json'
    data={'owner':'synthetic','enabled':True,'watcher_ids':[], 'tokens_valid_after':0}
    path.write_text(json.dumps(data))
    policy=OwnerPolicy(path,'synthetic')
    assert not policy('synthetic','job-build')
    data['managed_watcher_prefix']='job-'
    path.write_text(json.dumps(data))
    assert policy('synthetic','job-build')
    assert not policy('other','job-build') and not policy('synthetic','elsewhere')
    assert not policy('synthetic','job-../../escape')
    data['enabled']=False
    path.write_text(json.dumps(data))
    assert not policy('synthetic','job-build')


def test_local_scope_rejects_traversal_and_missing(tmp_path):
    assert checked_local_path(str(tmp_path)) == tmp_path.resolve()
    for value in ('relative', str(tmp_path/'..'/'elsewhere'), str(tmp_path/'missing'), '//host/share'):
        with pytest.raises((PermissionError,OSError)):
            checked_local_path(value)


@pytest.mark.skipif(os.name!='nt',reason='Windows directory junction boundary')
def test_junction_scope_and_scan_refuse_redirect(tmp_path):
    import subprocess
    from expergis.plugins.file_watcher import FileWatcherPlugin
    outside=tmp_path/'outside'
    outside.mkdir()
    link=tmp_path/'link'
    result=subprocess.run(['cmd.exe','/c','mklink','/J',str(link),str(outside)],capture_output=True)
    if result.returncode:
        pytest.skip('Junction creation unavailable')
    try:
        with pytest.raises(PermissionError): checked_local_path(str(link))
        watcher=FileWatcherPlugin('job-test',{'_strict_local_paths':True})
        watcher.paths=[link]
        with pytest.raises(PermissionError): watcher._scan()
    finally:
        link.rmdir()  # Remove only the junction, never traverse its target.


def test_runtime_config_requires_scope_and_does_not_fetch_credentials(tmp_path,monkeypatch):
    from expergis import windows_runtime as w
    binary=tmp_path/'synthetic-client.exe'
    binary.write_bytes(b'not executable; never started')
    config={'expergis':{'delivery_adapter':'mcp_events','watchers':[],
        'mcp_events':{'owner':'synthetic','allowed_roots':[],'allowed_process_names':[], 'allow_schedules':False},
        'auth0':{}},'tunnel':{'id':'tunnel_synthetic','client_path':str(binary),
        'sha256':hashlib.sha256(binary.read_bytes()).hexdigest()}}
    monkeypatch.setattr(w,'components',lambda cfg: None)
    path=tmp_path/'runtime.json'
    path.write_text(json.dumps(config))
    loaded,tunnel=w.load_config(tmp_path)
    from expergis.dispatcher import Dispatcher
    assert Dispatcher(loaded).adapter=='mcp_events'
    assert loaded['mcp_events']['database']==str(tmp_path/'events.db')
    assert loaded['auth0']['policy_file']==str(tmp_path/'policy.json')
    assert not (tmp_path/'events.db').exists()
    del config['expergis']['mcp_events']['allow_schedules']
    path.write_text(json.dumps(config))
    with pytest.raises(ValueError): w.load_config(tmp_path)


def test_tunnel_config_has_only_approved_origins_and_no_embedded_key(tmp_path):
    from expergis.windows_runtime import tunnel_configuration,tunnel_environment
    cfg=tunnel_configuration({'auth0':{'issuer':'https://issuer.example/'}},
        {'id':'tunnel_synthetic'},'http://127.0.0.1:8123',tmp_path/'health')
    assert cfg['mcp']['oauth_trusted_origins']==['http://127.0.0.1:8123','https://issuer.example']
    assert cfg['log']['format']=='json' and cfg['cloudflared']['managed'] is False
    assert cfg['control_plane']['api_key']=='env:CONTROL_PLANE_API_KEY'
    env=tunnel_environment('synthetic-not-a-credential',tmp_path)
    assert env['CONTROL_PLANE_API_KEY']=='synthetic-not-a-credential'
    assert 'OPENAI_API_KEY' not in env and 'HTTPS_PROXY' not in env


@pytest.mark.asyncio
async def test_supervisor_graceful_stop_and_child_failure_cleanup(tmp_path,monkeypatch):
    import uvicorn
    from expergis import server  # Load SDK before replacing subprocess.Popen.
    from expergis import windows_runtime as w, windows_process as processes
    class Server:
        def __init__(self,cfg): self.started=False; self.should_exit=False
        async def serve(self,sockets):
            assert sockets[0].getsockname()[0]=='127.0.0.1'
            self.started=True
            while not self.should_exit: await asyncio.sleep(.005)
    children=[]
    class Child:
        returncode=None
        def __init__(self,*a,**kw):
            assert kw['env']['CONTROL_PLANE_API_KEY']=='synthetic'
            assert kw['stdin']==w.subprocess.DEVNULL and kw['stdout']==w.subprocess.DEVNULL
            children.append(self)
        def poll(self): return self.returncode
        def terminate(self): self.returncode=0
        def wait(self,timeout): return self.returncode
    class Job:
        def attach(self,child): pass
        def close(self): pass
    monkeypatch.setattr(w,'load_config',lambda directory: ({'auth0':{'issuer':'https://issuer.example/'}},
        {'id':'tunnel_synthetic','client_path':'synthetic-never-executed'}))
    monkeypatch.setattr(w,'create_auth0_app',lambda config: object())
    monkeypatch.setattr(w,'DPAPIProtector',lambda: SimpleNamespace(open=lambda value:b'synthetic'))
    monkeypatch.setattr(uvicorn,'Config',lambda *a,**kw: None)
    monkeypatch.setattr(uvicorn,'Server',Server)
    monkeypatch.setattr(processes,'KillJob',Job)
    monkeypatch.setattr(processes,'TunnelMutex',lambda tid: Job())
    monkeypatch.setattr(w.subprocess,'Popen',Child)
    (tmp_path/'tunnel-key.dpapi').write_bytes(b'synthetic-test-ciphertext')
    async def ready(path):
        (tmp_path/'stop.request').touch()
        return True
    monkeypatch.setattr(w,'tunnel_ready',ready)
    await w.run(tmp_path)
    assert children[-1].poll()==0
    assert json.loads((tmp_path/'status.json').read_text())['state']=='stopped'
    # A dead tunnel must stop its server, preserve state, and record failure.
    def dead(*a,**kw):
        child=Child(*a,**kw); child.returncode=1; return child
    monkeypatch.setattr(w.subprocess,'Popen',dead)
    with pytest.raises(RuntimeError): await w.run(tmp_path)
    assert json.loads((tmp_path/'status.json').read_text())['state']=='failed'


@pytest.mark.skipif(os.name!='nt',reason='Windows named mutex')
def test_same_tunnel_supervisors_exclusive():
    from expergis.windows_process import TunnelMutex
    first=TunnelMutex('tunnel_synthetic_mutex_test')
    try:
        with pytest.raises(RuntimeError): TunnelMutex('tunnel_synthetic_mutex_test')
    finally:
        first.close()
    second=TunnelMutex('tunnel_synthetic_mutex_test')
    second.close()


@pytest.mark.skipif(os.name!='nt',reason='Windows ACL metadata helper')
@pytest.mark.parametrize('change',[
    {'daclPresent':False}, {'protected':False}, {'owner':'someone-else'},
    {'rules':[]}, {'rules':[{'sid':'S-1-1-0','allow':True}]},
])
def test_private_acl_fail_closed(tmp_path,monkeypatch,change):
    from expergis import windows_runtime as w
    data={'daclPresent':True,'protected':True,'owner':'user','user':'user',
          'rules':[{'sid':'user','allow':True}]}
    data.update(change)
    monkeypatch.setattr(w,'checked_local_path',lambda p: Path(p))
    monkeypatch.setattr(w.subprocess,'run',lambda *a,**k: SimpleNamespace(returncode=0,stdout=json.dumps(data).encode()))
    with pytest.raises(ValueError): w.private_directory(tmp_path)


@pytest.mark.skipif(os.name!='nt',reason='Windows ACL metadata helper')
def test_private_acl_accepts_owner_system_admin_only(tmp_path,monkeypatch):
    from expergis import windows_runtime as w
    data={'daclPresent':True,'protected':True,'owner':'user','user':'user',
          'rules':[{'sid':sid,'allow':True} for sid in ('user','S-1-5-18','S-1-5-32-544')]}
    monkeypatch.setattr(w,'checked_local_path',lambda p: Path(p))
    monkeypatch.setattr(w.subprocess,'run',lambda *a,**k: SimpleNamespace(returncode=0,stdout=json.dumps(data).encode()))
    assert w.private_directory(tmp_path)==tmp_path


def test_state_file_link_rejected(tmp_path):
    from expergis.windows_runtime import local_file
    target=tmp_path/'original'
    target.write_bytes(b'synthetic')
    os.link(target,tmp_path/'status.json')
    with pytest.raises(ValueError): local_file(tmp_path,'status.json')


def test_startup_failure_status_is_redacted(tmp_path,monkeypatch,capsys):
    from expergis import windows_runtime as w
    monkeypatch.setattr(w.sys,'argv',['runtime','run','--directory',str(tmp_path)])
    monkeypatch.setattr(w,'private_directory',lambda value:tmp_path)
    async def fail(directory):
        raise ValueError('SENSITIVE_SENTINEL')
    monkeypatch.setattr(w,'run',fail)
    assert w.main()==1
    status=(tmp_path/'status.json').read_text()
    assert json.loads(status)['reason']=='STARTUP_OR_RUNTIME_FAILED'
    assert 'SENSITIVE_SENTINEL' not in status+capsys.readouterr().out



def test_scoped_file_deletion_remains_observable(tmp_path):
    from expergis.plugins.file_watcher import FileWatcherPlugin
    target=tmp_path/'marker.txt'
    target.write_text('synthetic')
    watcher=FileWatcherPlugin('job-test',{'_strict_local_paths':True})
    watcher.paths=[target]
    watcher.patterns=['*.txt']
    assert str(target) in watcher._scan()
    target.unlink()
    assert watcher._scan()=={}
