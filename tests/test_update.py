"""Updater orchestration tests never access the installed runtime or start tasks."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

spec=importlib.util.spec_from_file_location('updater',Path(__file__).parents[1]/'scripts/update_expergis.py')
updater=importlib.util.module_from_spec(spec)
spec.loader.exec_module(updater)


def original(signals):
    return {'expergis': {'mcp_events': {'allowed_roots':[str(signals)],
        'allowed_process_names':[], 'allow_schedules':False},
        'auth0': {'synthetic':'preserved'}}, 'tunnel': {'synthetic':'preserved'}}


def test_only_approved_config_fields_change(tmp_path):
    before=original(tmp_path)
    after=updater.updated_config(before,tmp_path)
    assert before==original(tmp_path)
    assert after['expergis']['auth0']==before['expergis']['auth0']
    assert after['tunnel']==before['tunnel']
    options=after['expergis']['mcp_events']
    assert options['allow_schedules'] is False
    assert options['allowed_service_names']==['SemSearch']
    assert options['allowed_roots']==[r'F:\HexyLab',r'F:\Documents',r'F:\Downloads',str(tmp_path)]
    with pytest.raises(ValueError): updater.updated_config(after,tmp_path)


def test_unknown_manifest_layout_refused(tmp_path):
    value={'from_commit':'a'*40,'to_commit':'b'*40,'files':{'../escape':'a'*64}}
    path=tmp_path/'manifest.json'
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError,match='INVALID_BUNDLE_LAYOUT'):
        updater.verify_bundle(tmp_path,updater.digest(path))


@pytest.mark.parametrize('fail', [False, True])
def test_update_and_automatic_rollback(tmp_path, monkeypatch, fail):
    root=tmp_path/'runtime';root.mkdir()
    config=root/'runtime.json';config.write_text(json.dumps(original(tmp_path)))
    initial=config.read_bytes()
    helper=SimpleNamespace(ROOT=root,SIGNALS=tmp_path,user_context=Mock(),
        task_info=lambda: {},verify_task=lambda _:True)
    actions=[]
    for name in ('trusted_runtime','command','installed_matches'):
        monkeypatch.setattr(updater,name,lambda *a:None)
    monkeypatch.setattr(updater,'stop',lambda *a:actions.append('stop'))
    monkeypatch.setattr(updater,'install',lambda h,b,which:actions.append(which))
    monkeypatch.setattr(updater,'updated_config',lambda config,signals,**kwargs:{**config,'synthetic_update':True})
    def start(*a):
        actions.append('start')
        if fail and actions.count('start')==1: raise ValueError('SYNTHETIC_FAILURE')
    monkeypatch.setattr(updater,'start',start)
    manifest={'from_commit':'a'*40,'to_commit':'b'*40}
    if fail:
        with pytest.raises(ValueError,match='UPDATE_FAILED_PREVIOUS_CHECKPOINT_RESTORED'):
            updater.execute(helper,tmp_path,manifest)
        assert config.read_bytes()==initial
        assert actions==['stop','new','start','stop','old','start']
    else:
        updater.execute(helper,tmp_path,manifest)
        assert json.loads(config.read_text())['synthetic_update'] is True
        assert actions==['stop','new','start']
    assert (root/'update-backup-bbbbbbbbbbbb/runtime-before.json').read_bytes()==initial


def test_task_mismatch_prevents_stop_or_write(tmp_path,monkeypatch):
    helper=SimpleNamespace(user_context=Mock(),task_info=lambda:{},verify_task=lambda _:False)
    with pytest.raises(ValueError,match='TASK_IDENTITY_MISMATCH'):
        updater.execute(helper,tmp_path,{})
    assert list(tmp_path.iterdir())==[]


def test_code_only_update_cannot_enable_content_access(tmp_path):
    prior=updater.updated_config(original(tmp_path),tmp_path)
    assert updater.updated_config(prior,tmp_path,profile='job_inbox_code_only')==prior
    prior['expergis']['mcp_events']['allow_job_event_contents']=True
    with pytest.raises(ValueError,match='UNEXPECTED_EXISTING_SCOPE'):
        updater.updated_config(prior,tmp_path,profile='job_inbox_code_only')
