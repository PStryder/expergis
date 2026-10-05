import asyncio
import json
import os
from pathlib import Path
from uuid import uuid4

import pytest

from expergis.job_event_contract import parse_event
from expergis.inbox_files import read_event_file
from expergis.job_inbox import JobInbox
from expergis.event_store import EventStore
from .test_events import TestProtector, SECRET, Receiver


def sample(**changes):
    return {'schema_version':1,'event_id':str(uuid4()),'source':'arbitrium',
        'instance_id':'10000000-0000-4000-8000-000000000001',
        'job_id':'20000000-0000-4000-8000-000000000002',
        'run_id':'30000000-0000-4000-8000-000000000003',
        'status':'running','observed_at':'2026-10-05T16:00:00Z','sequence':1,
        'context':{'template_id':'synthetic-test','reason_code':'started','exit_code':None},
        'log_refs':[r'C:\synthetic\never-open.log'],'result_refs':[],**changes}


def encoded(data):
    return json.dumps(data).encode()


def subscribed(store):
    store.subscribe('sub_synthetic','alice','job-inbox',{'url':'https://receiver.example.com/events','secret':SECRET},store.clock()+600)


@pytest.mark.parametrize('change', [
    {'source':'other'}, {'schema_version':True}, {'sequence':True}, {'sequence':-1},
    {'status':'do-something'}, {'observed_at':'2026-10-05T12:00:00-04:00'},
    {'context':{'instructions':'execute this'}}, {'context':{'reason_code':'free text'}},
    {'context':{'exit_code':True}}, {'log_refs':[r'\\host\share\a']},
    {'result_refs':['https://example.com/a']}, {'result_refs':[r'C:\a\..\b']},
    {'result_refs':[r'C:\a:stream']}, {'result_refs':['C:\\'+('x'*1024)]},
    {'result_refs':[r'C:\x']*9}, {'event_id':'not-a-uuid'}, {'unexpected':True}])
def test_strict_contract_rejects_invalid(change):
    data=sample(**change)
    with pytest.raises((ValueError,TypeError)):
        parse_event(encoded(data),str(data['event_id'])+'.json')


def test_duplicate_keys_oversize_and_filename():
    data=sample();name=data['event_id']+'.json'
    assert parse_event(encoded(data),name)==data
    for body in (b'{"source":"arbitrium","source":"other"}',b' '*16385,b'\xff'):
        with pytest.raises(ValueError): parse_event(body,name)
    with pytest.raises(ValueError): parse_event(encoded(data),str(uuid4())+'.json')


def test_flat_read_and_hardlink_refusal(tmp_path):
    data=sample();name=data['event_id']+'.json';path=tmp_path/name
    path.write_bytes(encoded(data))
    assert read_event_file(tmp_path,name)==encoded(data)
    os.link(path,tmp_path/'alias')
    with pytest.raises((OSError,ValueError)):read_event_file(tmp_path,name)
    with pytest.raises(ValueError):read_event_file(tmp_path,'../'+name)


def test_reader_never_follows_refs(tmp_path,monkeypatch):
    data=sample();name=data['event_id']+'.json'
    (tmp_path/name).write_bytes(encoded(data))
    def forbidden(*args,**kwargs): raise AssertionError('Reference content must never be read')
    monkeypatch.setattr(Path,'read_text',forbidden)
    monkeypatch.setattr(Path,'read_bytes',forbidden)
    assert parse_event(read_event_file(tmp_path,name),name)==data


def test_restart_pending_subscription_and_dedup_after_retention(tmp_path):
    now=[1000]
    path=tmp_path/'test.db'
    store=EventStore(path,protector=TestProtector(),clock=lambda:now[0],retention=60)
    data=sample();ledger=JobInbox(store,'alice','job-inbox')
    assert ledger.accept(data,{})=='accepted'
    assert ledger.flush(lambda *a:True)==0
    store.close()
    store=EventStore(path,protector=TestProtector(),clock=lambda:now[0],retention=60)
    ledger=JobInbox(store,'alice','job-inbox');subscribed(store)
    assert ledger.accept(data,{})=='duplicate'
    assert ledger.flush(lambda *a:True)==1
    assert len(store.receipts('alice'))==1
    now[0]+=100
    store.prune()
    assert ledger.accept(data,{})=='duplicate' and ledger.flush(lambda *a:True)==0
    assert store.receipts('alice')==[]
    store.close()


def test_conflicts_and_out_of_order(tmp_path):
    store=EventStore(tmp_path/'test.db',protector=TestProtector())
    ledger=JobInbox(store,'alice','job-inbox')
    high=sample(sequence=10)
    assert ledger.accept(high,{})=='accepted'
    low=sample(sequence=2)
    assert ledger.accept(low,{})=='accepted'
    same=sample(sequence=10)
    assert ledger.accept(same,{})=='conflict'
    assert ledger.accept({**high,'status':'failed'},{})=='conflict'
    subscribed(store)
    assert ledger.flush(lambda *a:True)==1  # first ID conflict blocks its pending handoff
    row=store.db.execute('SELECT private FROM events').fetchone()
    payload=store.unpack(row['private'])
    assert payload['data']['observed']['details']['sequence_relation']=='historical'
    assert ledger.stats()=={'pending':0,'queued':1,'conflict':2}
    store.close()


def test_atomic_queue_handoff_rollback(tmp_path,monkeypatch):
    store=EventStore(tmp_path/'test.db',protector=TestProtector())
    ledger=JobInbox(store,'alice','job-inbox');ledger.accept(sample(),{});subscribed(store)
    original=store.enqueue
    def fail_after_insert(*args,**kwargs):
        original(*args,**kwargs)
        raise OSError('synthetic crash boundary')
    monkeypatch.setattr(store,'enqueue',fail_after_insert)
    with pytest.raises(OSError):ledger.flush(lambda *a:True)
    assert ledger.stats()['pending']==1 and store.db.execute('SELECT count(*) FROM events').fetchone()[0]==0
    monkeypatch.setattr(store,'enqueue',original)
    assert ledger.flush(lambda *a:False)==0
    assert ledger.flush(lambda *a:True)==1
    assert ledger.stats()['queued']==1
    store.close()


def test_capacity_is_fail_closed_without_forgetting_ids(tmp_path):
    store=EventStore(tmp_path/'test.db',protector=TestProtector())
    ledger=JobInbox(store,'alice','job-inbox',limit=1)
    data=sample();ledger.accept(data,{})
    with pytest.raises(ValueError):ledger.accept(sample(sequence=2),{})
    assert ledger.accept(data,{})=='duplicate'
    store.close()


@pytest.mark.asyncio
async def test_signed_mock_handoff_and_transient_receiver(tmp_path):
    from expergis.event_service import EventService
    store=EventStore(tmp_path/'test.db',protector=TestProtector())
    ledger=JobInbox(store,'alice','job-inbox');subscribed(store)
    ledger.accept(sample(),{});ledger.flush(lambda *a:True)
    receiver=Receiver();receiver.status=503
    service=EventService(store,lambda *a:True,sender=receiver)
    await service.deliver_one()
    receipt=store.receipts('alice')[0]
    assert receipt['state']=='pending' and receipt['http_status']==503
    receiver.status=202
    with store.db:store.db.execute('UPDATE jobs SET due=0')
    await service.deliver_one()
    assert store.receipts('alice')[0]['state']=='received'
    assert receiver.messages[0][0]['eventId']==receiver.messages[1][0]['eventId']
    store.close()


def test_permission_is_distinct_from_metadata_scope(tmp_path):
    from expergis.monitoring_scope import validate_watch
    args={'plugin_type':'job_event_watcher','config':{'inbox':str(tmp_path)}}
    with pytest.raises(PermissionError):validate_watch(args,{'allowed_roots':[str(tmp_path)]})
    args={'plugin_type':'job_event_watcher','config':{'inbox':str(tmp_path)}}
    validate_watch(args,{'allow_job_event_contents':True,'job_event_inbox':str(tmp_path)})
    with pytest.raises(PermissionError):
        validate_watch({'plugin_type':'job_event_watcher','config':{'inbox':str(tmp_path.parent)}},
            {'allow_job_event_contents':True,'job_event_inbox':str(tmp_path)})


@pytest.mark.asyncio
async def test_plugin_atomic_publish_ignores_temp_and_never_deletes(tmp_path):
    from expergis.plugins.job_event_watcher import JobEventWatcherPlugin
    store=EventStore(tmp_path/'test.db',protector=TestProtector())
    inbox=tmp_path/'inbox';inbox.mkdir()
    data=sample();temporary=inbox/'publish.tmp';temporary.write_bytes(encoded(data))
    plugin=JobEventWatcherPlugin('job-inbox',{'inbox':str(inbox)})
    plugin.bind(store,'alice',lambda *a:True)
    await plugin.setup();plugin.scan()
    assert plugin.source_stats['pending']==0
    target=inbox/(data['event_id']+'.json');temporary.replace(target)
    plugin.scan();assert plugin.source_stats['pending']==1
    plugin.scan();assert plugin.source_stats['pending']==1 and target.exists()
    store.close()


def test_run_identity_cannot_switch_jobs(tmp_path):
    store=EventStore(tmp_path/'test.db',protector=TestProtector())
    ledger=JobInbox(store,'alice','job-inbox')
    ledger.accept(sample(),{})
    assert ledger.accept(sample(sequence=2,job_id=str(uuid4())),{})=='conflict'
    store.close()


@pytest.mark.asyncio
async def test_malformed_early_files_do_not_starve_batch(tmp_path):
    from expergis.plugins.job_event_watcher import JobEventWatcherPlugin
    store=EventStore(tmp_path/'test.db',protector=TestProtector())
    inbox=tmp_path/'inbox';inbox.mkdir()
    for i in range(80):(inbox/(str(i)+'.json')).write_text('malformed')
    data=sample(event_id='ffffffff-ffff-4fff-8fff-ffffffffffff')
    (inbox/(data['event_id']+'.json')).write_bytes(encoded(data))
    plugin=JobEventWatcherPlugin('job-inbox',{'inbox':str(inbox)})
    plugin.bind(store,'alice',lambda *a:True);await plugin.setup()
    plugin.scan();plugin.scan()
    assert plugin.source_stats['pending']==1
    assert plugin.source_stats['invalid_reads']==80
    store.close()


@pytest.mark.skipif(os.name!='nt',reason='Windows junction containment')
def test_inbox_junction_rejected(tmp_path):
    import subprocess
    target=tmp_path/'outside';target.mkdir()
    link=tmp_path/'redirected'
    data=sample();name=data['event_id']+'.json';(target/name).write_bytes(encoded(data))
    subprocess.run(['cmd','/c','mklink','/J',str(link),str(target)],check=True,capture_output=True)
    try:
        with pytest.raises(PermissionError):read_event_file(link,name)
    finally:
        # Remove the junction itself only, never enumerate its target.
        os.rmdir(link)


def test_queue_capacity_retains_pending_for_retry(tmp_path):
    store=EventStore(tmp_path/'test.db',protector=TestProtector(),max_events=1)
    ledger=JobInbox(store,'alice','job-inbox');subscribed(store)
    ledger.accept(sample(),{});ledger.accept(sample(sequence=2),{})
    with pytest.raises(ValueError):ledger.flush(lambda *a:True)
    assert ledger.stats()['pending']==1 and ledger.stats()['queued']==1
    with store.db:store.db.execute('DELETE FROM events')
    assert ledger.flush(lambda *a:True)==1
    store.close()


def test_subscription_expiring_during_handoff_retains_pending(tmp_path, monkeypatch):
    now=[1000]
    store=EventStore(tmp_path/'test.db',protector=TestProtector(),clock=lambda:now[0])
    ledger=JobInbox(store,'alice','job-inbox');ledger.accept(sample(),{});subscribed(store)
    original=store.enqueue
    def expire_before_insert(*args,**kwargs):
        now[0]=2000
        return original(*args,**kwargs)
    monkeypatch.setattr(store,'enqueue',expire_before_insert)
    with pytest.raises(ValueError):ledger.flush(lambda *a:True)
    assert ledger.stats()['pending']==1
    assert store.db.execute('SELECT count(*) FROM events').fetchone()[0]==0
    store.close()
