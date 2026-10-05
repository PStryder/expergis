"""Portable synthetic v1 vectors for both repositories; no local resources referenced."""
import copy

BASE = {
    'schema_version':1,'event_id':'a0000000-0000-4000-8000-000000000001',
    'source':'arbitrium','instance_id':'a0000000-0000-4000-8000-000000000002',
    'job_id':'a0000000-0000-4000-8000-000000000003','run_id':'a0000000-0000-4000-8000-000000000004',
    'status':'completed','observed_at':'2026-10-05T12:00:00Z','sequence':3,
    'context':{'template_id':'synthetic-v1','reason_code':'exit_zero','exit_code':0},
    'log_refs':[r'C:\synthetic\never-open.log'],'result_refs':[]}


def cases():
    result=[]
    def add(name,expected,**changes):
        result.append((name,expected,{**copy.deepcopy(BASE),**changes}))
    for status,reasons in {
        'queued':['queued'],'running':['started'],'completed':['exit_zero'],
        'failed':['exit_nonzero','deadline','launch_failed'],
        'canceled':['cancel_requested','approval_denied'],
        'interrupted':['worker_stopped','lease_expired'],
        'unknown':['ownership_lost','lease_expired']}.items():
        for reason in reasons:
            add(status+'_'+reason,True,status=status,context={**BASE['context'],
                'reason_code':reason,'exit_code':0 if status=='completed' else None})
    add('max_sequence_microseconds',True,sequence=2147483647,observed_at='2026-10-05T12:00:00.123456Z')
    add('zero_sequence',False,sequence=0)
    add('sequence_overflow',False,sequence=2147483648)
    add('bool_sequence',False,sequence=True)
    add('uppercase_uuid',False,event_id=BASE['event_id'].upper())
    add('offset_timestamp',True,observed_at='2026-10-05T12:00:00+00:00')
    add('seven_fractional_digits',False,observed_at='2026-10-05T12:00:00.1234567Z')
    add('missing_context',False,context={})
    add('unknown_reason',False,context={**BASE['context'],'reason_code':'custom_reason'})
    add('mismatched_reason',False,context={**BASE['context'],'reason_code':'started'})
    add('completed_nonzero',False,context={**BASE['context'],'exit_code':3})
    add('completed_null',False,context={**BASE['context'],'exit_code':None})
    add('completed_bool',False,context={**BASE['context'],'exit_code':False})
    add('long_template',False,context={**BASE['context'],'template_id':'a'*81})
    add('colon_template',False,context={**BASE['context'],'template_id':'task:one'})
    add('exit_overflow',False,context={**BASE['context'],'exit_code':4294967296})
    add('relative_ref',False,log_refs=['relative.log'])
    add('unc_ref',False,log_refs=[r'\\server\share\event.log'])
    add('traversal_ref',False,log_refs=[r'C:\a\..\b.log'])
    add('stream_ref',False,log_refs=[r'C:\a.log:stream'])
    add('control_ref',False,log_refs=['C:\\bad\n.log'])
    add('too_many_refs',False,log_refs=[r'C:\synthetic\a.log']*9)
    add('extra_envelope_field',False,unexpected='rejected')
    return result
