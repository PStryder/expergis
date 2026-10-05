import json
import pytest
from expergis.job_event_contract import parse_event
from .job_contract_cases import cases


@pytest.mark.parametrize('name,expected,event',cases(),ids=[c[0] for c in cases()])
def test_shared_contract_vector(name,expected,event):
    body=json.dumps(event).encode()
    if expected:
        assert parse_event(body,event['event_id']+'.json')==event
    else:
        with pytest.raises((ValueError,TypeError)):
            parse_event(body,event['event_id']+'.json')
