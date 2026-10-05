from pathlib import Path
import json
import pytest
from expergis.job_event_contract import parse_event
from .job_contract_cases import cases


PRODUCER_CASES=json.loads((Path(__file__).parent/'fixtures/job-event-v1.producer-cases.json').read_text())
ALL_CASES=cases()+[(c['name'],c['valid'],c['event']) for c in PRODUCER_CASES]


@pytest.mark.parametrize('name,expected,event',ALL_CASES,ids=[c[0] for c in ALL_CASES])
def test_shared_contract_vector(name,expected,event):
    body=json.dumps(event).encode()
    if expected:
        assert parse_event(body,event['event_id']+'.json')==event
    else:
        with pytest.raises((ValueError,TypeError)):
            parse_event(body,event['event_id']+'.json')
