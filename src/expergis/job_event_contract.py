"""Strict, content-bounded Arbitrium v1 observations. References are never opened."""
from datetime import datetime
import json
from pathlib import PureWindowsPath
import re
from uuid import UUID

MAX_BYTES = 16384
FIELDS = {'schema_version', 'event_id', 'source', 'instance_id', 'job_id', 'run_id',
          'status', 'observed_at', 'sequence', 'context', 'log_refs', 'result_refs'}
STATUSES = {'queued', 'running', 'completed', 'failed', 'canceled', 'interrupted', 'unknown'}


def uuid_text(value):
    if not isinstance(value, str) or len(value) != 36 or str(UUID(value)) != value.lower():
        raise ValueError('Invalid UUID')
    return value.lower()


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key')
        result[key] = value
    return result


def parse_event(body, filename):
    if not isinstance(body, bytes) or not 1 <= len(body) <= MAX_BYTES:
        raise ValueError('Event size rejected')
    try:
        data = json.loads(body.decode('utf-8'), object_pairs_hook=_object,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError('Nonfinite JSON')))
    except (UnicodeError, RecursionError) as exc:
        raise ValueError('Invalid event encoding') from exc
    if not isinstance(data, dict) or set(data) != FIELDS:
        raise ValueError('Invalid event fields')
    if type(data['schema_version']) is not int or data['schema_version'] != 1 or data['source'] != 'arbitrium':
        raise ValueError('Unsupported source/version')
    for key in ('event_id', 'instance_id', 'job_id', 'run_id'):
        uuid_text(data[key])
    if filename.lower() != uuid_text(data['event_id']) + '.json':
        raise ValueError('Filename does not match event ID')
    if data['status'] not in STATUSES or type(data['sequence']) is not int or not 0 <= data['sequence'] <= 2**63-1:
        raise ValueError('Invalid status/sequence')
    stamp = data['observed_at']
    if not isinstance(stamp, str) or not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|\+00:00)', stamp):
        raise ValueError('UTC RFC3339 timestamp required')
    datetime.fromisoformat(stamp.replace('Z', '+00:00'))
    context = data['context']
    if not isinstance(context, dict) or set(context) - {'template_id', 'reason_code', 'exit_code'}:
        raise ValueError('Invalid context keys')
    for key in ('template_id', 'reason_code'):
        if key in context and (not isinstance(context[key], str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', context[key])):
            raise ValueError('Context identifiers must not contain prose')
    code = context.get('exit_code')
    if code is not None and (type(code) is not int or not -(2**31) <= code <= 2**32-1):
        raise ValueError('Invalid exit code')
    for key in ('log_refs', 'result_refs'):
        refs = data[key]
        if not isinstance(refs, list) or len(refs) > 8:
            raise ValueError('Invalid reference count')
        for value in refs:
            if (not isinstance(value, str) or not 1 <= len(value) <= 1024
                    or any(ord(c) < 32 for c in value)):
                raise ValueError('Invalid reference')
            path = PureWindowsPath(value)
            if (not path.is_absolute() or value.startswith(('\\\\', '//'))
                    or not re.fullmatch(r'[A-Za-z]:', path.drive)
                    or '..' in path.parts or ':' in value[2:]):
                raise ValueError('Reference must be a local absolute path')
    return data
