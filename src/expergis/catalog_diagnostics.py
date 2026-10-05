"""Bounded, in-memory public catalog evidence; never retains requests or tool bodies."""
from datetime import datetime, timezone
import hashlib
import json
import os
import re


def catalog_summary(tools):
    if not isinstance(tools,list) or not 1 <= len(tools) <= 32:
        raise ValueError('Invalid catalog')
    projection=[]
    types=None
    for tool in tools:
        if not isinstance(tool,dict) or not isinstance(tool.get('name'),str) or not isinstance(tool.get('inputSchema'),dict):
            raise ValueError('Invalid tool metadata')
        projection.append({'name':tool['name'],'inputSchema':tool['inputSchema']})
        if tool['name']=='expergis_watch':
            types=tool['inputSchema'].get('properties',{}).get('plugin_type',{}).get('enum')
    if (not isinstance(types,list) or not 1 <= len(types) <= 32
            or any(not isinstance(t,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',t) for t in types)):
        raise ValueError('Invalid watcher metadata')
    encoded=json.dumps(sorted(projection,key=lambda t:t['name']),sort_keys=True,
        separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()
    if len(encoded)>65536:
        raise ValueError('Catalog too large')
    return {'plugin_types':list(types),'schema_sha256':hashlib.sha256(encoded).hexdigest()}


class CatalogDiagnostics:
    def __init__(self):
        self.started_at=datetime.now(timezone.utc).isoformat()
        self.count=0
        self.last=None

    def emitted(self,payload):
        # Called only after the successful response body was handed to ASGI send.
        if not isinstance(payload,dict) or 'error' in payload:
            return
        try:
            summary=catalog_summary(payload.get('result',{}).get('tools'))
        except (ValueError,TypeError,AttributeError):
            return
        self.count=min(2**63-1,self.count+1)
        self.last={**summary,'emitted_at':datetime.now(timezone.utc).isoformat(),
            'protocol':'2026-07-28'}

    def snapshot(self,tools):
        return {'diagnostic_revision':1,'process_id':os.getpid(),'observer_started_at':self.started_at,
            'hash_scope':'sorted tool names and inputSchema; excludes top-level auth metadata and tool descriptions',
            'live_catalog':catalog_summary(tools),'successful_tools_list_count':self.count,
            'last_successful_tools_list':dict(self.last) if self.last else None,
            'observation_scope':'JSON tools/list responses for protocol 2026-07-28; process-local, resets on restart'}
