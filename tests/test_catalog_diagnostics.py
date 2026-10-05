import json
import time
from importlib.metadata import version
import pytest
from expergis.catalog_diagnostics import CatalogDiagnostics,catalog_summary
from expergis.mcp_events_app import EventDiscoveryMiddleware


def metadata():
    return [{'name':'expergis_watch','description':'private-description-sentinel',
        'securitySchemes':[{'synthetic':'private-auth-sentinel'}],
        'inputSchema':{'properties':{'plugin_type':{'enum':['file_watcher','job_event_watcher']}}}}]


def test_projection_has_no_auth_or_description_data():
    observer=CatalogDiagnostics()
    observer.emitted({'result':{'tools':metadata()},'private':'private-response-sentinel'})
    snapshot=observer.snapshot(metadata())
    assert snapshot['successful_tools_list_count']==1
    assert snapshot['live_catalog']=={k:snapshot['last_successful_tools_list'][k] for k in ('plugin_types','schema_sha256')}
    assert 'private-' not in json.dumps(snapshot)
    assert set(snapshot['last_successful_tools_list'])=={'plugin_types','schema_sha256','emitted_at','protocol'}
    changed=metadata();changed[0]['description']='another';changed[0]['securitySchemes']=[]
    assert catalog_summary(changed)==snapshot['live_catalog']


@pytest.mark.asyncio
@pytest.mark.parametrize('status,body,fail_send,protocol,expected',[
    (200,{'result':{'tools':metadata()}},False,'2026-07-28',1),
    (401,{'error':'denied'},False,'2026-07-28',0),
    (200,{'error':{'code':-32001}},False,'2026-07-28',0),
    (200,{'result':{'tools':metadata()}},True,'2026-07-28',0),
    (200,{'result':{'tools':metadata()}},False,'2025-11-25',0)])
async def test_observe_only_successfully_emitted_supported_catalog(status,body,fail_send,protocol,expected):
    observer=CatalogDiagnostics()
    async def app(scope,receive,send):
        await send({'type':'http.response.start','status':status,'headers':[]})
        await send({'type':'http.response.body','body':json.dumps(body).encode()})
    async def forbidden_receive():raise AssertionError('Observer must not inspect request body')
    async def send(message):
        if fail_send and message['type']=='http.response.body':raise OSError('synthetic disconnect')
    middleware=EventDiscoveryMiddleware(app,['expergis'],diagnostics=observer)
    scope={'type':'http','headers':[(b'mcp-method',b'tools/list'),(b'mcp-protocol-version',protocol.encode()),
        (b'authorization',b'Bearer private-token-sentinel')]}
    if fail_send:
        with pytest.raises(OSError):await middleware(scope,forbidden_receive,send)
    else:await middleware(scope,forbidden_receive,send)
    snapshot=observer.snapshot(metadata())
    assert snapshot['successful_tools_list_count']==expected
    assert 'private-' not in json.dumps(snapshot)


@pytest.mark.skipif(not version('mcp').startswith('2.'),reason='MCP 2 endpoint')
@pytest.mark.asyncio
async def test_authenticated_live_catalog_matches_actual_serialized_response(tmp_path):
    import httpx2 as httpx
    from mcp.server.auth.provider import AccessToken
    from mcp.server.auth.settings import AuthSettings
    from expergis.event_store import EventStore
    from expergis.mcp_events_app import create_app
    from .test_events import TestProtector,Receiver
    class Verifier:
        async def verify_token(self,token):
            if token!='private-token-sentinel':return None
            return AccessToken(token=token,subject='synthetic',client_id='synthetic',scopes=['expergis'],
                expires_at=int(time.time())+60,resource='https://example.com/mcp')
    store=EventStore(tmp_path/'test.db',protector=TestProtector())
    app=create_app({'velle_endpoint':'http://127.0.0.1:1/disabled','delivery_adapter':'mcp_events',
        'mcp_events':{'owner':'synthetic'},'watchers':[]},Verifier(),AuthSettings(issuer_url='https://issuer.example.com',
        resource_server_url='https://example.com/mcp',required_scopes=['expergis'],validate_token_resource=True),
        authorize=lambda user,watcher:user=='synthetic',store=store,sender=Receiver())
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='https://example.com') as client:
            async def request(method,token='private-token-sentinel'):
                params={'_meta':{'io.modelcontextprotocol/protocolVersion':'2026-07-28',
                    'io.modelcontextprotocol/clientCapabilities':{}}}
                headers={'Authorization':'Bearer '+token,'MCP-Method':method,'MCP-Protocol-Version':'2026-07-28',
                    'Accept':'application/json, text/event-stream'}
                if method=='tools/call':
                    params.update(name='expergis_list',arguments={});headers['MCP-Name']='expergis_list'
                return await client.post('/mcp',headers=headers,json={'jsonrpc':'2.0','id':1,'method':method,'params':params})
            assert (await request('tools/list','unauthorized')).status_code==401
            assert (await request('tools/call','unauthorized')).status_code==401
            initial=json.loads((await request('tools/call')).json()['result']['content'][0]['text'])['catalog_diagnostics']
            assert initial['successful_tools_list_count']==0 and initial['last_successful_tools_list'] is None
            emitted=(await request('tools/list')).json()
            final=json.loads((await request('tools/call')).json()['result']['content'][0]['text'])['catalog_diagnostics']
            actual=catalog_summary(emitted['result']['tools'])
            assert final['live_catalog']==actual
            assert final['successful_tools_list_count']==1
            assert final['last_successful_tools_list']['schema_sha256']==actual['schema_sha256']
            assert 'job_event_watcher' in actual['plugin_types']
            assert 'private-token-sentinel' not in json.dumps(final)
