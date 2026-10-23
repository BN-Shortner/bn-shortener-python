"""Unit tests with a fake transport (no network): python -m pytest sdk/python/tests (with sdk/python/src on the path).
The project's tests/test_sdk.py also runs the SDK against the real API on a test database."""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import bn_shortener  # noqa: E402
from bn_shortener import Response, oauth, webhooks  # noqa: E402


def ok(data, status=200, meta=None, headers=None):
    return Response(status, {'content-type': 'application/json', **(headers or {})},
                    json.dumps({'success': True, 'data': data, 'meta': meta or {}}).encode())


def client(responder, **kw):
    calls = []

    def transport(req):
        calls.append(req)
        return responder(len(calls), req)
    c = bn_shortener.BNShortener('bn_live_test', transport=transport, **kw)
    c._sleep = lambda s: None
    return c, calls


def test_headers_body_and_unwrapping():
    c, calls = client(lambda n, r: ok({'id': 1, 'short_url': 'https://b1.lc/AbC9'}, 201, headers={'x-request-id': 'req_1'}))
    link = c.links.create(url='https://example.com', title='x')
    assert link['id'] == 1 and c.last_response.request_id == 'req_1'
    req = calls[0]
    assert req.method == 'POST' and req.url == 'https://b1.lc/api/v1/links'
    assert req.headers['X-API-Key'] == 'bn_live_test' and req.headers['X-BN-Client'].startswith('bn-python/')
    assert req.headers['Idempotency-Key'].startswith('bn-sdk-')
    assert json.loads(req.body) == {'url': 'https://example.com', 'title': 'x'}


def test_query_and_path_params():
    c, calls = client(lambda n, r: ok({}))
    c.links.stats(5, period='7d')
    c.links.get_by_code('Ab/C9', domain='b0.lc')
    assert calls[0].url == 'https://b1.lc/api/v1/links/5/stats?period=7d'
    assert calls[1].url == 'https://b1.lc/api/v1/links/code/Ab%2FC9?domain=b0.lc'


def test_retries_keep_the_idempotency_key():
    c, calls = client(lambda n, r: Response(503, {}, b'') if n < 3 else ok({'id': 2}))
    assert c.links.archive(2)['id'] == 2
    assert len({r.headers['Idempotency-Key'] for r in calls}) == 1 and len(calls) == 3


def test_errors():
    problem = {'type': 'https://b1.lc/docs/errors/validation-failed', 'title': 'Validation Failed', 'status': 422,
               'detail': 'bad', 'errors': [{'field': 'url', 'code': 'INVALID', 'message': 'URL must use https'}], 'trace_id': 'req_2'}
    c, _ = client(lambda n, r: Response(422, {'content-type': 'application/problem+json'}, json.dumps(problem).encode()))
    with pytest.raises(bn_shortener.ValidationError) as e:
        c.links.create(url='x')
    assert e.value.errors[0]['field'] == 'url' and e.value.request_id == 'req_2' and 'url: URL must use https' in str(e.value)


def test_pagination():
    def pages(n, r):
        page = int(r.url.split('page=')[1].split('&')[0]) if 'page=' in r.url else 1
        return ok([page], meta={'pagination': {'page': page, 'total_pages': 3, 'has_next': page < 3}})
    c, _ = client(pages)
    assert list(c.paginate(c.links.list, per_page=1)) == [1, 2, 3]


def test_binary():
    c, _ = client(lambda n, r: Response(200, {'content-type': 'image/png'}, b'\x89PNG...'))
    img = c.qr_codes.image(1)
    assert img.content_type == 'image/png' and img.content.startswith(b'\x89PNG')


def test_webhook_signature_round_trip():
    sig = webhooks.sign(b'{"a":1}', 'secret')
    webhooks.verify_signature(b'{"a":1}', {'X-BN-Signature': sig}, 'secret')
    with pytest.raises(bn_shortener.WebhookVerificationError):
        webhooks.verify_signature(b'{"a":2}', {'X-BN-Signature': sig}, 'secret')


def test_pkce_and_callback():
    v, ch = oauth.generate_pkce()
    assert len(v) >= 43 and '=' not in ch
    app = oauth.OAuthClient('bnc_x', redirect_uri='https://app.example.com/cb', transport=lambda r: None)
    auth = app.authorization_url(['read'])
    assert app.parse_callback(f'https://app.example.com/cb?code=c&state={auth.state}&iss=https://b1.lc', expected_state=auth.state) == 'c'
    with pytest.raises(bn_shortener.OAuthError):
        app.parse_callback('https://app.example.com/cb?code=c&state=other', expected_state=auth.state)


def test_in_flight_409_is_retried_but_a_real_conflict_is_not():
    busy = Response(409, {'content-type': 'application/problem+json', 'retry-after': '1'},
                    json.dumps({'title': 'Request In Progress', 'status': 409}).encode())
    c, calls = client(lambda n, r: busy if n == 1 else ok({'id': 3}, 201))
    assert c.links.create(url='https://example.com')['id'] == 3 and len(calls) == 2
    taken = Response(409, {'content-type': 'application/problem+json'}, json.dumps({'title': 'Code Taken', 'status': 409}).encode())
    c, calls = client(lambda n, r: taken)
    with pytest.raises(bn_shortener.ConflictError):
        c.links.create(url='https://example.com', custom_code='abc')
    assert len(calls) == 1


def test_redirect_is_an_error_not_an_empty_file():
    c, _ = client(lambda n, r: Response(302, {'location': 'https://elsewhere.example/'}, b''))
    with pytest.raises(bn_shortener.APIError):
        c.links.list()


def test_device_polling_survives_a_5xx_and_a_network_blip():
    answers = iter([
        Response(400, {'content-type': 'application/json'}, b'{"error":"authorization_pending"}'),
        Response(502, {'content-type': 'text/html'}, b'bad gateway'),
        bn_shortener.APIConnectionError('reset'),
        Response(200, {'content-type': 'application/json'}, b'{"access_token":"bn_oat_x","expires_in":3600,"scope":"read"}'),
    ])

    def transport(req):
        a = next(answers)
        if isinstance(a, Exception):
            raise a
        return a
    app = oauth.OAuthClient('bnc_x', transport=transport)
    app._sleep = lambda s: None
    import time
    device = oauth.DeviceAuthorization('d', 'ABCD-EFGH', 'https://b1.lc/device', 'https://b1.lc/device', 600, 5, time.time())
    assert app.wait_for_device(device).access_token == 'bn_oat_x'


def test_non_ascii_signature_or_state_is_refused_cleanly():
    with pytest.raises(bn_shortener.WebhookVerificationError):
        webhooks.verify_signature(b'{}', {'X-BN-Signature': 't=1,v1=é'}, 'secret', tolerance=0)
    app = oauth.OAuthClient('bnc_x', redirect_uri='https://app.example.com/cb', transport=lambda r: None)
    with pytest.raises(bn_shortener.OAuthError):
        app.parse_callback('https://app.example.com/cb?code=c&state=%C3%A9', expected_state='abc')
