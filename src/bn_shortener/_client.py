import json
import os
import platform
import random
import time
import uuid
from typing import Any, Callable, Dict, Iterator, Mapping, Optional
from urllib.parse import quote, urlencode

from . import _transport
from ._errors import APIConnectionError, APIError, AuthenticationError, BNError, OAuthError, error_for
from ._generated import GeneratedResources
from ._version import __version__

DEFAULT_BASE_URL = 'https://b1.lc/api/v1'
RETRY_STATUSES = {408, 429, 500, 502, 503, 504}
WRITE_METHODS = {'POST', 'PUT', 'PATCH', 'DELETE'}
MAX_RETRY_WAIT = 60.0


class Page:
    """One page of a list. Iterate it for the items; ``pagination`` has page, per_page, total_items, total_pages,
    has_next, has_prev. ``client.paginate(...)`` walks every page for you."""

    def __init__(self, data, meta, fetch):
        self.data = list(data or [])
        self.meta = meta or {}
        self.pagination = self.meta.get('pagination') or {}
        self._fetch = fetch

    @property
    def has_next(self):
        p = self.pagination
        if 'has_next' in p:
            return bool(p['has_next'])
        return bool(p.get('total_pages') and p.get('page', 1) < p['total_pages'])

    def next_page(self):
        """The following page, or None after the last one."""
        if not self.has_next:
            return None
        return self._fetch(int(self.pagination.get('page', 1)) + 1)

    def __iter__(self):
        return iter(self.data)

    def __len__(self):
        return len(self.data)

    def __getitem__(self, i):
        return self.data[i]

    def __repr__(self):
        return f'<Page {self.pagination.get("page", "?")}/{self.pagination.get("total_pages", "?")}: {len(self.data)} items>'


class BinaryResponse:
    """A file answer (QR code image, CSV export): ``content`` bytes plus ``content_type``, ``filename`` and headers."""

    def __init__(self, content, headers):
        self.content = content
        self.headers = headers
        self.content_type = headers.get('content-type', '').split(';')[0].strip()
        cd = headers.get('content-disposition', '')
        self.filename = cd.split('filename=', 1)[1].strip('"; ') if 'filename=' in cd else None

    @property
    def text(self):
        return self.content.decode('utf-8')

    def save(self, path):
        with open(path, 'wb') as f:
            f.write(self.content)
        return path

    def __repr__(self):
        return f'<BinaryResponse {self.content_type} {len(self.content)} bytes>'


class LastResponse:
    """Status, headers and rate limit of the latest answer (``client.last_response``)."""

    def __init__(self, status, headers):
        self.status = status
        self.headers = headers
        self.request_id = headers.get('x-request-id')

        def num(name):
            try:
                return int(headers[name])
            except (KeyError, ValueError):
                return None
        self.rate_limit = {'limit': num('x-ratelimit-limit'), 'remaining': num('x-ratelimit-remaining'),
                           'reset': num('x-ratelimit-reset')}
        self.idempotent_replay = headers.get('idempotency-replayed') == 'true' or headers.get('x-idempotency-replayed') == 'true'


def _clean(params):
    out = {}
    for k, v in (params or {}).items():
        if v is None:
            continue
        if isinstance(v, bool):
            v = 'true' if v else 'false'
        elif isinstance(v, (list, tuple)):
            v = ','.join(str(x) for x in v)
        out[k] = v
    return out


class BNShortener(GeneratedResources):
    """Client for the BN Shortener API v3 (https://b1.lc/docs/).

    Authenticate with an API key (``api_key=`` or the ``BN_API_KEY`` environment variable), an OAuth access token
    (``access_token=``), or an ``oauth.TokenSession`` that refreshes itself (``oauth=``).

    Every resource is an attribute: ``client.links``, ``client.qr_codes``, ``client.bio_pages``, ``client.webhooks``...
    Writes get an Idempotency-Key automatically, so retries after a timeout or 5xx never do the work twice.
    """

    def __init__(self, api_key: Optional[str] = None, *, access_token: Optional[str] = None, oauth=None,
                 base_url: Optional[str] = None, timeout: float = 30.0, max_retries: int = 2,
                 client_name: Optional[str] = None, default_headers: Optional[Mapping[str, str]] = None,
                 transport: Optional[Callable[[_transport.Request], _transport.Response]] = None):
        if not (api_key or access_token or oauth):
            api_key = os.environ.get('BN_API_KEY')
        if not (api_key or access_token or oauth):
            raise BNError('Pass api_key=, access_token= or oauth= (or set BN_API_KEY)')
        self.api_key = api_key
        self.access_token = access_token
        self.oauth = oauth
        self.base_url = (base_url or os.environ.get('BN_BASE_URL') or DEFAULT_BASE_URL).rstrip('/')
        self.timeout = timeout
        self.max_retries = max(0, int(max_retries))
        self.client_name = client_name
        self.default_headers = dict(default_headers or {})
        self.transport = transport or _transport.urllib_transport
        self.last_response: Optional[LastResponse] = None
        self._sleep = time.sleep
        self._init_resources()

    # ---- public helpers ----------------------------------------------------------------------------------------
    def paginate(self, method, *args, **kwargs) -> Iterator[Any]:
        """Every item of a list method, page after page: ``for link in client.paginate(client.links.list, search='x')``."""
        page = method(*args, **kwargs)
        while page is not None:
            yield from page
            page = page.next_page()

    def request(self, method: str, path: str, *, query=None, body=None, idempotency_key=None, headers=None):
        """Call an endpoint this version does not wrap yet. ``path`` is relative to base_url (e.g. '/links')."""
        return self._request(method.upper(), path, query=query, body=body,
                             options={'idempotency_key': idempotency_key, 'headers': headers})

    # ---- internals ---------------------------------------------------------------------------------------------
    def _headers(self, options):
        h = {'Accept': 'application/json', 'User-Agent': f'bn-shortener-python/{__version__} (Python {platform.python_version()})',
             'X-BN-Client': self.client_name or f'bn-python/{__version__}'}
        h.update(self.default_headers)
        if self.oauth is not None:
            try:
                h['Authorization'] = 'Bearer ' + self.oauth.get_access_token()
            except OAuthError as e:
                if e.ended:  # disconnected, revoked, expired: the app must connect again
                    raise AuthenticationError(401, {'title': 'Authentication Required',
                                                    'detail': f'Could not refresh the access token ({e})'}) from e
                raise APIConnectionError(f'The token endpoint is unavailable ({e}); try again') from e
        elif self.access_token:
            h['Authorization'] = 'Bearer ' + self.access_token
        else:
            h['X-API-Key'] = self.api_key
        h.update((options or {}).get('headers') or {})
        return h

    def _url(self, path, path_params=None, query=None):
        for k, v in (path_params or {}).items():
            path = path.replace('{' + k + '}', quote(str(v), safe=''))
        q = _clean(query)
        return self.base_url + path + ('?' + urlencode(q) if q else '')

    def _retry_wait(self, attempt, headers):
        ra = headers.get('retry-after') if headers else None
        if ra:
            try:
                return min(MAX_RETRY_WAIT, max(0.0, float(ra)))
            except ValueError:
                pass
        return min(8.0, 0.5 * (2 ** attempt)) * (0.75 + random.random() / 2)

    def _send(self, method, url, body, options, stream=False):
        options = options or {}
        data = None
        idem = None
        if body is not None:
            data = json.dumps(body, default=str).encode('utf-8')
        if method in WRITE_METHODS:
            idem = options.get('idempotency_key') or f'bn-sdk-{uuid.uuid4().hex}'
        timeout = options.get('timeout') or self.timeout
        retried_auth = False
        attempt = 0
        while True:
            headers = self._headers(options)
            if data is not None:
                headers['Content-Type'] = 'application/json'
            if idem:
                headers['Idempotency-Key'] = idem
            try:
                resp = self.transport(_transport.Request(method, url, headers, data, timeout, stream))
            except APIConnectionError:
                if attempt < self.max_retries:
                    self._sleep(self._retry_wait(attempt, None))
                    attempt += 1
                    continue
                raise
            self.last_response = LastResponse(resp.status, resp.headers)
            if resp.status == 401 and self.oauth is not None and not retried_auth and self.oauth.can_refresh():
                retried_auth = True  # the access token may have been revoked or expired early: refresh once
                try:
                    self.oauth.refresh_now(only_if=headers['Authorization'][len('Bearer '):])
                except OAuthError as e:
                    if e.ended:
                        return resp  # the sign-in itself ended: the caller gets the 401 as AuthenticationError
                    raise APIConnectionError(f'The token endpoint is unavailable ({e}); try again') from e
                resp.close()
                continue
            # 409 + Retry-After = our earlier try with this Idempotency-Key is still running (e.g. after a timeout):
            # asking again shortly returns its stored answer. A real conflict (code taken) has no Retry-After.
            in_flight = resp.status == 409 and idem and 'retry-after' in resp.headers
            if (resp.status in RETRY_STATUSES or in_flight) and attempt < self.max_retries:
                resp.close()
                self._sleep(self._retry_wait(attempt, resp.headers))
                attempt += 1
                continue
            return resp

    def _raise_for(self, resp):
        body = resp.body
        if resp.lines is not None:
            body = b''.join(resp.lines)
        try:
            problem = json.loads(body.decode('utf-8')) if body else {}
        except ValueError:
            problem = {'title': f'HTTP {resp.status}', 'detail': body[:200].decode('utf-8', 'replace')}
        raise error_for(resp.status, problem, resp.headers)

    def _request(self, method, path, *, path_params=None, query=None, body=None, paged=False, options=None):
        url = self._url(path, path_params, query)
        resp = self._send(method, url, body, options)
        if resp.status >= 300:  # the API never redirects; a 3xx means a proxy or wrong base_url
            self._raise_for(resp)
        ctype = resp.headers.get('content-type', '')
        if 'json' not in ctype:
            if not resp.body and resp.status == 204:
                return None
            return BinaryResponse(resp.body, resp.headers)
        payload = json.loads(resp.body.decode('utf-8')) if resp.body else None
        if isinstance(payload, dict) and 'success' in payload and 'data' in payload:
            if paged:
                def fetch(n):
                    return self._request(method, path, path_params=path_params, query={**(query or {}), 'page': n},
                                         paged=True, options=options)
                return Page(payload['data'], payload.get('meta'), fetch)
            return payload['data']
        return payload

    def _stream(self, path, *, path_params=None, query=None, options=None):
        """Server-sent events as dicts. Heartbeats are skipped; the stream ends when the server closes it."""
        options = dict(options or {})
        options.setdefault('headers', {})
        options['headers'] = {**options['headers'], 'Accept': 'text/event-stream'}
        resp = self._send('GET', self._url(path, path_params, query), None, options, stream=True)
        if resp.status >= 400:
            self._raise_for(resp)
        event, data = None, []
        try:
            for raw in resp.lines:
                line = raw.decode('utf-8').rstrip('\r\n')
                if not line:
                    if data:
                        text = '\n'.join(data)
                        try:
                            item = json.loads(text)
                        except ValueError:
                            item = {'data': text}
                        if event and isinstance(item, dict):
                            item.setdefault('event', event)
                        yield item
                    event, data = None, []
                elif line.startswith(':'):
                    continue
                elif line.startswith('event:'):
                    event = line[6:].strip()
                elif line.startswith('data:'):
                    data.append(line[5:].lstrip())
        finally:
            resp.close()


__all__ = ['BNShortener', 'Page', 'BinaryResponse', 'LastResponse', 'APIError', 'AuthenticationError']
