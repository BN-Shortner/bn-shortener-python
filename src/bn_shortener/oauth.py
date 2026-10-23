"""OAuth 2.1 for apps that act for BN Shortener users (https://b1.lc/docs/oauth/).

Web apps and integrations (authorization code + PKCE)::

    app = OAuthClient('bnc_...', redirect_uri='https://example.com/callback')
    auth = app.authorization_url(scope=['read', 'write'])     # keep auth.state and auth.code_verifier in the session
    # ... send the person to auth.url; b1.lc sends them back to the redirect URI ...
    code = app.parse_callback(callback_url, expected_state=auth.state)
    token = app.exchange_code(code, auth.code_verifier)

Command-line tools and devices without a browser (device flow)::

    device = app.start_device_flow(scope=['read', 'write'])
    print(f'Open {device.verification_uri} and type {device.user_code}')
    token = app.wait_for_device(device)

Then ``BNShortener(oauth=TokenSession(app, token, on_refresh=save))``: the session refreshes the access token
(1 hour) by itself and calls ``on_refresh`` with every new token, because refresh tokens rotate on each use.
"""
import base64
import hashlib
import json
import secrets
import threading
import time
from dataclasses import asdict, dataclass
from typing import Callable, Iterable, Optional, Union
from urllib.parse import parse_qs, urlencode, urlparse

from . import _transport
from ._errors import APIConnectionError, BNError, OAuthError
from ._version import __version__

DEFAULT_ISSUER = 'https://b1.lc'
SCOPES = ('read', 'write', 'delete', 'webhooks')
DEVICE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code'


def generate_pkce():
    """(code_verifier, code_challenge) for PKCE S256."""
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode('ascii')).digest()).rstrip(b'=').decode('ascii')
    return verifier, challenge


def _scope(scope):
    if scope is None:
        return None
    return scope if isinstance(scope, str) else ' '.join(scope)


@dataclass
class Token:
    access_token: str
    expires_at: float
    refresh_token: Optional[str] = None
    scope: str = ''
    token_type: str = 'Bearer'

    @classmethod
    def from_response(cls, data):
        return cls(access_token=data['access_token'], refresh_token=data.get('refresh_token'),
                   expires_at=time.time() + int(data.get('expires_in') or 3600), scope=data.get('scope') or '',
                   token_type=data.get('token_type') or 'Bearer')

    @classmethod
    def from_dict(cls, data):
        return cls(**{k: data[k] for k in ('access_token', 'expires_at', 'refresh_token', 'scope', 'token_type') if k in data})

    def to_dict(self):
        return asdict(self)

    @property
    def scopes(self):
        return self.scope.split()

    def expired(self, leeway=60):
        return time.time() >= self.expires_at - leeway


@dataclass
class AuthorizationRequest:
    url: str
    state: str
    code_verifier: str


@dataclass
class DeviceAuthorization:
    device_code: str
    user_code: str
    verification_uri: str
    verification_uri_complete: str
    expires_in: int
    interval: int
    started_at: float


class OAuthClient:
    """One registered app. ``client_secret`` only for confidential (server-side) apps."""

    def __init__(self, client_id: str, *, client_secret: Optional[str] = None, redirect_uri: Optional[str] = None,
                 issuer: str = DEFAULT_ISSUER, timeout: float = 30.0, transport=None):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.issuer = issuer.rstrip('/')
        self.timeout = timeout
        self.transport = transport or _transport.urllib_transport
        self._sleep = time.sleep

    def authorization_url(self, scope: Union[str, Iterable[str]] = ('read',), *, redirect_uri: Optional[str] = None,
                          state: Optional[str] = None) -> AuthorizationRequest:
        redirect_uri = redirect_uri or self.redirect_uri
        if not redirect_uri:
            raise BNError('redirect_uri is required')
        state = state or secrets.token_urlsafe(24)
        verifier, challenge = generate_pkce()
        q = {'response_type': 'code', 'client_id': self.client_id, 'redirect_uri': redirect_uri, 'scope': _scope(scope),
             'state': state, 'code_challenge': challenge, 'code_challenge_method': 'S256'}
        return AuthorizationRequest(f'{self.issuer}/api/oauth/authorize?{urlencode(q)}', state, verifier)

    def parse_callback(self, url: str, *, expected_state: str) -> str:
        """The code from the redirect back to your app, after checking state and issuer (RFC 9207)."""
        q = {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}
        if not secrets.compare_digest(q.get('state', '').encode('utf-8'), (expected_state or '').encode('utf-8')):
            raise OAuthError('invalid_state', 'state does not match: start the sign-in again')
        if q.get('iss') and q['iss'] != self.issuer:
            raise OAuthError('invalid_issuer', f"answer came from {q['iss']}, expected {self.issuer}")
        if 'error' in q:
            raise OAuthError(q['error'], q.get('error_description'))
        if not q.get('code'):
            raise OAuthError('invalid_request', 'no code in the callback URL')
        return q['code']

    def exchange_code(self, code: str, code_verifier: str, *, redirect_uri: Optional[str] = None) -> Token:
        return Token.from_response(self._post('/api/oauth/token', {
            'grant_type': 'authorization_code', 'code': code, 'code_verifier': code_verifier,
            'redirect_uri': redirect_uri or self.redirect_uri}))

    def refresh(self, refresh_token: str) -> Token:
        """A new access token AND a new refresh token: store the new refresh token, the old one stops working."""
        return Token.from_response(self._post('/api/oauth/token', {'grant_type': 'refresh_token', 'refresh_token': refresh_token}))

    def revoke(self, token: str) -> None:
        """Ends the token (a refresh token ends the whole sign-in)."""
        self._post('/api/oauth/revoke', {'token': token})

    def start_device_flow(self, scope: Union[str, Iterable[str]] = ('read',)) -> DeviceAuthorization:
        d = self._post('/api/oauth/device/code', {'scope': _scope(scope)})
        return DeviceAuthorization(d['device_code'], d['user_code'], d['verification_uri'],
                                   d.get('verification_uri_complete') or d['verification_uri'],
                                   int(d.get('expires_in') or 600), int(d.get('interval') or 5), time.time())

    def wait_for_device(self, device: DeviceAuthorization, *, on_poll: Optional[Callable[[], None]] = None) -> Token:
        """Poll until the person approves (Token) or cancels / the code expires (OAuthError)."""
        interval = device.interval
        while True:
            if time.time() - device.started_at > device.expires_in:
                raise OAuthError('expired_token', 'The code expired: start again')
            self._sleep(interval)
            if on_poll:
                on_poll()
            try:
                return Token.from_response(self._post('/api/oauth/token', {'grant_type': DEVICE_GRANT, 'device_code': device.device_code}))
            except OAuthError as e:
                if e.error == 'authorization_pending':
                    continue
                if e.error == 'slow_down' or not e.ended:  # slow down; a 5xx is temporary: keep waiting
                    interval += 5
                    continue
                raise
            except APIConnectionError:  # network blip while the person is approving: keep waiting
                interval = min(interval + 5, 30)
                continue

    def _post(self, path, form):
        form = {k: v for k, v in form.items() if v is not None}
        form['client_id'] = self.client_id
        if self.client_secret:
            form['client_secret'] = self.client_secret
        headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json',
                   'User-Agent': f'bn-shortener-python/{__version__}'}
        resp = self.transport(_transport.Request('POST', self.issuer + path, headers, urlencode(form).encode('ascii'), self.timeout))
        try:
            data = json.loads(resp.body.decode('utf-8')) if resp.body else {}
        except ValueError:
            data = {}
        if resp.status >= 400:
            raise OAuthError(data.get('error') or f'http_{resp.status}', data.get('error_description'), resp.status)
        return data


class TokenSession:
    """Keeps a Token fresh for BNShortener(oauth=...). ``on_refresh(token)`` runs after every refresh: save the
    token there (refresh tokens rotate). Thread-safe."""

    def __init__(self, client: OAuthClient, token: Union[Token, dict], *, on_refresh: Optional[Callable[[Token], None]] = None):
        self.client = client
        self.token = token if isinstance(token, Token) else Token.from_dict(token)
        self.on_refresh = on_refresh
        self._lock = threading.Lock()

    def can_refresh(self):
        return bool(self.token.refresh_token)

    def get_access_token(self):
        if self.token.expired() and self.can_refresh():
            return self.refresh_now(only_if=self.token.access_token)
        return self.token.access_token

    def refresh_now(self, only_if=None):
        with self._lock:
            if only_if is not None and self.token.access_token != only_if:
                return self.token.access_token  # another thread refreshed meanwhile
            if not self.can_refresh():
                return self.token.access_token
            self.token = self.client.refresh(self.token.refresh_token)
            if self.on_refresh:
                self.on_refresh(self.token)
            return self.token.access_token
