"""Check that a webhook really comes from BN Shortener.

Every JSON delivery has ``X-BN-Signature: t=<unix time>,v1=<hex HMAC-SHA256(secret, "<t>.<raw body>")>``.
Pass the RAW request body (bytes, before any JSON parsing) and the webhook's secret::

    event = construct_event(request.get_data(), request.headers, secret)   # raises WebhookVerificationError
    if event['event'] == 'link.clicked': ...
"""
import hashlib
import hmac
import json
import time
from typing import Mapping, Optional, Union

from ._errors import WebhookVerificationError

SIGNATURE_HEADER = 'X-BN-Signature'
DEFAULT_TOLERANCE = 300


def _header(headers, name):
    if hasattr(headers, 'get'):
        v = headers.get(name)
        if v is not None:
            return v
    for k, v in dict(headers).items():
        if k.lower() == name.lower():
            return v
    return None


def sign(payload: Union[bytes, str], secret: str, timestamp: Optional[int] = None) -> str:
    """The X-BN-Signature value for a body (useful in your own tests)."""
    body = payload.encode('utf-8') if isinstance(payload, str) else payload
    t = int(time.time()) if timestamp is None else int(timestamp)
    mac = hmac.new(secret.encode('utf-8'), f'{t}.'.encode('ascii') + body, hashlib.sha256).hexdigest()
    return f't={t},v1={mac}'


def verify_signature(payload: Union[bytes, str], headers: Mapping[str, str], secret: str, *,
                     tolerance: int = DEFAULT_TOLERANCE, now: Optional[float] = None) -> None:
    """Raises WebhookVerificationError unless the signature matches and is at most ``tolerance`` seconds old."""
    value = _header(headers, SIGNATURE_HEADER)
    if not value:
        raise WebhookVerificationError(f'No {SIGNATURE_HEADER} header')
    parts = {}
    for item in value.split(','):
        k, sep, v = item.strip().partition('=')
        if sep:
            parts.setdefault(k, []).append(v)
    try:
        t = int(parts['t'][0])
    except (KeyError, ValueError):
        raise WebhookVerificationError('Signature has no timestamp') from None
    body = payload.encode('utf-8') if isinstance(payload, str) else payload
    expected = hmac.new(secret.encode('utf-8'), f'{t}.'.encode('ascii') + body, hashlib.sha256).hexdigest()
    if not any(hmac.compare_digest(expected.encode('ascii'), v.encode('utf-8', 'replace')) for v in parts.get('v1', [])):
        raise WebhookVerificationError('Signature does not match (wrong secret, or the body was changed or re-encoded)')
    if tolerance and abs((time.time() if now is None else now) - t) > tolerance:
        raise WebhookVerificationError('Signature is too old (replayed delivery?)')


def construct_event(payload: Union[bytes, str], headers: Mapping[str, str], secret: str, *,
                    tolerance: int = DEFAULT_TOLERANCE) -> dict:
    """Verify, then return the parsed event ({id, event, timestamp, data, ...})."""
    verify_signature(payload, headers, secret, tolerance=tolerance)
    return json.loads(payload)
