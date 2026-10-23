"""Errors raised by the client. API errors carry the RFC 9457 problem fields the API sends."""


class BNError(Exception):
    """Base class of every error this package raises."""


class APIConnectionError(BNError):
    """The request did not get an answer (DNS, refused connection, TLS, reset)."""


class APITimeoutError(APIConnectionError):
    """No answer within the timeout."""


class APIError(BNError):
    """The API answered with an error status.

    ``type`` links to a page that explains the error (https://b1.lc/docs/errors/...); ``errors`` lists field
    problems ({field, code, message}) on 422; quote ``request_id`` when contacting support.
    """

    def __init__(self, status, problem=None, headers=None):
        problem = problem if isinstance(problem, dict) else {}
        self.status = status
        self.problem = problem
        self.type = problem.get('type')
        self.title = problem.get('title')
        self.detail = problem.get('detail') or problem.get('error_description') or problem.get('message')
        self.errors = problem.get('errors') or []
        self.headers = headers or {}
        self.request_id = problem.get('trace_id') or self.headers.get('x-request-id')
        retry = problem.get('retry_after') or self.headers.get('retry-after')
        try:
            self.retry_after = int(retry) if retry is not None else None
        except (TypeError, ValueError):
            self.retry_after = None
        text = self.title or f'HTTP {status}'
        if self.detail and self.detail != self.title:
            text += f': {self.detail}'
        fields = '; '.join(f"{e.get('field')}: {e.get('message')}" for e in self.errors if isinstance(e, dict) and e.get('field'))
        if fields:
            text += f' ({fields})'
        if self.request_id:
            text += f' (request {self.request_id})'
        super().__init__(text)


class BadRequestError(APIError):
    """400"""


class AuthenticationError(APIError):
    """401: missing, wrong, expired or revoked key or token."""


class PermissionDeniedError(APIError):
    """403: the key or app lacks the permission (read, write, delete, webhooks, admin)."""


class NotFoundError(APIError):
    """404"""


class ConflictError(APIError):
    """409: e.g. the short code is taken, or the same Idempotency-Key is still in flight."""


class ValidationError(APIError):
    """422: see ``errors`` for the fields."""


class RateLimitError(APIError):
    """429: see ``retry_after``."""


class InternalServerError(APIError):
    """5xx"""


_BY_STATUS = {400: BadRequestError, 401: AuthenticationError, 403: PermissionDeniedError, 404: NotFoundError,
              409: ConflictError, 422: ValidationError, 429: RateLimitError}


def error_for(status, problem, headers):
    cls = _BY_STATUS.get(status) or (InternalServerError if status >= 500 else APIError)
    return cls(status, problem, headers)


class OAuthError(BNError):
    """The authorization server refused (RFC 6749 ``error`` + ``error_description``)."""

    def __init__(self, error, description=None, status=None):
        self.error = error
        self.description = description
        self.status = status
        super().__init__(f'{error}: {description}' if description else error)

    @property
    def ended(self):
        """True when the grant is gone for good (connect again); False for a temporary failure (5xx)."""
        return self.status is None or self.status < 500


class WebhookVerificationError(BNError):
    """The webhook signature is missing, wrong or too old."""
