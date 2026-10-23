"""HTTP transport. The default uses only the standard library; pass your own ``transport`` to the client to use
another HTTP library, a proxy setup or a test double (any callable taking a Request and returning a Response)."""
import http.client
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterator, Optional

from ._errors import APIConnectionError, APITimeoutError


@dataclass
class Request:
    method: str
    url: str
    headers: Dict[str, str]
    body: Optional[bytes] = None
    timeout: float = 30.0
    stream: bool = False


@dataclass
class Response:
    status: int
    headers: Dict[str, str]  # lower-case names
    body: bytes = b''
    lines: Optional[Iterator[bytes]] = None  # stream=True: the body line by line
    close: Callable[[], None] = field(default=lambda: None)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # The API never redirects; following one would resend the API key to wherever it points
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def urllib_transport(req: Request) -> Response:
    r = urllib.request.Request(req.url, data=req.body, method=req.method, headers=req.headers)
    try:
        resp = _opener.open(r, timeout=req.timeout)
    except urllib.error.HTTPError as e:  # 4xx / 5xx still carry a body
        try:
            body = e.read()
        finally:
            e.close()
        return Response(e.code, {k.lower(): v for k, v in e.headers.items()}, body)
    except socket.timeout as e:
        raise APITimeoutError(f'No answer within {req.timeout} s') from e
    except (urllib.error.URLError, ssl.SSLError, ConnectionError, OSError) as e:
        reason = getattr(e, 'reason', e)
        if isinstance(reason, socket.timeout):
            raise APITimeoutError(f'No answer within {req.timeout} s') from e
        raise APIConnectionError(f'Could not reach {req.url.split("?")[0]}: {reason}') from e
    headers = {k.lower(): v for k, v in resp.headers.items()}
    if req.stream:
        def lines():
            try:
                for line in resp:
                    yield line
            except socket.timeout as e:
                raise APITimeoutError('The stream went quiet for longer than the timeout') from e
            except (http.client.HTTPException, ConnectionError, OSError) as e:
                raise APIConnectionError(f'The stream was cut off: {e}') from e
            finally:
                resp.close()
        return Response(resp.status, headers, b'', lines(), resp.close)
    try:
        body = resp.read()
    except socket.timeout as e:
        raise APITimeoutError(f'No answer within {req.timeout} s') from e
    except (http.client.HTTPException, ConnectionError, OSError) as e:
        raise APIConnectionError(f'The answer was cut off: {e}') from e
    finally:
        resp.close()
    return Response(resp.status, headers, body)
