# bn-shortener (Python)

Official Python client for the [BN Shortener API](https://b1.lc/docs/) (b1.lc): short links, QR codes,
bio pages, analytics, Launch Check, webhooks and OAuth. No dependencies; Python 3.9+.

```bash
pip install bn-shortener
```

## Quick start

```python
from bn_shortener import BNShortener

bn = BNShortener("bn_live_...")          # or set BN_API_KEY

link = bn.links.create(url="https://example.com/spring-sale", title="Spring sale")
print(link["short_url"])                 # https://b1.lc/AbC9

stats = bn.links.stats(link["id"], period="30d")
print(stats["summary"]["total_clicks"])

for l in bn.paginate(bn.links.list, search="sale"):   # every page
    print(l["short_code"], l["click_count"])
```

Create an API key in the dashboard: **API Portal → API keys**. A key has permissions (`read`, `write`, `delete`,
`webhooks`, `admin`); give each integration only what it needs.

## Resources

| Attribute | What |
|---|---|
| `bn.links` | create, get, get_by_code, update, delete, archive, restore, clone, stats, clicks, referrers, devices, geo, timeline, export, import, bulk_create / bulk_update / bulk_delete, health, stream_clicks |
| `bn.qr_codes` | create, get, update, delete, list, image (png, jpeg, webp, svg, pdf, eps), stats |
| `bn.bio_pages` | create, get, update, delete, list, list_blocks, create_block, update_block, delete_block, reorder_blocks, analytics, subscribers, messages |
| `bn.webhooks` | create, get, update, delete, list, test, deliveries, get_delivery, redeliver, events |
| `bn.launch_check` | run, get, start_run, get_run, stop_run |
| `bn.security` | scan, check, get_scan, bulk_scan, list_scans, ... |
| `bn.messaging` | create_batch, list_batches, get_batch, list_messages, record_conversion |
| `bn.api_keys`, `bn.account`, `bn.app_links`, `bn.system` | keys, usage + audit log, apps, API info |

Every method's docstring names its endpoint and the permission it needs. Methods return the response's `data`;
list methods return a `Page` (iterate it; `page.pagination`, `page.next_page()`); files come back as
`BinaryResponse` (`.content`, `.content_type`, `.save(path)`):

```python
qr = bn.qr_codes.create(name="Menu", content={"url": "https://example.com/menu"})
bn.qr_codes.image(qr["id"], format="svg", size=1000).save("menu.svg")
```

## Command line

The package installs the `bn` command: `bn login`, `bn shorten URL`, `bn links`, `bn stats CODE`, `bn check CODE`
(Launch Check, exit 1 when not ready), `bn qr URL -o file.svg`, `bn bulk file.csv`, `bn api GET /usage`. Run
`bn --help`. The same command is a single file at https://b1.lc/cli/bn.

## Errors

```python
from bn_shortener import ValidationError, RateLimitError, NotFoundError, APIError

try:
    bn.links.create(url="not a url")
except ValidationError as e:
    print(e.errors)        # [{'field': 'url', 'code': ..., 'message': ...}]
except APIError as e:
    print(e.status, e.type, e.detail, e.request_id)   # e.type links to https://b1.lc/docs/errors/...
```

Connection errors, timeouts, 408, 429 and 5xx are retried (`max_retries=2`, waiting as long as `Retry-After`
says). Every write carries an `Idempotency-Key`, so a retry after a lost answer never creates a second link.
Pass `request_options={"idempotency_key": "..."}` to make your own retries safe too.

## Apps that act for other people (OAuth 2.1)

```python
from bn_shortener import BNShortener
from bn_shortener.oauth import OAuthClient, TokenSession

app = OAuthClient("bnc_...", redirect_uri="https://example.com/callback")
auth = app.authorization_url(scope=["read", "write"])     # keep auth.state + auth.code_verifier in the session
# send the person to auth.url; b1.lc sends them back to your redirect URI
code = app.parse_callback(callback_url, expected_state=auth.state)
token = app.exchange_code(code, auth.code_verifier)

bn = BNShortener(oauth=TokenSession(app, token, on_refresh=save_token))   # refreshes by itself
```

Command-line tools without a browser use the device flow:

```python
device = app.start_device_flow(scope=["read", "write"])
print(f"Open {device.verification_uri} and type {device.user_code}")
token = app.wait_for_device(device)
```

Refresh tokens rotate: save the new token in `on_refresh` every time.

## Webhooks

```python
from bn_shortener.webhooks import construct_event

event = construct_event(request.get_data(), request.headers, WEBHOOK_SECRET)  # raises WebhookVerificationError
```

Pass the raw body, before any JSON parsing. Signatures older than 5 minutes are refused (replays).

## Options

`BNShortener(api_key, access_token=None, oauth=None, base_url="https://b1.lc/api/v1", timeout=30.0, max_retries=2,
client_name=None, default_headers=None, transport=None)`. `client_name` shows your integration by name in the
account's usage (`GET /usage`). `bn.last_response` has the status, request id and rate limit of the latest call.
`bn.request("GET", "/path")` calls an endpoint this version does not wrap yet.

## License

MIT
