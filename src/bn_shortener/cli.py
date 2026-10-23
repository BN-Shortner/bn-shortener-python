"""bn: the BN Shortener command line (https://b1.lc/docs/tools/cli/).

  bn login                      sign in in the browser with a code (or: bn login --api-key)
  bn shorten https://example.com/sale --title "Sale" --qr sale.png
  bn links --search sale        bn stats AbC9 --period 7d        bn check AbC9  (exit 1 when not ready)
  bn qr https://example.com -o menu.svg        bn bulk urls.txt > links.csv        bn api GET /usage

Every command takes --json for scripts. BN_API_KEY (and BN_BASE_URL) override the saved login.
"""
import argparse
import contextlib
import csv
import io
import json
import os
import re
import sys
import tempfile
import webbrowser

from . import oauth as bn_oauth
from ._client import BNShortener, Page
from ._errors import APIConnectionError, APIError, AuthenticationError, BNError, NotFoundError, OAuthError
from ._version import __version__

CLI_CLIENT_ID = 'bnc_cli'  # first-party OAuth app "BN Shortener CLI" (device flow)
LOGIN_SCOPES = ('read', 'write', 'delete')
EXIT_ERROR, EXIT_USAGE, EXIT_AUTH, EXIT_NOT_READY = 1, 2, 3, 1


class CLIError(Exception):
    def __init__(self, message, code=EXIT_ERROR):
        super().__init__(message)
        self.code = code


# ---- saved login ------------------------------------------------------------------------------------------------------
def config_dir():
    if os.environ.get('BN_CONFIG_DIR'):
        return os.environ['BN_CONFIG_DIR']
    base = os.environ.get('XDG_CONFIG_HOME') or os.path.join(os.path.expanduser('~'), '.config')
    return os.path.join(base, 'bn')


def creds_path():
    return os.path.join(config_dir(), 'credentials.json')


def load_creds():
    try:
        with open(creds_path(), encoding='utf-8') as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def save_creds(data):
    os.makedirs(config_dir(), mode=0o700, exist_ok=True)
    path = creds_path()
    fd, tmp = tempfile.mkstemp(dir=config_dir(), prefix='.credentials-', suffix='.tmp')  # 0600: the token is a password
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=1)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.remove(tmp)
        raise


@contextlib.contextmanager
def creds_lock():
    """Only one bn process refreshes at a time: a refresh token works once, and reusing one ends the sign-in."""
    os.makedirs(config_dir(), mode=0o700, exist_ok=True)
    f = open(os.path.join(config_dir(), '.lock'), 'a+')
    try:
        try:
            import fcntl
            fcntl.flock(f, fcntl.LOCK_EX)
        except ImportError:  # Windows
            import msvcrt
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)
        yield
    finally:
        f.close()


class SavedSession(bn_oauth.TokenSession):
    """TokenSession whose refreshes are shared with other bn processes through the credentials file."""

    def __init__(self, client, creds):
        super().__init__(client, creds['token'])
        self.creds = creds

    def refresh_now(self, only_if=None):
        with self._lock, creds_lock():
            current = load_creds() or {}
            disk = bn_oauth.Token.from_dict(current['token']) if current.get('type') == 'oauth' and current.get('token') else None
            if disk and disk.access_token != self.token.access_token and not disk.expired():
                self.token = disk  # another bn process already refreshed: use its token
                return self.token.access_token
            if disk and disk.refresh_token != self.token.refresh_token:
                self.token = disk
            if only_if is not None and self.token.access_token != only_if and not self.token.expired():
                return self.token.access_token
            if not self.can_refresh():
                return self.token.access_token
            self.token = self.client.refresh(self.token.refresh_token)
            try:
                save_creds({**self.creds, **current, 'token': self.token.to_dict()})
            except OSError as e:
                print(f'bn: could not save the refreshed sign-in to {creds_path()} ({e}); run bn login next time', file=sys.stderr)
            return self.token.access_token


def issuer_for(base_url):
    m = re.match(r'^(https?://[^/]+)', base_url)
    return m.group(1) if m else 'https://b1.lc'


class Ctx:
    def __init__(self, args, transport=None):
        self.args = args
        self.transport = transport
        self.base_url = (args.base_url or os.environ.get('BN_BASE_URL') or 'https://b1.lc/api/v1').rstrip('/')
        self._client = None

    def oauth_app(self, issuer=None, client_id=CLI_CLIENT_ID):
        return bn_oauth.OAuthClient(client_id, issuer=issuer or issuer_for(self.base_url), transport=self.transport)

    @property
    def client(self):
        if self._client:
            return self._client
        kw = {'base_url': self.base_url, 'client_name': f'bn-cli/{__version__}'}
        if self.transport:
            kw['transport'] = self.transport
        key = os.environ.get('BN_API_KEY')
        creds = None if key else load_creds()
        if key:
            self._client = BNShortener(key, **kw)
        elif creds and creds.get('type') == 'api_key':
            self._client = BNShortener(creds['api_key'], **{**kw, 'base_url': creds.get('base_url') or self.base_url})
        elif creds and creds.get('type') == 'oauth':
            app = self.oauth_app(creds.get('issuer'), creds.get('client_id') or CLI_CLIENT_ID)
            session = SavedSession(app, creds)
            self._client = BNShortener(oauth=session, **{**kw, 'base_url': creds.get('base_url') or self.base_url})
        else:
            raise CLIError('Not signed in. Run: bn login   (or set BN_API_KEY)', EXIT_AUTH)
        return self._client


# ---- output -----------------------------------------------------------------------------------------------------------
def out_json(data):
    print(json.dumps(data, indent=2, ensure_ascii=False, default=str))


def table(rows, cols):
    """rows: list of dicts; cols: [(header, key or callable)]."""
    cells = [[h for h, _ in cols]] + [[str((k(r) if callable(k) else r.get(k)) if (k(r) if callable(k) else r.get(k)) is not None else '')
                                       for _, k in cols] for r in rows]
    widths = [min(60, max(len(row[i]) for row in cells)) for i in range(len(cols))]
    for n, row in enumerate(cells):
        print('  '.join((c if len(c) <= widths[i] else c[:widths[i] - 1] + '…').ljust(widths[i]) for i, c in enumerate(row)).rstrip())
        if n == 0:
            print('  '.join('-' * w for w in widths))


def spark(values):
    bars = '▁▂▃▄▅▆▇█'
    top = max(values) if values else 0
    return ''.join(bars[min(7, int(v * 7 / top))] if top else bars[0] for v in values)


# ---- link references --------------------------------------------------------------------------------------------------
def link_id(ctx, ref):
    """A link id from AbC9, b1.lc/AbC9, https://b0.lc/AbC9, a custom domain short URL, id:123 or 123.
    All-digit values are codes first (b1.lc/2024 is common), then ids."""
    ref = str(ref).strip()
    if re.match(r'^id:[0-9]+$', ref):
        return int(ref[3:])
    if ref.isdigit():
        try:
            return ctx.client.links.get_by_code(ref)['id']
        except NotFoundError:
            return int(ref)
    m = re.match(r'^(?:https?://)?([^/\s]+)/([A-Za-z0-9_-]+)/?$', ref)
    code, domain = (m.group(2), m.group(1).lower()) if m else (ref, None)
    if not re.match(r'^[A-Za-z0-9_-]{1,50}$', code):
        raise CLIError(f'Not a link id, code or short URL: {ref}', EXIT_USAGE)
    domain = domain if domain and domain not in ('b1.lc', 'www.b1.lc') else None
    try:
        return ctx.client.links.get_by_code(code, domain=domain)['id']
    except NotFoundError:
        raise CLIError(f'No link {ref} in this account') from None


def _by_name(items, ref, what):
    ref = str(ref).strip()
    if ref.isdigit():
        return int(ref)
    hits = [x for x in items if str(x.get('name', '')).lower() == ref.lower()]
    if not hits:
        raise CLIError(f'No {what} named "{ref}"', EXIT_USAGE)
    return hits[0]['id']


def campaign_id(ctx, ref):
    """A campaign id from its id or exact name (archived ones too)."""
    if str(ref).strip().isdigit():
        return int(ref)
    return _by_name(list(ctx.client.paginate(ctx.client.campaigns.list, search=str(ref).strip(), include_archived=True, per_page=100)),
                    ref, 'campaign')


def preset_id(ctx, ref):
    return _by_name(list(ctx.client.utm.list_presets()), ref, 'UTM preset')


def _utm(a):
    tags = {k: getattr(a, f'utm_{k}') for k in ('source', 'medium', 'campaign', 'term', 'content') if getattr(a, f'utm_{k}', None)}
    return tags or None


# ---- commands ---------------------------------------------------------------------------------------------------------
def cmd_login(ctx, a):
    issuer = issuer_for(ctx.base_url)
    if a.api_key is not None:
        key = a.api_key or (sys.stdin.readline().strip() if not sys.stdin.isatty() else __import__('getpass').getpass('API key: '))
        if not key:
            raise CLIError('No API key given', EXIT_USAGE)
        probe = BNShortener(key, base_url=ctx.base_url, client_name=f'bn-cli/{__version__}', **({'transport': ctx.transport} if ctx.transport else {}))
        probe.account.usage()  # fails with AuthenticationError when the key is wrong
        save_creds({'type': 'api_key', 'api_key': key, 'base_url': ctx.base_url})
        print(f'Saved the API key to {creds_path()}', file=sys.stderr)
        return 0
    app = ctx.oauth_app(issuer)
    scopes = a.scope.split(',') if a.scope else list(LOGIN_SCOPES)
    device = app.start_device_flow(scopes)
    print(f'Open {device.verification_uri} and enter the code:  {device.user_code}', file=sys.stderr)
    if not a.no_browser and not os.environ.get('BN_NO_BROWSER'):
        try:
            webbrowser.open(device.verification_uri_complete)
        except Exception:
            pass
    print('Waiting for you to approve it in the browser...', file=sys.stderr)
    token = app.wait_for_device(device)
    save_creds({'type': 'oauth', 'issuer': issuer, 'client_id': app.client_id, 'base_url': ctx.base_url, 'token': token.to_dict()})
    print(f"Signed in ({token.scope}). Saved to {creds_path()}", file=sys.stderr)
    return 0


def cmd_logout(ctx, a):
    creds = load_creds()
    if not creds:
        print('Not signed in.', file=sys.stderr)
        return 0
    if creds.get('type') == 'oauth':
        try:
            tok = creds['token']
            ctx.oauth_app(creds.get('issuer'), creds.get('client_id') or CLI_CLIENT_ID).revoke(tok.get('refresh_token') or tok['access_token'])
        except (BNError, KeyError):
            print('Could not reach BN Shortener to end the sign-in; disconnect "BN Shortener CLI" in Settings, Connected Apps.', file=sys.stderr)
    os.remove(creds_path())
    print('Signed out.', file=sys.stderr)
    return 0


def cmd_whoami(ctx, a):
    usage = ctx.client.account.usage()
    creds = load_creds() or {}
    how = 'BN_API_KEY' if os.environ.get('BN_API_KEY') else {'oauth': 'bn login', 'api_key': 'saved API key'}.get(creds.get('type'), '?')
    if a.json:
        return out_json({'auth': how, 'base_url': ctx.client.base_url, 'usage': usage})
    print(f"Signed in with {how} at {ctx.client.base_url}")
    print(f"Plan: {usage.get('plan_name') or usage.get('plan')}" + (' (complimentary, no limits)' if usage.get('exempt') else ''))
    names = {'links': 'links this month', 'qr': 'QR codes', 'bio_pages': 'bio pages', 'domains': 'custom domains',
             'monitors': 'Guardian monitors', 'seats': 'team seats'}
    for name, v in (usage.get('resources') or {}).items():
        lim = v.get('limit')
        print(f"  {names.get(name, name)}: {v.get('used', 0)} / {'unlimited' if lim is None else lim}")
    return 0


def _link_body(a):
    body = {'url': a.url} if getattr(a, 'url', None) else {}
    for k in ('title', 'domain', 'password'):
        if getattr(a, k, None):
            body[k] = getattr(a, k)
    if getattr(a, 'code', None):
        body['custom_code'] = a.code
    if getattr(a, 'tags', None):
        body['tags'] = [t.strip() for t in a.tags.split(',') if t.strip()]
    if getattr(a, 'expires', None):
        body['expires_at'] = a.expires
    return body


def qr_format(path, fmt=None):
    fmt = fmt or (os.path.splitext(path)[1].lstrip('.').lower() if path != '-' else '') or 'png'
    fmt = 'jpeg' if fmt == 'jpg' else fmt
    if fmt not in ('png', 'jpeg', 'webp', 'svg', 'pdf', 'eps'):
        raise CLIError(f'Unknown QR file type .{fmt}: use png, jpg, webp, svg, pdf or eps', EXIT_USAGE)
    return fmt


def _save_qr(ctx, qr_id, path, fmt=None, size=None):
    fmt = qr_format(path, fmt)
    img = ctx.client.qr_codes.image(qr_id, format=fmt, size=size or (1000 if fmt in ('svg', 'pdf', 'eps') else 600))
    if path == '-':
        sys.stdout.buffer.write(img.content)
    else:
        img.save(path)
    omitted = img.headers.get('x-qr-vector-omitted')
    if omitted:
        print(f'Note: left out of the vector file: {omitted}', file=sys.stderr)
    return path


def cmd_shorten(ctx, a):
    if a.qr:
        qr_format(a.qr)  # a bad file type fails before anything is created
    body = _link_body(a)
    if a.campaign:
        body['campaign_id'] = campaign_id(ctx, a.campaign)
    if _utm(a):
        body['utm'] = _utm(a)
    if a.utm_preset:
        body['utm_preset_id'] = preset_id(ctx, a.utm_preset)
    link = ctx.client.links.create(body)
    result = dict(link)
    text = sys.stderr if a.qr == '-' else sys.stdout  # the image goes to stdout then
    code = 0
    if a.qr:
        try:
            qr = ctx.client.qr_codes.create(name=link.get('title') or a.url[:100], type='url', content={'url': link['short_url']})
            result['qr'] = {'id': qr['id'], 'file': _save_qr(ctx, qr['id'], a.qr)}
        except (APIError, OSError) as e:  # the link exists: still say which one
            print(f'bn: the link was made but not the QR code: {e}', file=sys.stderr)
            code = EXIT_ERROR
    if a.json:
        print(json.dumps(result, indent=2, ensure_ascii=False, default=str), file=text)
        return code
    print(link['short_url'], file=text)
    if a.qr and a.qr != '-' and 'qr' in result:
        print(f'QR code saved to {a.qr}', file=sys.stderr)
    return code


def _all(page, limit):
    items = []
    while page is not None and len(items) < limit:
        items.extend(page)
        page = page.next_page() if len(items) < limit else None
    return items[:limit]


def cmd_links(ctx, a):
    c = ctx.client
    page = c.links.list(search=a.search, per_page=min(100, a.limit), sort=a.sort, order='asc' if a.asc else None,
                        is_active=False if a.inactive else None)
    items = _all(page, a.limit)
    if a.json:
        return out_json(items)
    table(items, [('ID', 'id'), ('SHORT URL', 'short_url'), ('CLICKS', 'click_count'), ('TITLE', 'title'),
                  ('DESTINATION', 'original_url'), ('CREATED', lambda r: (r.get('created_at') or '')[:10])])
    p = page.pagination
    if p.get('total_items') and p['total_items'] > len(items):
        print(f"({len(items)} of {p['total_items']}; --limit N for more)", file=sys.stderr)
    return 0


def cmd_link(ctx, a):
    c = ctx.client
    lid = link_id(ctx, a.ref)
    if a.action == 'get':
        out = c.links.get(lid)
    elif a.action == 'update':
        body = _link_body(a)
        if a.disable:
            body['is_active'] = False
        if a.enable:
            body['is_active'] = True
        if a.no_expiry:
            body['expires_at'] = None
        if not body:
            raise CLIError('Nothing to change: --url, --title, --tags, --expires, --no-expiry, --disable or --enable', EXIT_USAGE)
        out = c.links.update(lid, body)
    elif a.action == 'archive':
        out = c.links.archive(lid) or {'id': lid, 'is_archived': True}
    elif a.action == 'restore':
        out = c.links.restore(lid) or {'id': lid}
    else:  # delete
        if not a.yes and sys.stdin.isatty():
            if input(f'Move link {a.ref} to Trash (restorable for 30 days)? [y/N] ').strip().lower() not in ('y', 'yes'):
                raise CLIError('Not deleted')
        c.links.delete(lid)
        out = {'id': lid, 'deleted': True}
    if a.json:
        return out_json(out)
    if a.action == 'delete':
        print(f'Moved link {lid} to Trash (restorable in the dashboard for 30 days).')
    else:
        for k in ('id', 'short_url', 'original_url', 'title', 'tags', 'is_active', 'is_archived', 'click_count', 'expires_at', 'created_at'):
            if k in out:
                print(f'{k:>14}: {out[k] if out[k] is not None else ""}')
    return 0


def cmd_stats(ctx, a):
    lid = link_id(ctx, a.ref)
    s = ctx.client.links.stats(lid, period=a.period, country=a.country, device=a.device,
                               include_bots=True if a.include_bots else None)
    if a.json:
        return out_json(s)
    link, sm = s.get('link') or {}, s.get('summary') or {}
    print(f"{link.get('short_url')}  ->  {link.get('original_url')}")
    print(f"{a.period}: {sm.get('total_clicks', 0)} clicks, {sm.get('unique_clicks', 0)} unique"
          + (' (people only)' if not s.get('includes_bots') else ' (bots included)'))
    tl = [d.get('clicks', 0) for d in s.get('timeline') or []]
    if tl:
        print(f'  {spark(tl)}  per day')
    for title, rows, key in (('Countries', (s.get('geography') or {}).get('countries'), 'country'),
                             ('Devices', (s.get('devices') or {}).get('types'), 'type'),
                             ('Referrers', s.get('referrers'), 'domain')):
        rows = list(rows or [])[:5]
        if rows:
            print(f'{title}: ' + ', '.join(f"{r.get(key) or 'Direct'} {r.get('clicks')}" for r in rows))
    return 0


def cmd_qr(ctx, a):
    target = a.target
    if not re.match(r'^https?://', target):  # a link of this account: encode its short URL
        target = ctx.client.links.get(link_id(ctx, target))['short_url']
    qr = ctx.client.qr_codes.create(name=a.name or target[:100], type='url', content={'url': target})
    path = a.output or f"qr-{qr['id']}.{a.format or 'png'}"
    _save_qr(ctx, qr['id'], path, a.format, a.size)
    if a.json:
        return out_json({**qr, 'file': path})
    if path != '-':
        print(f"{path}  (scans: {qr.get('scan_url')})")
    return 0


def cmd_check(ctx, a):
    lid = link_id(ctx, a.ref)
    r = ctx.client.launch_check.run(lid)
    verdict = r.get('verdict')
    if a.json:
        out_json(r)
    else:
        print(f"Launch Check: {verdict}  ({r.get('destination')})")
        mark = {'pass': 'ok  ', 'warn': 'warn', 'fail': 'FAIL', 'unknown': '??  ', 'info': 'info'}
        for c in r.get('results') or []:
            if c.get('status') == 'pass' and not a.all:
                continue
            print(f"  [{mark.get(c.get('status'), c.get('status'))}] {c.get('name')}: {c.get('summary')}")
            if c.get('fix') and c.get('status') in ('fail', 'warn'):
                print(f"         fix: {c['fix']}")
    if verdict == 'not_ready' or (a.strict and verdict != 'ready'):
        return EXIT_NOT_READY
    return 0


def cmd_health(ctx, a):
    r = ctx.client.links.health(severity=a.severity)
    issues = r.get('issues') or []
    if a.json:
        return out_json(r)
    if not issues:
        print('No link needs attention.')
        return 0
    table(issues, [('SEVERITY', 'severity'), ('LINK', lambda i: (i.get('link') or {}).get('short_url')),
                   ('PROBLEM', 'label'), ('DETAIL', 'detail')])
    return 0


def cmd_scan(ctx, a):
    r = ctx.client.security.scan(url=a.url)
    if a.json:
        out_json(r)
    else:
        print(f"{r.get('url')}: {r.get('threat_level')}" + (' (blocked)' if r.get('blocked') else ''))
        for t in r.get('threats') or []:
            print(f'  - {t}')
    return 1 if r.get('blocked') else 0


def _read_rows(path):
    text = sys.stdin.read() if path == '-' else open(path, encoding='utf-8-sig').read()
    lines = [l for l in text.splitlines() if l.strip() and not l.lstrip().startswith('#')]
    if lines and ',' in lines[0] and 'url' in [h.strip().lower() for h in lines[0].split(',')]:
        rows = list(csv.DictReader(io.StringIO('\n'.join(lines))))
        return [{k.strip().lower(): (v or '').strip() for k, v in r.items() if k} for r in rows]
    return [{'url': l.strip()} for l in lines]


def cmd_bulk(ctx, a):
    rows = _read_rows(a.file)
    if not rows:
        raise CLIError('No URLs found (one per line, or a CSV with a url column)', EXIT_USAGE)
    results = []
    todo = []
    for r in rows:
        if r.get('url'):
            todo.append({k: v for k, v in (('url', r.get('url')), ('title', r.get('title')), ('tags', r.get('tags')),
                                           ('custom_code', r.get('code') or r.get('custom_code'))) if v})
        else:
            results.append({'url': '', 'short_url': '', 'error': 'no url in this row'})
    stopped = None
    for i in range(0, len(todo), 100):
        chunk = todo[i:i + 100]
        if stopped:  # an earlier chunk was refused as a whole (plan limit, rate limit...): report, don't retry
            results += [{'url': c['url'], 'short_url': '', 'error': f'not sent: {stopped}'} for c in chunk]
            continue
        try:
            res = ctx.client.links.bulk_create(links=chunk)
        except APIError as e:  # every link of the chunk failed: the API answers 400 with the per-link results
            res = (e.problem.get('data') if isinstance(e.problem.get('data'), dict) else None) or {}
            if not res.get('results'):
                stopped = e.detail or e.title or f'HTTP {e.status}'
                results += [{'url': c['url'], 'short_url': '', 'error': stopped} for c in chunk]
                continue
        got = res.get('results') or []
        for n, src in enumerate(chunk):
            r = got[n] if n < len(got) else {}
            results.append({'url': src['url'], 'short_url': (r.get('data') or {}).get('short_url', ''),
                            'error': '' if r.get('success') else ((r.get('error') or {}).get('message') or 'failed')})
    if a.json:
        out_json(results)
    else:
        w = csv.writer(sys.stdout)
        w.writerow(['url', 'short_url', 'error'])
        for r in results:
            w.writerow([r['url'], r['short_url'], r['error']])
    failed = sum(1 for r in results if r['error'])
    if failed:
        print(f'{failed} of {len(results)} failed', file=sys.stderr)
    return 1 if failed else 0


def cmd_campaigns(ctx, a):
    items = list(ctx.client.paginate(ctx.client.campaigns.list, search=a.search, include_archived=True if a.all else None, per_page=100))
    if a.json:
        return out_json(items)
    if not items:
        print('No campaigns yet. Create one: bn campaign create "Spring sale"')
        return 0
    table(items, [('ID', 'id'), ('NAME', 'name'), ('LINKS', 'link_count'), ('CLICKS', 'total_clicks'),
                  ('GOAL', lambda c: f"{c['goal_progress']:g}% of {c['goal_value']:g}" if c.get('goal_progress') is not None else (c.get('goal_type') or '')),
                  ('DATES', lambda c: ' to '.join(x for x in (c.get('start_date'), c.get('end_date')) if x)),
                  ('', lambda c: 'archived' if c.get('is_archived') else '')])
    return 0


def cmd_campaign(ctx, a):
    c = ctx.client.campaigns
    if a.action == 'create':
        body = {'name': a.ref}
        for k in ('description', 'color', 'goal_type', 'start_date', 'end_date'):
            if getattr(a, k, None):
                body[k] = getattr(a, k)
        if a.goal is not None:
            body['goal_value'] = a.goal
            body.setdefault('goal_type', 'clicks')
        if a.budget is not None:
            body['budget'] = a.budget
        out = c.create(body)
    else:
        cid = campaign_id(ctx, a.ref)
        if a.action == 'show':
            out = c.get(cid)
        elif a.action == 'stats':
            out = c.analytics(cid, days=a.days)
            if not a.json:
                camp = c.get(cid)
                sm = out['summary']
                print(f"{camp['name']}: {sm['clicks']} clicks by people in {out['days']} days, {sm['unique_visitors']} unique, "
                      f"{camp['link_count']} links")
                tl = [d['clicks'] for d in out.get('timeline') or []]
                if tl:
                    print(f'  {spark(tl)}  per day with clicks')
                if out.get('top_links'):
                    print('Top links: ' + ', '.join(f"{l['short_url']} {l['clicks']}" for l in out['top_links'][:5]))
                if out.get('top_countries'):
                    print('Countries: ' + ', '.join(f"{x['country'] or x['country_code']} {x['clicks']}" for x in out['top_countries'][:5]))
                return 0
        elif a.action in ('add', 'remove'):
            if not a.links:
                raise CLIError('Give the links: bn campaign add CAMPAIGN LINK [LINK...]', EXIT_USAGE)
            ids = [link_id(ctx, r) for r in a.links]
            out = (c.add_links if a.action == 'add' else c.remove_links)(cid, {'link_ids': ids})
        elif a.action == 'archive':
            out = c.update(cid, {'is_archived': True})
        else:  # delete
            if not a.yes and sys.stdin.isatty():
                what = 'and move its links to Trash' if a.with_links else '(its links stay, outside any campaign)'
                if input(f'Delete campaign {a.ref} {what}? [y/N] ').strip().lower() not in ('y', 'yes'):
                    raise CLIError('Not deleted')
            out = c.delete(cid, delete_links=True if a.with_links else None)
    if a.json:
        return out_json(out)
    if a.action in ('add', 'remove'):
        print(f"{out['updated']} link(s) {'added' if a.action == 'add' else 'removed'}; the campaign has {out['link_count']}.")
    elif a.action == 'delete':
        print(f"Deleted campaign {a.ref}.")
    else:
        for k in ('id', 'name', 'description', 'link_count', 'total_clicks', 'goal_type', 'goal_value', 'goal_progress', 'start_date',
                  'end_date', 'budget', 'is_archived'):
            if out.get(k) not in (None, ''):
                print(f'{k:>14}: {out[k]}')
        if out.get('last_30_days'):
            print(f"{'last 30 days':>14}: {out['last_30_days']['clicks']} clicks")
    return 0


def cmd_domains(ctx, a):
    items = ctx.client.domains.list()
    if a.json:
        return out_json(items)
    table(items, [('DOMAIN', 'domain'), ('ID', lambda d: d['id'] if d['id'] is not None else 'default'), ('TYPE', 'type'),
                  ('READY', lambda d: 'yes' if d['ready'] else f"no ({d['ssl_status']})"), ('YOUR LINKS', 'link_count')])
    return 0


def cmd_utm(ctx, a):
    if a.action == 'presets':
        items = ctx.client.utm.list_presets()
        if a.json:
            return out_json(items)
        if not items:
            print('No UTM presets yet (dashboard: UTM Builder).')
            return 0
        table(items, [('ID', 'id'), ('NAME', 'name'), ('SOURCE', lambda p: p['utm']['source']), ('MEDIUM', lambda p: p['utm']['medium']),
                      ('CAMPAIGN', lambda p: p['utm']['campaign']), ('USED', 'use_count')])
        return 0
    if not a.url:
        raise CLIError('Give the URL: bn utm build URL --utm-source ... (or --utm-preset NAME)', EXIT_USAGE)
    body = {'url': a.url}
    if _utm(a):
        body['utm'] = _utm(a)
    if a.utm_preset:
        body['utm_preset_id'] = preset_id(ctx, a.utm_preset)
    out = ctx.client.utm.build(body)
    if a.json:
        return out_json(out)
    print(out['utm_url'])
    return 0


def cmd_api(ctx, a):
    body = None
    if a.data:
        raw = sys.stdin.read() if a.data == '-' else a.data
        try:
            body = json.loads(raw)
        except ValueError:
            raise CLIError('--data must be JSON', EXIT_USAGE) from None
    query = dict(q.split('=', 1) for q in a.query or [] if '=' in q)
    path = a.path if a.path.startswith('/') else '/' + a.path
    path = path[len('/api/v1'):] if path.startswith('/api/v1/') else path
    r = ctx.client.request(a.method, path, query=query or None, body=body)
    if hasattr(r, 'content'):
        sys.stdout.buffer.write(r.content)
    elif isinstance(r, Page):
        out_json({'data': r.data, 'pagination': r.pagination})
    else:
        out_json(r)
    return 0


# ---- parser -----------------------------------------------------------------------------------------------------------
def parser():
    p = argparse.ArgumentParser(prog='bn', description='BN Shortener (b1.lc) from the command line.',
                                epilog='Docs: https://b1.lc/docs/tools/cli/')
    p.add_argument('--version', action='version', version=f'bn {__version__}')
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument('--json', action='store_true', help='print JSON (for scripts)')
    common.add_argument('--base-url', help=argparse.SUPPRESS)
    sub = p.add_subparsers(dest='cmd', metavar='COMMAND')

    def add(name, fn, help_, **kw):
        sp = sub.add_parser(name, parents=[common], help=help_, description=help_, **kw)
        sp.set_defaults(fn=fn)
        return sp

    s = add('login', cmd_login, 'Sign in (browser + code), or save an API key')
    s.add_argument('--api-key', nargs='?', const='', help='save this API key instead (no value: read it from stdin / a prompt)')
    s.add_argument('--no-browser', action='store_true', help='only print the address and code')
    s.add_argument('--scope', help='comma-separated: read,write,delete,webhooks (default read,write,delete)')
    add('logout', cmd_logout, 'End the saved sign-in')
    add('whoami', cmd_whoami, 'Show how you are signed in and the plan usage')

    def utm_args(sp):
        for k in ('source', 'medium', 'campaign', 'term', 'content'):
            sp.add_argument(f'--utm-{k}', dest=f'utm_{k}', metavar=k.upper(), help=f'UTM {k} tag' if k != 'source' else 'UTM tags to add to the destination')
        sp.add_argument('--utm-preset', help='add the tags of a saved UTM preset (id or name)')

    def link_fields(sp, url_required):
        if url_required:
            sp.add_argument('url', help='destination, https://...')
        else:
            sp.add_argument('--url', help='new destination')
        sp.add_argument('--title')
        sp.add_argument('--tags', help='comma-separated')
        sp.add_argument('--expires', help='ISO 8601 date-time, e.g. 2026-12-31T23:59:00Z')
    s = add('shorten', cmd_shorten, 'Create a short link and print it')
    link_fields(s, True)
    s.add_argument('--code', help='your own short code')
    s.add_argument('--domain', help='b1.lc (default), b0.lc or one of your custom domains')
    s.add_argument('--password', help='visitors must enter it')
    s.add_argument('--qr', metavar='FILE', help='also make a QR code of the short link (png, svg, pdf, eps; - = stdout)')
    s.add_argument('--campaign', help='put it into this campaign (id or name)')
    utm_args(s)

    s = add('links', cmd_links, 'List your links')
    s.add_argument('--search', '-s')
    s.add_argument('--limit', '-n', type=lambda v: max(1, int(v)), default=20)
    s.add_argument('--sort', choices=['created_at', 'updated_at', 'click_count', 'title'])
    s.add_argument('--asc', action='store_true')
    s.add_argument('--inactive', action='store_true', help='only links that are switched off')

    s = add('link', cmd_link, 'Show or change one link')
    s.add_argument('action', choices=['get', 'update', 'archive', 'restore', 'delete'])
    s.add_argument('ref', help='code, short URL or id:123')
    link_fields(s, False)
    s.add_argument('--no-expiry', action='store_true')
    s.add_argument('--disable', action='store_true')
    s.add_argument('--enable', action='store_true')
    s.add_argument('--yes', '-y', action='store_true', help='delete without asking')

    s = add('stats', cmd_stats, 'Click statistics of a link (people only by default)')
    s.add_argument('ref', help='link id, code or short URL')
    s.add_argument('--period', '-p', default='30d', choices=['7d', '30d', '90d', '1y', 'all'])
    s.add_argument('--country', help='ISO code, e.g. DE')
    s.add_argument('--device', help='e.g. Mobile')
    s.add_argument('--include-bots', action='store_true')

    s = add('qr', cmd_qr, 'Make a QR code for a URL or one of your links and save the image')
    s.add_argument('target', help='https://... or a link id / code / short URL')
    s.add_argument('--output', '-o', help='file (type from the extension); - = stdout; default qr-<id>.png')
    s.add_argument('--format', '-f', choices=['png', 'jpeg', 'webp', 'svg', 'pdf', 'eps'])
    s.add_argument('--size', type=int, help='pixels (vector files: page size)')
    s.add_argument('--name', help='name in the dashboard')

    s = add('check', cmd_check, 'Launch Check a link before a campaign (exit 1 when not ready)')
    s.add_argument('ref', help='link id, code or short URL')
    s.add_argument('--strict', action='store_true', help='exit 1 on warnings too')
    s.add_argument('--all', action='store_true', help='also list passed checks')

    s = add('health', cmd_health, 'Links that need attention')
    s.add_argument('--severity', help='critical, warning, info (comma-separated)')

    s = add('scan', cmd_scan, 'Check a URL against threat sources (exit 1 when blocked)')
    s.add_argument('url')

    s = add('bulk', cmd_bulk, 'Shorten many URLs: a file with one URL per line or a CSV (url,title,tags,code); prints CSV')
    s.add_argument('file', help='file, or - for stdin')

    s = add('campaigns', cmd_campaigns, 'List campaigns')
    s.add_argument('--search', '-s')
    s.add_argument('--all', action='store_true', help='archived ones too')

    s = add('campaign', cmd_campaign, 'Create a campaign, or show / stats / add / remove / archive / delete one')
    s.add_argument('action', choices=['create', 'show', 'stats', 'add', 'remove', 'archive', 'delete'])
    s.add_argument('ref', help='create: the name; otherwise the campaign id or name')
    s.add_argument('links', nargs='*', help='add / remove: links (code, short URL or id:N)')
    s.add_argument('--description')
    s.add_argument('--color', help='#RRGGBB')
    s.add_argument('--goal', type=float, help='goal value (clicks unless --goal-type)')
    s.add_argument('--goal-type', choices=['clicks', 'conversions', 'value'])
    s.add_argument('--start', dest='start_date', help='YYYY-MM-DD')
    s.add_argument('--end', dest='end_date', help='YYYY-MM-DD')
    s.add_argument('--budget', type=float)
    s.add_argument('--days', type=int, default=30, help='stats: period (1-365)')
    s.add_argument('--with-links', action='store_true', help='delete: also move its links to Trash')
    s.add_argument('--yes', '-y', action='store_true')

    add('domains', cmd_domains, 'Domains your links can use (b1.lc, b0.lc, your custom domains)')

    s = add('utm', cmd_utm, 'UTM presets, or build a tagged URL')
    s.add_argument('action', choices=['presets', 'build'])
    s.add_argument('url', nargs='?', help='build: the destination')
    utm_args(s)

    s = add('api', cmd_api, 'Call any API v3 endpoint, e.g. bn api GET /links/123/stats -q period=7d')
    s.add_argument('method', type=str.upper, choices=['GET', 'POST', 'PUT', 'PATCH', 'DELETE'])
    s.add_argument('path', help='/links, /usage, ...')
    s.add_argument('--data', '-d', help='JSON body, or - to read it from stdin')
    s.add_argument('--query', '-q', action='append', help='name=value (repeatable)')
    return p


def main(argv=None, transport=None):
    p = parser()
    args = p.parse_args(argv)
    if not getattr(args, 'fn', None):
        p.print_help(sys.stderr)
        return EXIT_USAGE
    ctx = Ctx(args, transport)
    try:
        code = args.fn(ctx, args)
        return code or 0
    except CLIError as e:
        print(f'bn: {e}', file=sys.stderr)
        return e.code
    except AuthenticationError as e:
        print(f'bn: {e}\nSign in again: bn login', file=sys.stderr)
        return EXIT_AUTH
    except APIError as e:
        print(f'bn: {e}', file=sys.stderr)
        return EXIT_ERROR
    except OAuthError as e:
        print(f'bn: sign-in failed: {e}', file=sys.stderr)
        return EXIT_AUTH
    except APIConnectionError as e:
        print(f'bn: {e}', file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print('', file=sys.stderr)
        return 130
    except BrokenPipeError:
        return 0


def run():
    sys.exit(main())


if __name__ == '__main__':
    run()
