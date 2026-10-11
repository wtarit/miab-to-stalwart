#!/usr/bin/env python3
"""Run an S5 Mail migration from the Stalwart machine (Python stdlib only)."""

import argparse
import atexit
import base64
import fcntl
import getpass
import hashlib
import importlib.util
import json
import os
import re
import secrets
import shlex
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

COMPONENTS = {
    'mail': ('imap', 'mailbox,email', 'mail', 29993, 993, 'imaps'),
    'sieve': ('managesieve', 'sievescript', 'sieve', 24190, 4190, 'sieve'),
    'carddav': ('carddav', 'addressbook,contactcard', 'contacts', 24443, 443, 'https'),
    'caldav': ('caldav', 'calendar,calendarevent', 'calendars', 24443, 443, 'https'),
}
HOSTS_TAG = '# stalwart-migration-tunnel'
HOSTS_CODE = '''
import pathlib,sys
p=pathlib.Path('/etc/hosts'); text=p.read_text(); tag=sys.argv[2]
if sys.argv[1] == 'add':
    host=sys.argv[3]
    if any(host in line.split('#')[0].split()[1:] for line in text.splitlines()):
        raise SystemExit('Source hostname already exists in /etc/hosts; remove that override first')
    text='127.0.0.1 '+host+' '+tag+'\\n'+text
else:
    text=''.join(line for line in text.splitlines(keepends=True) if tag not in line)
p.write_text(text)
'''


def checked(command, **kwargs):
    p = subprocess.run(command, **kwargs)
    if p.returncode:
        raise RuntimeError(f'{Path(command[0]).name} failed (exit {p.returncode})')
    return p


class Source:
    def __init__(self, args):
        self.ssh = ['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                    '-o', 'ConnectTimeout=15', '-o', 'ServerAliveInterval=15',
                    '-o', 'ServerAliveCountMax=3']
        if args.identity:
            self.ssh += ['-i', str(args.identity.expanduser())]
        self.host = args.source
        self.code = Path(__file__).with_name('source-agent.py').read_text()
        self.control = tempfile.TemporaryDirectory(prefix='stalwart-migration-ssh-')
        self.ssh += ['-S', str(Path(self.control.name) / 'control')]
        # One transport avoids S5 Mail's UFW SSH rate limit and keeps SSH
        # connected to the original host while /etc/hosts points at tunnels.
        checked(self.ssh + ['-M', '-N', '-f', self.host])
        self.forwards = []
        atexit.register(self.close)

    def close(self):
        try:
            subprocess.run(self.ssh + ['-O', 'exit', self.host],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        finally:
            self.control.cleanup()

    def terminate(self):
        for forward in self.forwards:
            checked(self.ssh + ['-O', 'cancel', '-L', forward, self.host],
                    stdout=subprocess.DEVNULL)
        self.forwards = []

    def call(self, operation, **values):
        command = self.ssh + [self.host, 'sudo -n python3 -c ' + shlex.quote(self.code)]
        p = subprocess.run(command, input=json.dumps({'operation': operation, **values}),
                           text=True, capture_output=True)
        # Do not print stdout: it may contain password hashes or an app token.
        try:
            result = json.loads(p.stdout)
        except ValueError:
            raise RuntimeError('SSH/source operation failed: ' + p.stderr.strip()) from None
        if p.returncode or 'error' in result:
            raise RuntimeError(result.get('error', 'Source operation failed'))
        return result


def hosts(action, hostname=''):
    checked(['sudo', '-n', 'python3', '-c', HOSTS_CODE, action, HOSTS_TAG, hostname])


def load_importer():
    spec = importlib.util.spec_from_file_location('accounts', Path(__file__).with_name('import-miab-account.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def ensure_accounts(users):
    importer = load_importer()
    domains = importer.get_domains()
    existing = importer.get_existing_accounts(domains)
    # Validate every missing account before making any changes.
    pending = [(email, importer.normalize_password_hash(password))
               for email, password in users if email.lower() not in existing]
    for domain in sorted({email.rsplit('@', 1)[1].lower() for email, _ in pending} - domains.keys()):
        print(f'Creating domain: {domain}', flush=True)
        importer.run_cli('create', 'Domain', '--stdin', input_json={'name': domain})
    if pending:
        domains = importer.get_domains()
    for email, password in pending:
        print(f'Creating account: {email}', flush=True)
        importer.create_user(email.lower(), password, domains[email.rsplit('@', 1)[1].lower()])
    if pending:
        importer.invalidate_caches()
    print(f'Accounts ready: {len(users)} ({len(pending)} created)', flush=True)


def auth_header(user, password):
    return 'Basic ' + base64.b64encode(f'{user}:{password}'.encode()).decode()


def preflight_target(args, components):
    parsed = urllib.parse.urlparse(args.stalwart_url)
    if parsed.scheme != 'https' and not (parsed.scheme == 'http' and parsed.hostname in ('127.0.0.1', 'localhost', '::1')):
        raise ValueError('Use HTTPS for Stalwart, or HTTP on loopback only')
    request = urllib.request.Request(args.stalwart_url.rstrip('/') + '/.well-known/jmap',
                                     headers={'Authorization': auth_header(args.stalwart_user, os.environ['STALWART_PASSWORD'])})
    with urllib.request.urlopen(request, timeout=30) as response:
        session = json.load(response)
    required = {'urn:ietf:params:jmap:' + COMPONENTS[c][2] for c in components}
    missing = required - session['capabilities'].keys()
    if missing:
        raise ValueError('Stalwart does not advertise: ' + ', '.join(sorted(missing)))
    # Verify management access before touching the source.
    load_importer().get_domains()
    return session


def dav_collections(url, user, password, component):
    body = (b'<d:propfind xmlns:d="DAV:"><d:prop><d:resourcetype/>'
            b'<d:owner/><d:current-user-privilege-set/></d:prop></d:propfind>')
    request = urllib.request.Request(url, data=body, method='PROPFIND', headers={
        'Authorization': auth_header(user, password), 'Depth': '1', 'Content-Type': 'application/xml'})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            if response.status != 207:
                raise ValueError(f'DAV discovery returned HTTP {response.status}')
            document = ET.fromstring(response.read())
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return []  # Existing Nextcloud user has no home for this service.
        raise
    collection_type = '{urn:ietf:params:xml:ns:caldav}calendar' if component == 'caldav' else '{urn:ietf:params:xml:ns:carddav}addressbook'
    collections = []
    for response in document.findall('{DAV:}response'):
        properties = ET.Element('properties')
        for propstat in response.findall('{DAV:}propstat'):
            if ' 200 ' in propstat.findtext('{DAV:}status', ''):
                for prop in propstat.findall('{DAV:}prop'):
                    properties.extend(list(prop))
        if properties.find('.//' + collection_type) is None:
            continue
        owner = urllib.parse.unquote(properties.findtext('{DAV:}owner/{DAV:}href', '')).rstrip('/')
        writable = any(properties.find('.//{DAV:}current-user-privilege-set//{DAV:}' + p) is not None
                       for p in ('all', 'write', 'write-content'))
        href = response.findtext('{DAV:}href', '')
        collection_url = urllib.parse.urljoin(url, href)
        if not owner.endswith('/principals/users/' + user) or not writable:
            print(f'{user}: skip {component} collection {href} (not owned/writable)', flush=True)
            continue
        # Never let source DAV metadata send temporary credentials elsewhere.
        if urllib.parse.urlparse(collection_url).netloc != urllib.parse.urlparse(url).netloc:
            raise ValueError('DAV collection points outside the source tunnel')
        collections.append(collection_url)
    return collections


def vandelay(*args, password):
    checked(['vandelay', *args], env={**os.environ, 'VANDELAY_PASSWORD': password})


def start_tunnel(source, components, log):
    forwards = sorted({(COMPONENTS[c][3], COMPONENTS[c][4]) for c in components})
    # Reserve stable ports so re-imports have the same Vandelay source URL.
    for port, _ in forwards:
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', port))
    try:
        for port, remote_port in forwards:
            forward = f'127.0.0.1:{port}:127.0.0.1:{remote_port}'
            checked(source.ssh + ['-O', 'forward', '-L', forward, source.host],
                    stdout=subprocess.DEVNULL, stderr=log)
            source.forwards.append(forward)
        for _ in range(100):
            try:
                for port, _ in forwards:
                    with socket.create_connection(('127.0.0.1', port), timeout=0.1):
                        pass
                return source
            except OSError:
                time.sleep(0.1)
        raise RuntimeError('SSH tunnel did not become ready')
    except BaseException:
        source.terminate()
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, help='SSH user@host for S5 Mail')
    parser.add_argument('--identity', type=Path, help='SSH private key on this machine')
    parser.add_argument('--components', default='all', help='Comma-separated accounts,mail,sieve,carddav,caldav (default: all)')
    parser.add_argument('--user', action='append', help='Only this email; repeat to select multiple users')
    parser.add_argument('--work-dir', type=Path, default=Path.home() / 's5mail-migration')
    parser.add_argument('--stalwart-url', default=os.environ.get('STALWART_URL', 'http://127.0.0.1:8080'))
    parser.add_argument('--stalwart-user', default=os.environ.get('STALWART_USER'))
    parser.add_argument('--occ', default='/usr/local/lib/owncloud/occ', help='Nextcloud occ path on source')
    parser.add_argument('--resume-source', action='store_true', help='Rehearsal: restore initial source service state after cleanup')
    parser.add_argument('--cleanup-source', action='store_true', help='Recover an interrupted run; no imports')
    args = parser.parse_args()
    if args.source.startswith('-') or not re.fullmatch(r'[A-Za-z0-9_.@:-]+', args.source):
        raise ValueError('Invalid SSH source')
    os.umask(0o077)
    # Installers put these tools here, often outside noninteractive SSH PATH.
    os.environ['PATH'] += os.pathsep + str(Path.home() / '.cargo/bin')
    os.environ.pop('STALWART_TOKEN', None)  # This workflow uses Basic auth.
    args.work_dir = args.work_dir.expanduser().resolve()
    args.work_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    if args.work_dir.stat().st_mode & 0o077:
        raise ValueError('Work directory must be owner-only (chmod 700)')
    with (Path('/tmp') / f'stalwart-migration-{os.getuid()}.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.cleanup_source:
            # A crashed run may still map the SSH hostname to loopback.
            # Remove that override before establishing the recovery connection.
            hosts('remove')
            source = Source(args)
            source.call('cleanup', resume=args.resume_source)
            print('Source credentials, firewall rules and local hostname override cleaned up.')
            return
        source = Source(args)
        for tool in ('ssh', 'sudo', 'vandelay', 'stalwart-cli'):
            if not shutil.which(tool):
                raise ValueError(f'Required command not found: {tool}')
        if not args.stalwart_user:
            parser.error('--stalwart-user is required')
        selected = set(COMPONENTS) | {'accounts'} if args.components == 'all' else set(args.components.split(','))
        if not selected or selected - (set(COMPONENTS) | {'accounts'}):
            parser.error('Unknown component; choose accounts,mail,sieve,carddav,caldav or all')
        components = [c for c in COMPONENTS if c in selected]
        os.environ.update(STALWART_URL=args.stalwart_url, STALWART_USER=args.stalwart_user)
        if not os.environ.get('STALWART_PASSWORD'):
            os.environ['STALWART_PASSWORD'] = getpass.getpass('Stalwart admin password: ')
        session = preflight_target(args, components)
        checked(['sudo', '-n', 'true'])
        dav = bool(selected & {'carddav', 'caldav'})
        print('Reading source user database and Nextcloud users...', flush=True)
        info = source.call('inspect', dav=dav, occ=args.occ)
        hostname = info['hostname']
        if not re.fullmatch(r'[A-Za-z0-9.-]+', hostname):
            raise ValueError('Invalid source hostname')
        target_hosts = {urllib.parse.urlparse(session.get(k, '')).hostname
                        for k in ('apiUrl', 'uploadUrl', 'downloadUrl')}
        target_hosts.add(urllib.parse.urlparse(args.stalwart_url).hostname)
        if hostname in target_hosts:
            raise ValueError('Give the source a distinct legacy hostname before migrating')
        identity = {'source': args.source, 'hostname': hostname, 'ports': [29993, 24190, 24443]}
        manifest = args.work_dir / 'source.json'
        if manifest.exists() and json.loads(manifest.read_text()) != identity:
            raise ValueError('Work directory belongs to another source. Use a separate directory.')
        manifest.write_text(json.dumps(identity, indent=2) + '\n')
        db = args.work_dir / 'users.sqlite'
        db.write_bytes(base64.b64decode(info['database'], validate=True))
        with sqlite3.connect(db.as_uri() + '?mode=ro', uri=True) as conn:
            users = conn.execute('SELECT email,password FROM users ORDER BY email').fetchall()
        for email, _ in users:
            if not re.fullmatch(r'[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+', email):
                raise ValueError('Invalid email in source database')
        if args.user:
            wanted = {email.lower() for email in args.user}
            missing = wanted - {email.lower() for email, _ in users}
            if missing:
                raise ValueError('Users missing from source: ' + ', '.join(sorted(missing)))
            users = [(email, password) for email, password in users if email.lower() in wanted]
        if not users:
            raise ValueError('No users selected')
        ensure_accounts(users)
        if not components:
            return
        run_id = secrets.token_hex(8)
        prepared = False
        mapped = False
        tunnel = None
        try:
            hosts('add', hostname)
            mapped = True
            with (args.work_dir / 'tunnel.log').open('w') as log:
                tunnel = start_tunnel(source, components, log)
            print('Pausing source delivery and client access...', flush=True)
            # Mark cleanup responsibility before prepare: an SSH response could
            # be lost after the source has persisted its recovery state.
            prepared = True
            credentials = source.call('prepare', run_id=run_id, occ=args.occ, dav=dav,
                                      mail=bool(selected & {'mail', 'sieve'}), resume=args.resume_source)
            for email, _ in users:
                token = None
                try:
                    for component in components:
                        protocol, objects, _, port, _, scheme = COMPONENTS[component]
                        url = f'{scheme}://{hostname}:{port}'
                        if component in ('carddav', 'caldav'):
                            if email not in info['dav_users']:
                                print(f'{email}: skip {component} (no Nextcloud user)', flush=True)
                                continue
                            if token is None:
                                token = source.call('token', run_id=run_id, user=email)['password']
                            path = 'calendars/' if component == 'caldav' else 'addressbooks/users/'
                            url += '/remote.php/dav/' + path + urllib.parse.quote(email, safe='') + '/'
                            urls = dav_collections(url, email, token, component)
                            if not urls:
                                print(f'{email}: skip {component} (no collections)', flush=True)
                                continue
                            login, password = email, token
                        else:
                            urls = [url]
                            login = email + '%' + credentials['master_user']
                            password = credentials['master_password']
                        directory = args.work_dir / component / email
                        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
                        for url in urls:
                            # Each DAV collection is a separate Vandelay source.
                            archive_name = hashlib.sha256(url.encode()).hexdigest()[:24] if component in ('carddav', 'caldav') else component
                            archive = str(directory / (archive_name + '.sqlite'))
                            print(f'{email}: importing {component} from {url}', flush=True)
                            vandelay('import', protocol, '--url', url, '--auth-basic', login, archive, password=password)
                            print(f'{email}: exporting {component}', flush=True)
                            vandelay('export', '--url', args.stalwart_url, '--auth-basic', args.stalwart_user,
                                     '--account-name', email, '--objects', objects, archive,
                                     password=os.environ['STALWART_PASSWORD'])
                finally:
                    if token is not None:
                        source.call('revoke', run_id=run_id, user=email)
        finally:
            try:
                if prepared:
                    print('Cleaning up source migration credentials...', flush=True)
                    source.call('cleanup', run_id=run_id, resume=args.resume_source)
            finally:
                try:
                    if tunnel is not None:
                        tunnel.terminate()
                finally:
                    if mapped:
                        hosts('remove')
        print('Migration complete. Archives: ' + str(args.work_dir), flush=True)
        print('Source services restored to their initial state.' if args.resume_source else
              'Source postfix, nginx and dovecot are stopped. Verify the destination before switching traffic.')


if __name__ == '__main__':
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    try:
        main()
    except KeyboardInterrupt:
        print('Interrupted. If cleanup did not finish, rerun with --cleanup-source.', file=sys.stderr)
        sys.exit(130)
    except Exception as exc:
        print(f'ERROR: {exc}\nIf source cleanup failed, rerun with --cleanup-source.', file=sys.stderr)
        sys.exit(1)
