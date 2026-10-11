#!/usr/bin/env python3
"""Root-side S5 Mail operations, invoked over SSH by migrate.py.

Requests and responses are JSON on stdin/stdout. Never log credentials.
Persistent state allows cleanup after an interrupted SSH session.
"""

import base64
import fcntl
import grp
import json
import os
import re
import secrets
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path('/var/lib/stalwart-migration')
STATE = ROOT / 'state.json'
CONF = Path('/etc/dovecot/dovecot.conf')
INCLUDE = '!include /var/lib/stalwart-migration/master.conf'
MASTER = 'stalwartmigration'
PORTS = '25,465,587,80,443,110,143,993,995,4190'


def run(*args, input=None):
    p = subprocess.run(args, input=input, text=True, capture_output=True)
    if p.returncode:
        # Output from credential creation may contain a secret, even on failure.
        raise RuntimeError(f'{args[0]} {args[1]} failed (exit {p.returncode})')
    return p.stdout


def occ(path, *args):
    return run('sudo', '-n', '-u', 'www-data', 'php', path, *args)


def save(state):
    temporary = STATE.with_suffix('.tmp')
    temporary.write_text(json.dumps(state))
    temporary.replace(STATE)


def settings():
    text = Path('/etc/s5mail.conf').read_text()
    values = {}
    for key in ('STORAGE_ROOT', 'PRIMARY_HOSTNAME'):
        match = re.search(rf'^{key}=(.+)$', text, re.M)
        if not match:
            raise ValueError(f'Missing {key} in /etc/s5mail.conf')
        values[key] = match[1].strip().strip('\"\'')
    return values


def inspect(request):
    config = settings()
    if not run('/usr/sbin/dovecot', '--version').startswith('2.4.'):
        raise ValueError('This script requires Dovecot 2.4.x')
    # Backup through SQLite, rather than copying a live SQLite/WAL file.
    with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
        snapshot = Path(temporary) / 'users.sqlite'
        with sqlite3.connect(Path(config['STORAGE_ROOT'], 'mail/users.sqlite').as_uri() + '?mode=ro', uri=True) as source:
            with sqlite3.connect(snapshot) as target:
                source.backup(target)
        database = base64.b64encode(snapshot.read_bytes()).decode()
    dav_users = []
    if request['dav']:
        while True:
            page = json.loads(occ(request['occ'], 'user:list', '--output=json',
                                  '--limit=500', '--offset=' + str(len(dav_users))))
            dav_users.extend(page)
            if len(page) < 500:
                break
    return {'hostname': config['PRIMARY_HOSTNAME'], 'database': database, 'dav_users': dav_users}


def firewall_args(state, action):
    return [action, 'INPUT', *(['1'] if action == '-I' else []),
            '!', '-i', 'lo', '-p', 'tcp', '-m', 'multiport', '--dports', PORTS,
            '-m', 'comment', '--comment', state['tag'], '-j', 'REJECT']


def revoke(state, user):
    tokens = json.loads(occ(state['occ'], 'user:auth-tokens:list', user, '--output=json'))
    for token in tokens:
        if token['name'] == state['tag']:
            occ(state['occ'], 'user:auth-tokens:delete', user, str(token['id']), '--no-interaction')


def cleanup(request):
    if not STATE.exists():
        return {'cleaned': True}
    state = json.loads(STATE.read_text())
    if request.get('run_id') and request['run_id'] != state['run_id']:
        raise RuntimeError('Another migration owns the source state')
    errors = []
    def attempt(fn):
        try:
            fn()
        except Exception as exc:
            errors.append(str(exc))
    for user in state['token_users']:
        attempt(lambda user=user: revoke(state, user))
    if state['mail']:
        def remove_master():
            text = CONF.read_text()
            CONF.write_text(''.join(line for line in text.splitlines(keepends=True) if line.rstrip() != INCLUDE))
            for name in ('master.conf', 'master-users'):
                (ROOT / name).unlink(missing_ok=True)
            run('/usr/bin/doveconf', '-n')
        attempt(remove_master)
    # Keep clients away until services have been stopped or restored.
    for service, active in state['services'].items():
        action = 'restart' if request.get('resume') and active else 'stop'
        attempt(lambda service=service, action=action: run('systemctl', action, service))
    # If configuration/services/token cleanup failed, retain the firewall and
    # recovery state. --cleanup-source can safely retry the remaining work.
    if not errors:
        for command in ('/usr/sbin/iptables', '/usr/sbin/ip6tables'):
            if subprocess.run([command, *firewall_args(state, '-C')], capture_output=True).returncode == 0:
                attempt(lambda command=command: run(command, *firewall_args(state, '-D')))
    if errors:
        raise RuntimeError('Cleanup incomplete: ' + '; '.join(errors))
    STATE.unlink()
    return {'cleaned': True}


def prepare(request):
    if STATE.exists():
        raise RuntimeError('Source has unfinished migration state. Run --cleanup-source first.')
    if INCLUDE in CONF.read_text() or (ROOT / 'master.conf').exists():
        raise RuntimeError('Unexpected migration master config already exists')
    run('/usr/bin/doveconf', '-n')
    state = {'run_id': request['run_id'], 'tag': 'stalwart-migration-' + request['run_id'],
             'occ': request['occ'], 'mail': request['mail'], 'token_users': [],
             'services': {s: subprocess.run(['systemctl', 'is-active', '--quiet', s]).returncode == 0
                          for s in ('postfix', 'nginx', 'dovecot')}}
    save(state)  # Record recovery information before the first mutation.
    try:
        for command in ('/usr/sbin/iptables', '/usr/sbin/ip6tables'):
            run(command, *firewall_args(state, '-I'))
        run('systemctl', 'stop', 'postfix', 'nginx')
        if request['mail']:
            text = CONF.read_text()
            if not re.search(r'^passdb sql\s*\{', text, re.M):
                raise ValueError('Expected S5 Mail SQL passdb was not found')
            password = secrets.token_urlsafe(36)
            hashed = run('openssl', 'passwd', '-6', '-stdin', input=password + '\n').strip()
            (ROOT / 'master-users').write_text(f'{MASTER}:{{SHA512-CRYPT}}{hashed}\n')
            group = grp.getgrnam('dovecot').gr_gid
            os.chown(ROOT, 0, group)
            ROOT.chmod(0o710)
            os.chown(ROOT / 'master-users', 0, group)
            (ROOT / 'master-users').chmod(0o640)
            (ROOT / 'master.conf').write_text('auth_master_user_separator = %\n'
                'passdb stalwart-migration {\n  driver = passwd-file\n'
                '  passwd_file_path = /var/lib/stalwart-migration/master-users\n'
                '  auth_username_format = %{user}\n  master = yes\n'
                '  result_success = continue\n}\n')
            CONF.write_text(re.sub(r'(?m)^(passdb sql\s*\{)', INCLUDE + '\n' + r'\1', text, count=1))
            run('/usr/bin/doveconf', '-n')
            run('systemctl', 'restart', 'dovecot')
        else:
            password = None
            run('systemctl', 'stop', 'dovecot')
        if request['dav']:
            run('/usr/sbin/nginx', '-t')
            run('systemctl', 'start', 'nginx')
        return {'master_user': MASTER, 'master_password': password}
    except Exception:
        cleanup({'resume': request['resume'], 'run_id': request['run_id']})
        raise


def token(request):
    state = json.loads(STATE.read_text())
    if request['run_id'] != state['run_id']:
        raise RuntimeError('Another migration owns the source state')
    user = request['user']
    if user not in state['token_users']:
        state['token_users'].append(user)
        save(state)
    # Record the unique token name before creation so recovery can revoke it
    # even if the SSH response is lost before the client receives the secret.
    output = occ(state['occ'], 'user:auth-tokens:add', user,
                 '--name=' + state['tag'], '--no-interaction')
    match = re.search(r'app password:\s*\n\s*(\S+)', output, re.I)
    if not match:
        raise RuntimeError('Could not parse Nextcloud app password')
    return {'password': match[1]}


def main():
    if os.geteuid() != 0:
        raise ValueError('Run source-agent.py through sudo')
    os.umask(0o077)
    ROOT.mkdir(mode=0o700, exist_ok=True)
    request = json.load(sys.stdin)
    with (ROOT / 'lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        operation = request['operation']
        if operation == 'revoke':
            state = json.loads(STATE.read_text())
            if request['run_id'] != state['run_id']:
                raise RuntimeError('Another migration owns the source state')
            revoke(state, request['user'])
            result = {}
        else:
            result = {'inspect': inspect, 'prepare': prepare, 'token': token, 'cleanup': cleanup}[operation](request)
        print(json.dumps(result))


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(json.dumps({'error': str(exc)}))
        sys.exit(1)
