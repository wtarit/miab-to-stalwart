import base64
import contextlib
import importlib.util
import io
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import migrate

spec = importlib.util.spec_from_file_location('agent', Path(__file__).resolve().parents[1] / 'source-agent.py')
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)


def collection(href, owner, writable=True):
    privilege = 'write-content' if writable else 'read'
    return f'''<d:response><d:href>{href}</d:href><d:propstat><d:prop>
      <d:resourcetype><d:collection/><c:addressbook/></d:resourcetype>
      <d:owner><d:href>/remote.php/dav/principals/users/{owner}/</d:href></d:owner>
      <d:current-user-privilege-set><d:privilege><d:{privilege}/></d:privilege></d:current-user-privilege-set>
      </d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>'''


class MigrationTests(unittest.TestCase):
    def test_recovery_removes_stale_hostname_override_before_ssh(self):
        with tempfile.TemporaryDirectory() as temporary:
            removed = Mock()
            source = Mock()
            def connect(_args):
                removed.assert_called_once_with('remove')
                return source
            with patch('sys.argv', ['migrate.py', '--source', 'admin@legacy.example',
                                   '--work-dir', temporary, '--cleanup-source']), \
                 patch('migrate.hosts', removed), patch('migrate.Source', side_effect=connect), \
                 patch.dict('os.environ'), contextlib.redirect_stdout(io.StringIO()):
                migrate.main()
            source.call.assert_called_once_with('cleanup', resume=False)

    def discover(self, entries):
        xml = ('<d:multistatus xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:carddav">'
               + entries + '</d:multistatus>').encode()
        response = io.BytesIO(xml)
        response.status = 207
        with patch('urllib.request.urlopen', return_value=response), contextlib.redirect_stdout(io.StringIO()):
            return migrate.dav_collections('https://legacy.example:24443/home/', 'user@example.com', 'secret', 'carddav')

    def test_dav_only_owned_writable_collections(self):
        entries = (collection('/own/', 'user%40example.com')
                   + collection('/generated/', 'user%40example.com', False)
                   + collection('/shared/', 'other%40example.com')
                   + collection('/system/', 'system'))
        self.assertEqual(self.discover(entries), ['https://legacy.example:24443/own/'])

    def test_dav_rejects_collection_outside_tunnel(self):
        with self.assertRaisesRegex(ValueError, 'outside the source tunnel'):
            self.discover(collection('https://other.example/steal/', 'user%40example.com'))

    def test_existing_account_credentials_are_never_overwritten(self):
        importer = Mock()
        importer.get_domains.return_value = {'example.com': 'domain-id'}
        importer.get_existing_accounts.return_value = {'user@example.com'}
        with patch('migrate.load_importer', return_value=importer), contextlib.redirect_stdout(io.StringIO()):
            migrate.ensure_accounts([('user@example.com', 'unsupported-old-hash')])
        importer.normalize_password_hash.assert_not_called()
        importer.create_user.assert_not_called()
        importer.invalidate_caches.assert_not_called()

    def test_sqlite_snapshot_includes_committed_wal_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'mail').mkdir()
            with sqlite3.connect(root / 'mail/users.sqlite') as writer:
                writer.execute('PRAGMA journal_mode=WAL')
                writer.execute('CREATE TABLE users (email TEXT,password TEXT)')
                writer.execute("INSERT INTO users VALUES ('user@example.com','hash')")
                writer.commit()
                with patch.object(agent, 'ROOT', root), patch.object(agent, 'settings', return_value={
                    'STORAGE_ROOT': str(root), 'PRIMARY_HOSTNAME': 'legacy.example'
                }), patch.object(agent, 'run', return_value='2.4.1'):
                    result = agent.inspect({'dav': False})
                (root / 'snapshot.sqlite').write_bytes(base64.b64decode(result['database']))
                with sqlite3.connect(root / 'snapshot.sqlite') as snapshot:
                    self.assertEqual(snapshot.execute('SELECT email FROM users').fetchall(), [('user@example.com',)])

    def test_failed_cleanup_retains_firewall_and_recovery_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / 'state.json'
            conf = root / 'dovecot.conf'
            original = '!include /etc/dovecot/existing-master.conf\npassdb sql {\n}\n'
            conf.write_text(agent.INCLUDE + '\n' + original)
            state.write_text(json.dumps({'run_id': 'test', 'tag': 'test-rule', 'occ': '/occ',
                'mail': True, 'token_users': ['user@example.com'], 'services': {'dovecot': True}}))
            with patch.object(agent, 'ROOT', root), patch.object(agent, 'STATE', state), patch.object(agent, 'CONF', conf), \
                 patch.object(agent, 'run'), patch.object(agent.subprocess, 'run', return_value=SimpleNamespace(returncode=0)) as firewall:
                with patch.object(agent, 'revoke', side_effect=RuntimeError('token backend unavailable')):
                    with self.assertRaisesRegex(RuntimeError, 'Cleanup incomplete'):
                        agent.cleanup({'run_id': 'test', 'resume': True})
                self.assertTrue(state.exists())
                self.assertEqual(conf.read_text(), original)
                firewall.assert_not_called()  # Public access remains blocked.
                with patch.object(agent, 'revoke'):
                    agent.cleanup({'run_id': 'test', 'resume': True})
                self.assertFalse(state.exists())
                self.assertEqual(conf.read_text(), original)


if __name__ == '__main__':
    unittest.main()
