import base64
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import shutil
import tempfile
import types
import unittest
from contextlib import ExitStack, redirect_stdout, nullcontext
from unittest.mock import patch
import urllib.parse

import yaml

import VH2 as app


KEY1 = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip('=')
KEY2 = base64.urlsafe_b64encode(bytes(range(31, -1, -1))).decode().rstrip('=')


def hy_meta(**kwargs):
    value = {'host': '2001:db8::1', 'port': 443, 'password': '#a /?@&!*: 密码',
             'sni': 'hy2.my-domain25.com', 'insecure': False,
             'certificate': {'sni': 'hy2.my-domain25.com', 'insecure': False}}
    value.update(kwargs)
    return value


def vless_meta():
    return {'host': '192.0.2.1', 'port': 443, 'uuid': '2c3fc3da-b4f3-47d0-acab-1f1dc5815f8b',
            'sni': 'www.microsoft.com', 'public_key': KEY2, 'short_id': 'abcdef0123456789'}


def hy_config(password='before'):
    return {'listen': ':443', 'auth': {'type': 'password', 'password': password},
            'masquerade': {'type': 'proxy', 'proxy': {'url': 'https://www.bing.com', 'rewriteHost': True}},
            'tls': {'cert': '/placeholder/cert', 'key': '/placeholder/key'}}


class HomeExportTests(unittest.TestCase):
    def test_export_copies_to_account_home_with_user_ownership(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            home = root / 'custom-home'
            home.mkdir()
            exports = root / 'exports'
            user = types.SimpleNamespace(pw_dir=str(home), pw_uid=1234, pw_gid=5678)
            from unittest.mock import Mock
            pwd = types.SimpleNamespace(getpwnam=Mock(return_value=user))
            configs = {'clash.yaml': 'secret: 中文\n', 'links.txt': 'hysteria2://test\n'}
            with patch.dict('sys.modules', {'pwd': pwd}), \
                    patch.dict(os.environ, {'SUDO_USER': 'installer', 'HOME': str(root)}), \
                    patch.object(app, 'EXPORT_DIR', exports), \
                    patch.object(app, 'client_configs', return_value=configs), \
                    patch.object(app.os, 'chown', create=True) as chown:
                app.export_clients({})
            pwd.getpwnam.assert_called_once_with('installer')
            self.assertEqual(chown.call_count, len(configs))
            for call in chown.call_args_list:
                self.assertEqual(call.args[1:], (1234, 5678))
            for name, content in configs.items():
                self.assertEqual((home / name).read_bytes(), content.encode('utf-8'))
                self.assertEqual((exports / name).read_bytes(), content.encode('utf-8'))
                if os.name != 'nt':
                    self.assertEqual((home / name).stat().st_mode & 0o777, 0o600)

    def test_missing_or_root_sudo_user_skips_copy(self):
        for username in ('', 'root'):
            with patch.dict(os.environ, {'SUDO_USER': username}), \
                    patch.object(app, 'atomic_write') as write:
                app.copy_exports_to_sudo_home({'clash.yaml': 'secret'})
                write.assert_not_called()

    def test_unknown_user_warns_without_failing_export(self):
        from unittest.mock import Mock
        pwd = types.SimpleNamespace(getpwnam=Mock(side_effect=KeyError('missing')))
        with patch.dict('sys.modules', {'pwd': pwd}), \
                patch.dict(os.environ, {'SUDO_USER': 'missing'}), \
                patch.object(app, 'warn') as warn:
            app.copy_exports_to_sudo_home({'clash.yaml': 'secret'})
            warn.assert_called_once()


class PureTests(unittest.TestCase):
    def test_passwords_roundtrip_yaml(self):
        for password in ('#abcd', '*abcd', '!abcd', '&abcd', 'a: b', 'a # b', 'true', '123',
                         'a/b?@&=\nline2', '中文 🔑'):
            with self.subTest(password=password):
                config = hy_config(password)
                self.assertEqual(yaml.safe_load(app.config_text('hy2', config)), config)

    def test_domain_accepts_digits_hyphens(self):
        for value in ('hy2.xiexie25.com', 'hy2.my-domain.com', 'EXAMPLE.COM.'):
            self.assertEqual(app.valid_domain(value), value.lower().rstrip('.'))

    def test_domain_rejects_shell_paths_and_bad_labels(self):
        for value in ('a;id.com', '$(id).com', '../example.com', '-x.example.com',
                      'a..com', 'a_' + '.com', 'a' * 64 + '.com'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                app.valid_domain(value)

    def test_url_rejects_nonweb_and_credentials(self):
        for value in ('file:///etc/passwd', 'https://user:pass@example.com', 'https://example.com:70000',
                      'https://example.com/\nheader'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                app.valid_url(value)

    def test_url_accepts_ipv6(self):
        self.assertEqual(app.valid_url('https://[2001:db8::1]:443/a'), 'https://[2001:db8::1]:443/a')

    def test_link_roundtrip_ipv6_password_and_obfs(self):
        meta = hy_meta(obfs='q/?&= #密码', hopping=[20000, 20100])
        link = app.build_link('hy2', meta)
        parsed = urllib.parse.urlsplit(link)
        self.assertEqual(parsed.hostname, meta['host'])
        self.assertEqual(parsed.port, 443)
        self.assertEqual(urllib.parse.unquote(parsed.username), meta['password'])
        self.assertEqual(urllib.parse.parse_qs(parsed.query)['obfs-password'], [meta['obfs']])
        self.assertEqual(urllib.parse.parse_qs(parsed.query)['mport'], ['20000-20100'])
        self.assertTrue(link.startswith('hysteria2://'))

    def test_export_roundtrip_and_no_dns_credentials(self):
        meta = hy_meta(obfs='foo', hopping=[20000, 20100])
        state = {'hy2': meta, 'vless': vless_meta()}
        state['hy2']['certificate']['source'] = {'cert': '/secret/path', 'key': '/secret/key'}
        exports = app.client_configs(state)
        clash = json.loads(exports['mihomo.json'])
        sb = json.loads(exports['sing-box.json'])
        self.assertEqual(clash['proxies'][1]['password'], meta['password'])
        self.assertEqual(clash['proxies'][1]['ports'], '20000-20100')
        self.assertEqual(sb['outbounds'][2]['server_ports'], ['20000:20100'])
        self.assertNotIn('/secret/', ''.join(exports.values()))
        self.assertEqual(len(exports['links.txt'].splitlines()), 2)

    def test_empty_exports_valid(self):
        exports = app.client_configs({})
        self.assertEqual(json.loads(exports['sing-box.json'])['outbounds'][0]['outbounds'], ['direct'])

    def test_old_export_names_match_native_formats(self):
        meta = hy_meta(password='test-pass', obfs='obfs-pass', hopping=[20000, 20100])
        exports = app.client_configs({'hy2': meta, 'vless': vless_meta()})
        self.assertEqual(yaml.safe_load(exports['clash.yaml']), json.loads(exports['mihomo.json']))
        self.assertEqual(exports['sing-box.yaml'], exports['sing-box.json'])
        self.assertEqual(exports['surge.yaml'], exports['surge.conf'])
        self.assertIn('port-hopping=20000-20100', exports['surge.conf'])
        self.assertIn('salamander-password="obfs-pass"', exports['surge.conf'])
        self.assertNotIn(KEY2, exports['surge.conf'])
        self.assertEqual(exports['hy2_url_scheme.txt'].strip(), app.build_link('hy2', meta))

    def test_surge_unsupported_credentials_do_not_inject_or_bypass_proxy(self):
        for password in ('pass\n[Rule]\nFINAL,DIRECT', 'a"b', 'a\\b'):
            result = app.surge_config({'hy2': hy_meta(password=password)})
            self.assertNotIn('password=', result)
            self.assertIn('PROXY = select, REJECT', result)
            self.assertEqual(result.count('[Rule]'), 1)
        self.assertIn('PROXY = select, REJECT', app.surge_config({'vless': vless_meta()}))

    def test_hy2_precheck_never_switches_user_or_binds_port(self):
        with patch.object(app, 'validate_certificate') as cert, patch.object(app, 'run') as command:
            app.validate_config('hy2', hy_config(), Path('/candidate'))
        cert.assert_called_once()
        command.assert_not_called()

    def test_key_output_compatibility(self):
        for label in ('Public key', 'PublicKey', 'Password', 'Password (PublicKey)'):
            self.assertEqual(app.parse_key_pair('PrivateKey: ' + KEY1 + '\n' + label + ': ' + KEY2), (KEY1, KEY2))

    def test_empty_keys_rejected(self):
        with self.assertRaises(app.DeployError):
            app.parse_key_pair('PrivateKey: \nPassword: ')

    def test_shell_string_rejected(self):
        with self.assertRaises(TypeError):
            app.run('echo unsafe')

    def test_run_failure_does_not_leak_arguments(self):
        with patch.object(app.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', 'secret')):
            with self.assertRaises(app.DeployError) as caught:
                app.run(['command', 'SUPER_SECRET'])
        self.assertNotIn('SUPER_SECRET', str(caught.exception))
        self.assertNotIn('secret', str(caught.exception))

    def test_nft_scoped_to_local_udp(self):
        rules = app.nft_rules([20000, 20100], 443)
        self.assertIn('table inet vh2_hopping', rules)
        self.assertIn('fib daddr type local udp dport 20000-20100', rules)
        self.assertNotIn('flush ruleset', rules)

    def test_bad_hopping_ranges_rejected(self):
        for ports in ([20100, 20000], [0, 100], [400, 500], [1, 70000]):
            with self.subTest(ports=ports), self.assertRaises(ValueError):
                app.nft_rules(ports, 443)

    def test_exact_port_filter(self):
        with patch.object(app, 'run', return_value=subprocess.CompletedProcess([], 0, '', '')) as command:
            app.port_lines(443, 'tcp')
            self.assertEqual(command.call_args.args[0], ['ss', '-Hlnpt', 'sport = :443'])

    def test_own_listener_allowed_other_listener_rejected(self):
        with patch.object(app, 'service_property', return_value='123'):
            with patch.object(app, 'port_lines', return_value=['users:(("xray",pid=123,fd=3))']):
                self.assertTrue(app.port_available(443, 'tcp', app.XRAY_SVC))
            with patch.object(app, 'port_lines', return_value=['users:(("nginx",pid=1234,fd=3))']):
                self.assertFalse(app.port_available(443, 'tcp', app.XRAY_SVC))

    def test_hopping_range_checks_one_socket_listing(self):
        output = 'UNCONN 0 0 [::]:20050 [::]:*\n'
        with patch.object(app, 'run', return_value=subprocess.CompletedProcess([], 0, output, '')) as command:
            with self.assertRaises(app.DeployError):
                app.hopping_range_available([20000, 20100])
            command.assert_called_once()


class FilesystemTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        paths = {'DATA_DIR': 'data', 'STATE_FILE': 'data/state.json', 'BACKUP_DIR': 'data/backups',
                 'EXPORT_DIR': 'exports', 'HY2_CFG': 'hy2/config.yaml', 'HY2_LINK': 'hy2/link.txt',
                 'HY2_BIN': 'bin/hysteria', 'XRAY_BIN': 'bin/xray', 'XRAY_CFG': 'xray/config.json',
                 'VLESS_LINK': 'vless.txt', 'NFT_FILE': 'nft/rules.nft', 'NFT_UNIT': 'unit/hopping.service',
                 'CERT_DIR': 'hy2/certs', 'HELPER': 'lib/helper.py', 'RENEW_HOOK': 'hooks/deploy',
                 'BBR_FILE': 'sysctl/bbr.conf', 'SYSTEMD_DIR': 'systemd',
                 'PERF_FILE': 'sysctl/performance.conf', 'PROC_DIR': 'proc', 'CGROUP_DIR': 'cgroup'}
        for name, path in paths.items():
            self.stack.enter_context(patch.object(app, name, self.root / path))
        services = {'hy2': (app.HY2_BIN, app.HY2_CFG, app.HY2_SVC, app.HY2_LINK, 'udp'),
                    'vless': (app.XRAY_BIN, app.XRAY_CFG, app.XRAY_SVC, app.VLESS_LINK, 'tcp')}
        self.stack.enter_context(patch.object(app, 'SERVICES', services))
        if hasattr(os, 'chown'):
            self.stack.enter_context(patch.object(app.os, 'chown'))
        self.stack.enter_context(redirect_stdout(io.StringIO()))

    def setup_apply(self):
        app.atomic_write(app.HY2_CFG, app.config_text('hy2', hy_config()))
        app.atomic_write(app.HY2_LINK, 'old link\n')
        app.atomic_write(app.STATE_FILE, app.json_text({'hy2': hy_meta(password='before')}))
        app.export_clients()
        self.stack.enter_context(patch.object(app, 'svc_active', return_value=True))
        self.stack.enter_context(patch.object(app, 'svc_enabled', return_value=False))
        self.stack.enter_context(patch.object(app, 'service_identity', return_value=('hysteria', 10, 10)))
        self.stack.enter_context(patch.object(app, 'service_property', return_value=str(app.HY2_CFG)))
        self.run_mock = self.stack.enter_context(patch.object(app, 'run', return_value=subprocess.CompletedProcess([], 0, '', '')))
        self.validate = self.stack.enter_context(patch.object(app, 'validate_config'))
        self.sync = self.stack.enter_context(patch.object(app, 'sync_hopping'))
        self.health = self.stack.enter_context(patch.object(app, 'wait_healthy'))
        self.stack.enter_context(patch.object(app, 'manage_renew_hook'))
        self.stack.enter_context(patch.object(app, 'remove_legacy_cron'))
        self.print_mock = self.stack.enter_context(patch.object(app, 'print_link'))
        self.stack.enter_context(patch.object(app, 'prepare_performance', return_value={'previous': {}}))
        self.perf_write = self.stack.enter_context(patch.object(app, 'write_performance'))
        self.perf_restore = self.stack.enter_context(patch.object(app, 'restore_performance'))

    def test_snapshot_restores_existing_removes_new(self):
        old, new = self.root / 'old', self.root / 'new'
        app.atomic_write(old, 'old')
        snapshot = app.Snapshot([old, new], 'test')
        app.atomic_write(old, 'changed')
        app.atomic_write(new, 'new')
        snapshot.restore()
        self.assertEqual(old.read_text(), 'old')
        self.assertFalse(new.exists())
        self.assertTrue((snapshot.directory / 'manifest.json').exists())

    def test_load_old_yaml(self):
        app.atomic_write(app.HY2_CFG, 'listen: :443\nauth:\n  type: password\n  password: abc\n')
        self.assertEqual(app.read_config(app.HY2_CFG)['auth']['password'], 'abc')

    def test_snapshot_rejects_symlinks(self):
        target, link = self.root / 'target', self.root / 'link'
        target.write_text('original')
        try:
            link.symlink_to(target)
        except OSError:
            self.skipTest('Symlinks unavailable on host')
        with self.assertRaises(app.DeployError):
            app.Snapshot([link], 'test')
        with self.assertRaises(app.DeployError):
            app.atomic_write(link, 'changed')
        self.assertEqual(target.read_text(), 'original')

    def test_apply_success_commits_config_state_exports(self):
        self.setup_apply()
        app.apply_config('hy2', hy_config('after'), hy_meta(password='after'))
        self.assertEqual(app.read_config(app.HY2_CFG)['auth']['password'], 'after')
        self.assertEqual(app.load_state()['hy2']['password'], 'after')
        self.assertIn('after@', app.HY2_LINK.read_text())
        self.assertTrue(all(p.exists() for p in app.export_paths()))
        self.print_mock.assert_called_once()

    def test_prevalidation_failure_does_not_stop_service(self):
        self.setup_apply()
        self.validate.side_effect = app.DeployError('invalid')
        with self.assertRaises(app.DeployError):
            app.apply_config('hy2', hy_config('after'), hy_meta(password='after'))
        self.run_mock.assert_not_called()
        self.assertEqual(app.read_config(app.HY2_CFG)['auth']['password'], 'before')
        self.print_mock.assert_not_called()

    def test_runtime_failure_restores_config_state_links_exports(self):
        self.setup_apply()
        old_exports = {p.name: p.read_bytes() for p in app.export_paths()}
        self.health.side_effect = [app.DeployError('failed startup'), None]
        with self.assertRaises(app.DeployError):
            app.apply_config('hy2', hy_config('after'), hy_meta(password='after'))
        self.assertEqual(app.read_config(app.HY2_CFG)['auth']['password'], 'before')
        self.assertEqual(app.load_state()['hy2']['password'], 'before')
        self.assertEqual(app.HY2_LINK.read_text(), 'old link\n')
        self.assertEqual({p.name: p.read_bytes() for p in app.export_paths()}, old_exports)
        calls = [c.args[0] for c in self.run_mock.call_args_list]
        self.assertIn(['systemctl', 'disable', app.HY2_SVC], calls)
        self.print_mock.assert_not_called()

    def test_first_deploy_failure_leaves_no_success_state(self):
        self.setup_apply()
        app.HY2_CFG.unlink()
        app.HY2_LINK.unlink()
        app.STATE_FILE.unlink()
        self.health.side_effect = app.DeployError('failed startup')
        with self.assertRaises(app.DeployError):
            app.apply_config('hy2', hy_config('after'), hy_meta(password='after'))
        self.assertFalse(app.HY2_CFG.exists())
        self.assertFalse(app.HY2_LINK.exists())
        self.assertFalse(app.STATE_FILE.exists())
        self.print_mock.assert_not_called()

    def test_interrupt_restores_old_config(self):
        self.setup_apply()
        self.health.side_effect = [KeyboardInterrupt(), None]
        with self.assertRaises(KeyboardInterrupt):
            app.apply_config('hy2', hy_config('after'), hy_meta(password='after'))
        self.assertEqual(app.read_config(app.HY2_CFG)['auth']['password'], 'before')

    def test_rollback_failure_reports_backup_path(self):
        self.setup_apply()
        self.health.side_effect = [app.DeployError('failed startup'), app.DeployError('old service failed')]
        with self.assertRaises(app.DeployError) as caught:
            app.apply_config('hy2', hy_config('after'), hy_meta(password='after'))
        self.assertIn(str(app.BACKUP_DIR), str(caught.exception))

    def test_export_write_failure_rolls_back(self):
        self.setup_apply()
        with patch.object(app, 'export_clients', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                app.apply_config('hy2', hy_config('after'), hy_meta(password='after'))
        self.assertEqual(app.load_state()['hy2']['password'], 'before')
        self.assertEqual(app.read_config(app.HY2_CFG)['auth']['password'], 'before')

    def test_refresh_mode_does_not_print_secrets(self):
        self.setup_apply()
        app.apply_config('hy2', hy_config('after'), hy_meta(password='after'), show_link=False)
        self.print_mock.assert_not_called()

    def test_legacy_cron_removes_exact_line_only(self):
        original = app.OLD_CRON + '\n0 4 * * * certbot renew --deploy-hook other\n# certbot for site\n'
        def command(args, **kwargs):
            return subprocess.CompletedProcess(args, 0, original if args == ['crontab', '-l'] else '', '')
        with patch.object(app.shutil, 'which', return_value='/usr/bin/crontab'), patch.object(app, 'run', side_effect=command) as run:
            app.remove_legacy_cron()
        written = run.call_args.kwargs['input']
        self.assertNotIn(app.OLD_CRON, written)
        self.assertIn('certbot renew --deploy-hook other', written)
        self.assertIn('# certbot for site', written)

    def test_certificate_staging_does_not_touch_live_pair(self):
        cert, key = self.root / 'cert', self.root / 'key'
        cert.write_text('cert')
        key.write_text('key')
        with patch.object(app, 'validate_certificate'):
            material = app.stage_certificate(cert, key)
        self.assertEqual(material, {'cert': b'cert', 'key': b'key'})
        self.assertFalse(app.CERT_DIR.exists())

    def test_certificate_pair_commits_before_systemd_and_repairs_parent(self):
        self.setup_apply()
        chown = self.stack.enter_context(patch.object(app.os, 'chown', create=True))
        app.HY2_CFG.parent.chmod(0o700)
        cfg = hy_config('after')
        cfg['tls'] = app.certificate_paths()
        material = {'cert': b'new cert', 'key': b'new key'}
        def healthy(*args, **kwargs):
            self.assertEqual(Path(cfg['tls']['cert']).read_bytes(), material['cert'])
            self.assertEqual(Path(cfg['tls']['key']).read_bytes(), material['key'])
            if os.name != 'nt':
                for path, mode in ((app.HY2_CFG.parent, 0o750), (app.CERT_DIR, 0o750),
                                   (Path(cfg['tls']['cert']), 0o644), (Path(cfg['tls']['key']), 0o640)):
                    self.assertEqual(path.stat().st_mode & 0o777, mode)
        self.health.side_effect = healthy
        app.apply_config('hy2', cfg, hy_meta(password='after'), certificate=material)
        chown.assert_any_call(app.HY2_CFG.parent, 0, 10)
        chown.assert_any_call(app.CERT_DIR, 0, 10)
        calls = [c.args[0] for c in self.run_mock.call_args_list]
        self.assertIn(['systemctl', 'restart', app.HY2_SVC], calls)
        self.assertFalse(any(c[0] == 'runuser' or str(c[0]) == str(app.HY2_BIN) for c in calls))
        self.assertNotIn('new key', app.STATE_FILE.read_text())

    def test_failed_certificate_replacement_restores_pair_and_directory_modes(self):
        self.setup_apply()
        cfg = hy_config('after')
        cfg['tls'] = app.certificate_paths()
        app.atomic_write(Path(cfg['tls']['cert']), 'old cert')
        app.atomic_write(Path(cfg['tls']['key']), 'old key')
        app.HY2_CFG.parent.chmod(0o700)
        app.CERT_DIR.chmod(0o700)
        self.health.side_effect = [app.DeployError('startup failed'), None]
        with self.assertRaises(app.DeployError):
            app.apply_config('hy2', cfg, hy_meta(password='after'),
                             certificate={'cert': b'new cert', 'key': b'new key'})
        self.assertEqual(Path(cfg['tls']['cert']).read_text(), 'old cert')
        self.assertEqual(Path(cfg['tls']['key']).read_text(), 'old key')
        if os.name != 'nt':
            self.assertEqual(app.HY2_CFG.parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(app.CERT_DIR.stat().st_mode & 0o777, 0o700)

    def test_rejected_candidate_keeps_certificate_and_running_service(self):
        self.setup_apply()
        cfg = hy_config()
        cfg['tls'] = app.certificate_paths()
        app.atomic_write(Path(cfg['tls']['key']), 'old key')
        self.validate.side_effect = app.DeployError('bad cert')
        with self.assertRaises(app.DeployError):
            app.apply_config('hy2', cfg, hy_meta(), certificate={'cert': b'bad', 'key': b'bad'})
        self.assertEqual(Path(cfg['tls']['key']).read_text(), 'old key')
        self.run_mock.assert_not_called()

    def test_hy2_root_daemon_is_rejected(self):
        self.setup_apply()
        with patch.object(app, 'service_identity', return_value=('root', 0, 0)):
            with self.assertRaisesRegex(app.DeployError, 'User=hysteria'):
                app.apply_config('hy2', hy_config(), hy_meta())
        self.perf_write.assert_not_called()

    def test_consent_acceptance_is_persistent_and_old_marker_compatible(self):
        with patch.object(app, 'yes', return_value=True) as question:
            self.assertTrue(app.agree_treaty())
            self.assertTrue(app.agree_treaty())
        question.assert_called_once()
        (app.EXPORT_DIR / 'agree.txt').write_text('')
        with patch.object(app, 'yes', side_effect=AssertionError('must not ask again')):
            self.assertTrue(app.agree_treaty())

    def test_consent_refusal_precedes_dependency_installation(self):
        with patch.object(app.sys, 'argv', ['VH2.py']), patch.object(app, 'preflight') as preflight, \
             patch.object(app, 'yes', return_value=False), patch.object(app, 'run') as command:
            app.main()
        preflight.assert_called_once_with()
        command.assert_not_called()
        self.assertFalse(app.EXPORT_DIR.exists())

    def test_empty_export_does_not_overwrite_old_attachment_outputs(self):
        old = app.EXPORT_DIR / 'hy2_url_scheme.txt'
        app.atomic_write(old, 'existing link')
        with self.assertRaises(app.DeployError):
            app.export_all()
        self.assertEqual(old.read_text(), 'existing link')

    def test_compact_menu_routes_update_without_reconfiguring(self):
        with patch.object(app, 'prompt', side_effect=['2', '3', 'v26.2.6', 'v2.12.2']), \
             patch.object(app, 'process_lock', return_value=nullcontext()), \
             patch.object(app, 'install_core') as install, patch.object(app, 'configure_hy2') as configure:
            app.menu_action('1')
        self.assertEqual([c.args for c in install.call_args_list], [('vless', 'v26.2.6'), ('hy2', 'v2.12.2')])
        self.assertTrue(all(c.kwargs['upgrade'] for c in install.call_args_list))
        configure.assert_not_called()

    def test_compact_menu_export_uses_shared_entry_point(self):
        with patch.object(app, 'prompt', return_value='3'), \
             patch.object(app, 'process_lock', return_value=nullcontext()), patch.object(app, 'export_all') as export:
            app.menu_action('3')
        export.assert_called_once()

    def test_fresh_hy2_does_not_reuse_installer_sample_password(self):
        app.atomic_write(app.HY2_BIN, 'binary')
        app.atomic_write(app.HY2_CFG, app.config_text('hy2', hy_config('sample-password')))
        with patch.object(app, 'choose_port', return_value=443), patch.object(app, 'public_endpoint', return_value='192.0.2.1'), \
             patch.object(app, 'secret', return_value='generated') as password, \
             patch.object(app, 'prompt', return_value='https://www.bing.com'), \
             patch.object(app, 'yes', return_value=False), \
             patch.object(app, 'certificate_wizard', return_value=({'tls': {'cert': 'cert', 'key': 'key'}}, {'sni': 'example.com', 'insecure': True}, None)), \
             patch.object(app, 'apply_config') as apply:
            app.configure_hy2(fresh=True)
        self.assertIsNone(password.call_args.args[1])
        self.assertEqual(apply.call_args.args[1]['auth']['password'], 'generated')

    def test_hy2_reconfiguration_preserves_password_and_custom_fields(self):
        app.atomic_write(app.HY2_BIN, 'binary')
        cfg = hy_config('existing')
        cfg['resolver'] = {'type': 'udp', 'udp': {'addr': '1.1.1.1:53'}}
        app.atomic_write(app.HY2_CFG, app.config_text('hy2', cfg))
        with patch.object(app, 'choose_port', return_value=8443), patch.object(app, 'public_endpoint', return_value='192.0.2.1'), \
             patch.object(app, 'secret', side_effect=lambda label, old: old), \
             patch.object(app, 'prompt', return_value='https://www.bing.com'), \
             patch.object(app, 'yes', return_value=False), \
             patch.object(app, 'certificate_wizard', return_value=({'tls': cfg['tls']}, {'sni': 'example.com', 'insecure': True}, None)), \
             patch.object(app, 'apply_config') as apply:
            app.configure_hy2()
        result = apply.call_args.args[1]
        self.assertEqual(result['auth']['password'], 'existing')
        self.assertEqual(result['resolver'], cfg['resolver'])
        self.assertEqual(result['listen'], ':8443')

    def test_certificate_refresh_ignores_unrelated_lineage(self):
        meta = hy_meta(certificate={'source': {'cert': '/etc/letsencrypt/live/own/fullchain.pem', 'key': '/key'}})
        app.atomic_write(app.STATE_FILE, app.json_text({'hy2': meta}))
        with patch.dict(os.environ, {'RENEWED_LINEAGE': '/etc/letsencrypt/live/another'}), patch.object(app, 'stage_certificate') as copy_cert:
            app.refresh_certificate()
        copy_cert.assert_not_called()

    def test_vless_reconfiguration_preserves_identity(self):
        app.atomic_write(app.XRAY_BIN, 'binary')
        meta = vless_meta()
        inbound = {'listen': '0.0.0.0', 'port': 443, 'protocol': 'vless',
                   'settings': {'clients': [{'id': meta['uuid'], 'flow': 'xtls-rprx-vision'}], 'decryption': 'none'},
                   'streamSettings': {'network': 'tcp', 'security': 'reality',
                                      'realitySettings': {'privateKey': KEY1, 'shortIds': [meta['short_id']],
                                                         'dest': 'www.microsoft.com:443', 'serverNames': [meta['sni']]}}}
        cfg = {'inbounds': [inbound], 'outbounds': [{'protocol': 'freedom'}], 'dns': {'servers': ['1.1.1.1']}}
        app.atomic_write(app.XRAY_CFG, app.json_text(cfg))
        def answer(label, default=None, validator=lambda s:s):
            return validator(default)
        output = 'PrivateKey: ' + KEY1 + '\nPassword (PublicKey): ' + KEY2
        with patch.object(app, 'choose_port', return_value=8443), patch.object(app, 'public_endpoint', return_value='192.0.2.1'), \
             patch.object(app, 'yes', return_value=False), patch.object(app, 'prompt', side_effect=answer), \
             patch.object(app, 'run', return_value=subprocess.CompletedProcess([], 0, output, '')) as command, \
             patch.object(app, 'apply_config') as apply:
            app.configure_vless()
        command.assert_called_once_with([app.XRAY_BIN, 'x25519', '-i', KEY1])
        updated = apply.call_args.args[1]
        self.assertEqual(updated['inbounds'][0]['settings']['clients'], inbound['settings']['clients'])
        self.assertEqual(updated['inbounds'][0]['streamSettings']['realitySettings']['shortIds'], [meta['short_id']])
        self.assertEqual(updated['dns'], cfg['dns'])

    def test_upgrade_preserves_config_and_disabled_service(self):
        app.atomic_write(app.HY2_BIN, 'old binary')
        app.atomic_write(app.HY2_CFG, app.config_text('hy2', hy_config('old password')))
        original = app.HY2_CFG.read_bytes()
        def command(args, **kwargs):
            if args[0] == 'curl':
                Path(args[args.index('-o') + 1]).write_text('#!/bin/bash\n')
            if args[0] == 'bash':
                app.atomic_write(app.HY2_BIN, 'new binary')
                app.atomic_write(app.HY2_CFG, 'overwritten by installer')
            return subprocess.CompletedProcess(args, 0, 'version', '')
        with patch.object(app, 'svc_active', return_value=False), patch.object(app, 'svc_enabled', return_value=False), \
             patch.object(app, 'run', side_effect=command) as commands:
            app.install_core('hy2', '2.6.0', upgrade=True)
        self.assertEqual(app.HY2_BIN.read_text(), 'new binary')
        self.assertEqual(app.HY2_CFG.read_bytes(), original)
        self.assertIn(['systemctl', 'stop', app.HY2_SVC], [c.args[0] for c in commands.call_args_list])

    def test_failed_upgrade_restores_binary_and_config(self):
        app.atomic_write(app.HY2_BIN, 'old binary')
        app.atomic_write(app.HY2_CFG, app.config_text('hy2', hy_config('old password')))
        original = app.HY2_CFG.read_bytes()
        def command(args, **kwargs):
            if args[0] == 'curl':
                Path(args[args.index('-o') + 1]).write_text('#!/bin/bash\n')
            if args[0] == 'bash':
                app.atomic_write(app.HY2_BIN, 'new binary')
                app.atomic_write(app.HY2_CFG, 'bad config')
                raise app.DeployError('installer failed')
            return subprocess.CompletedProcess(args, 0, '', '')
        with patch.object(app, 'svc_active', return_value=False), patch.object(app, 'svc_enabled', return_value=False), \
             patch.object(app, 'run', side_effect=command):
            with self.assertRaises(app.DeployError):
                app.install_core('hy2', upgrade=True)
        self.assertEqual(app.HY2_BIN.read_text(), 'old binary')
        self.assertEqual(app.HY2_CFG.read_bytes(), original)

    def test_nft_disable_only_removes_own_table(self):
        app.atomic_write(app.NFT_UNIT, 'unit')
        app.atomic_write(app.NFT_FILE, 'rules')
        with patch.object(app.shutil, 'which', return_value='/usr/sbin/nft'), \
             patch.object(app, 'run', return_value=subprocess.CompletedProcess([], 0, '', '')) as command:
            app.sync_hopping(None)
        commands = [c.args[0] for c in command.call_args_list]
        self.assertIn(['nft', 'delete', 'table', 'inet', 'vh2_hopping'], commands)
        self.assertFalse(app.NFT_UNIT.exists())
        self.assertFalse(app.NFT_FILE.exists())
        self.assertNotIn('flush ruleset', repr(commands))

    def test_nft_boot_file_is_idempotent(self):
        with patch.object(app.shutil, 'which', return_value='/usr/sbin/nft'), \
             patch.object(app, 'run', return_value=subprocess.CompletedProcess([], 0, '', '')):
            app.sync_hopping(hy_meta(hopping=[20000, 20100]))
        self.assertTrue(app.NFT_FILE.read_text().startswith('add table inet vh2_hopping\ndelete table inet vh2_hopping\n'))
        self.assertIn('Before=hysteria-server.service', app.NFT_UNIT.read_text())

    def test_qr_receives_raw_link_on_stdin(self):
        meta = hy_meta()
        with patch.object(app.shutil, 'which', return_value='/usr/bin/qrencode'), \
             patch.object(app, 'run', return_value=subprocess.CompletedProcess([], 0, '', '')) as command:
            app.print_link('hy2', meta)
        self.assertEqual(command.call_args.kwargs['input'], app.build_link('hy2', meta))
        self.assertNotIn(meta['password'], repr(command.call_args.args))

    def test_uninstall_preserves_configuration_and_certificates(self):
        self.setup_apply()
        app.atomic_write(app.HY2_BIN, 'binary')
        certificate = app.CERT_DIR / 'old' / 'key.pem'
        app.atomic_write(certificate, 'private key')
        with patch.object(app, 'yes', return_value=True):
            app.uninstall('hy2')
        self.assertFalse(app.HY2_BIN.exists())
        self.assertTrue(app.HY2_CFG.exists())
        self.assertEqual(certificate.read_text(), 'private key')
        self.assertNotIn('hy2', app.load_state())

    def test_failed_uninstall_restores_binary_and_state(self):
        self.setup_apply()
        app.atomic_write(app.HY2_BIN, 'binary')
        with patch.object(app, 'yes', return_value=True), patch.object(app, 'export_clients', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                app.uninstall('hy2')
        self.assertEqual(app.HY2_BIN.read_text(), 'binary')
        self.assertIn('hy2', app.load_state())
        self.assertEqual(app.HY2_LINK.read_text(), 'old link\n')

    def test_custom_service_config_path_is_rejected_before_writing(self):
        self.setup_apply()
        with patch.object(app, 'service_property', return_value='other-config.yaml'):
            with self.assertRaises(app.DeployError):
                app.apply_config('hy2', hy_config('after'), hy_meta(password='after'))
        self.run_mock.assert_not_called()
        self.assertEqual(app.read_config(app.HY2_CFG)['auth']['password'], 'before')

    def test_real_openssl_certificate_pair_and_mismatch(self):
        openssl = shutil.which('openssl')
        if not openssl and Path('C:/Program Files/Git/usr/bin/openssl.exe').exists():
            openssl = 'C:/Program Files/Git/usr/bin/openssl.exe'
        if not openssl:
            self.skipTest('OpenSSL unavailable')
        conf = self.root / 'openssl.cnf'
        conf.write_text('[req]\ndistinguished_name=dn\n[dn]\n')
        real_run = app.run
        def command(args, **kwargs):
            return real_run([openssl] + list(args[1:]), **kwargs)
        with patch.object(app, 'run', side_effect=command):
            pairs = []
            for index in range(2):
                cert, key = self.root / ('cert' + str(index)), self.root / ('key' + str(index))
                app.run(['openssl', 'req', '-config', conf, '-x509', '-nodes', '-newkey', 'ec',
                         '-pkeyopt', 'ec_paramgen_curve:P-256', '-keyout', key, '-out', cert,
                         '-subj', '/CN=example.com', '-addext', 'subjectAltName=DNS:example.com', '-days', '1'])
                pairs.append((cert, key))
            app.validate_certificate(*pairs[0])
            with self.assertRaises(app.DeployError):
                app.validate_certificate(pairs[0][0], pairs[1][1])

    def test_resource_detection_respects_parent_cgroup_limit(self):
        app.atomic_write(app.PROC_DIR / 'meminfo', 'MemTotal: 1048576 kB\nMemAvailable: 700000 kB\n')
        app.atomic_write(app.PROC_DIR / 'self/cgroup', '0::/slice/manager\n')
        app.atomic_write(app.CGROUP_DIR / 'memory.max', 'max')
        app.atomic_write(app.CGROUP_DIR / 'slice/memory.max', str(256 * 1024**2))
        app.atomic_write(app.CGROUP_DIR / 'slice/manager/memory.max', 'max')
        self.assertEqual(app.host_resources()['memory_bytes'], 256 * 1024**2)

    def test_performance_profile_raises_ceiling_not_default_buffer(self):
        resources = {'memory_bytes': 1024 * 1024**2, 'visible_cpus': 2}
        original = {'net.core.rmem_max': '212992', 'net.core.wmem_max': str(32 * 1024**2),
                    'net.ipv4.tcp_congestion_control': 'cubic', 'net.core.default_qdisc': 'fq_codel'}
        def command(args, **kwargs):
            output = 'reno cubic bbr' if args[-1] == 'net.ipv4.tcp_available_congestion_control' else original[args[-1]]
            return subprocess.CompletedProcess(args, 0, output, '')
        with patch.object(app, 'host_resources', return_value=resources), patch.object(app, 'run', side_effect=command), \
             patch.object(app, 'service_property', return_value='0'):
            plan = app.prepare_performance('hy2')
        self.assertEqual(plan['settings']['net.core.rmem_max'], str(16 * 1024**2))
        self.assertEqual(plan['settings']['net.core.wmem_max'], str(32 * 1024**2))
        self.assertNotIn('net.core.rmem_default', plan['settings'])
        self.assertEqual(plan['settings']['net.ipv4.tcp_congestion_control'], 'bbr')
        self.assertNotIn('CPUQuota', plan['dropin'])

    def test_small_memory_profile_and_no_bbr_fallback(self):
        resources = {'memory_bytes': 256 * 1024**2, 'visible_cpus': 1}
        def command(args, **kwargs):
            return subprocess.CompletedProcess(args, 0, 'cubic' if 'congestion' in args[-1] else '212992', '')
        with patch.object(app, 'host_resources', return_value=resources), patch.object(app, 'run', side_effect=command), \
             patch.object(app.shutil, 'which', return_value=None), patch.object(app, 'service_property', return_value='-10'):
            plan = app.prepare_performance('hy2')
        self.assertEqual(plan['settings']['net.core.rmem_max'], str(8 * 1024**2))
        self.assertNotIn('net.ipv4.tcp_congestion_control', plan['settings'])
        self.assertEqual(plan['dropin'], '[Service]\nNice=-10\n')

    def test_performance_sysctl_failure_restores_previous_files_and_runtime(self):
        self.setup_apply()
        app.atomic_write(app.PERF_FILE, 'old performance config')
        def bad_write(kind, plan):
            app.atomic_write(app.PERF_FILE, 'partly changed')
            raise app.DeployError('sysctl refused')
        self.perf_write.side_effect = bad_write
        with self.assertRaises(app.DeployError):
            app.apply_config('hy2', hy_config('after'), hy_meta(password='after'))
        self.assertEqual(app.PERF_FILE.read_text(), 'old performance config')
        self.perf_restore.assert_called_once()
        self.assertEqual(app.read_config(app.HY2_CFG)['auth']['password'], 'before')

    def test_performance_dropin_restored_on_bad_start(self):
        self.setup_apply()
        dropin = app.performance_dropin('hy2')
        app.atomic_write(dropin, '[Service]\nNice=0\n')
        self.perf_write.side_effect = lambda kind, plan: app.atomic_write(dropin, '[Service]\nNice=-5\n')
        self.health.side_effect = [app.DeployError('bad startup'), None]
        with self.assertRaises(app.DeployError):
            app.apply_config('hy2', hy_config('after'), hy_meta(password='after'))
        self.assertEqual(dropin.read_text(), '[Service]\nNice=0\n')

    def test_light_defaults_preserve_user_tuning(self):
        original = {'sniff': {'enable': True}, 'ignoreClientBandwidth': True,
                    'quic': {'maxConnReceiveWindow': 123456, 'disablePathMTUDiscovery': True}}
        self.assertEqual(app.lean_hy2_defaults(copy.deepcopy(original)), original)
        fresh = app.lean_hy2_defaults({})
        self.assertFalse(fresh['sniff']['enable'])
        self.assertFalse(fresh['ignoreClientBandwidth'])
        self.assertFalse(fresh['quic']['disablePathMTUDiscovery'])
        self.assertNotIn('bandwidth', fresh)
        self.assertNotIn('maxConnReceiveWindow', fresh['quic'])

    def test_sampling_avoids_counting_steal_as_busy(self):
        before = {'cpu': [0] * 8, 'udp': {'RcvbufErrors': 10, 'SndbufErrors': 5}}
        after = {'cpu': [10, 0, 10, 30, 0, 0, 0, 50], 'udp': {'RcvbufErrors': 12, 'SndbufErrors': 5}}
        delta = app.counter_delta(before, after)
        self.assertEqual(delta['busy_pct'], 20)
        self.assertEqual(delta['steal_pct'], 50)
        self.assertEqual(delta['udp_errors'], {'RcvbufErrors': 2, 'SndbufErrors': 0})

    def test_kernel_counters_read_udp_and_exclude_guest_cpu(self):
        app.atomic_write(app.PROC_DIR / 'stat', 'cpu 1 2 3 4 5 6 7 8 100 200\ncpu0 1 2 3\n')
        app.atomic_write(app.PROC_DIR / 'net/snmp', 'Udp: InDatagrams RcvbufErrors SndbufErrors\nUdp: 100 5 7\n')
        result = app.performance_counters()
        self.assertEqual(result['cpu'], list(range(1, 9)))
        self.assertEqual(result['udp']['RcvbufErrors'], 5)

    def test_performance_persistence_and_runtime_verification(self):
        plan = {'settings': {'net.core.rmem_max': '16777216'}, 'previous': {'net.core.rmem_max': '212992'},
                'resources': {'memory_bytes': 1024**3, 'visible_cpus': 2}, 'dropin': '[Service]\nNice=-5\n'}
        with patch.object(app, 'run', return_value=subprocess.CompletedProcess([], 0, '16777216', '')):
            app.write_performance('hy2', plan)
        self.assertIn('net.core.rmem_max=16777216', app.PERF_FILE.read_text())
        self.assertEqual(app.performance_dropin('hy2').read_text(), '[Service]\nNice=-5\n')


if __name__ == '__main__':
    unittest.main()
