#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""VH2: VLESS Reality + Hysteria2 management for Debian/Ubuntu (Python 3.8+)."""

import argparse
import base64
import copy
import getpass
import ipaddress
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse
import uuid
from contextlib import contextmanager
from pathlib import Path

XRAY_BIN = Path('/usr/local/bin/xray')
XRAY_CFG = Path('/usr/local/etc/xray/config.json')
XRAY_SVC = 'xray.service'
EXPORT_DIR = Path('/etc/hy2config')
VLESS_LINK = EXPORT_DIR / 'vless_url_scheme.txt'
HY2_BIN = Path('/usr/local/bin/hysteria')
HY2_CFG = Path('/etc/hysteria/config.yaml')
HY2_SVC = 'hysteria-server.service'
HY2_LINK = EXPORT_DIR / 'hy2_url_scheme.txt'
DATA_DIR = Path('/var/lib/vh2')
STATE_FILE = DATA_DIR / 'state.json'
BACKUP_DIR = DATA_DIR / 'backups'
CERT_DIR = Path('/etc/hysteria/certs')
SYSTEMD_DIR = Path('/etc/systemd/system')
NFT_FILE = Path('/etc/vh2/hopping.nft')
NFT_UNIT = Path('/etc/systemd/system/vh2-hopping.service')
NFT_SVC = 'vh2-hopping.service'
BBR_FILE = Path('/etc/sysctl.d/90-vh2-bbr.conf')
PERF_FILE = Path('/etc/sysctl.d/91-vh2-performance.conf')
PROC_DIR = Path('/proc')
CGROUP_DIR = Path('/sys/fs/cgroup')
HELPER = Path('/usr/local/lib/vh2/VH2.py')
RENEW_HOOK = Path('/etc/letsencrypt/renewal-hooks/deploy/90-vh2')
OLD_CRON = '0 3 * * * certbot renew --quiet && systemctl restart xray hysteria-server'
SERVICES = {'vless': (XRAY_BIN, XRAY_CFG, XRAY_SVC, VLESS_LINK, 'tcp'),
            'hy2': (HY2_BIN, HY2_CFG, HY2_SVC, HY2_LINK, 'udp')}
INSTALLERS = {'vless': 'https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh',
              'hy2': 'https://get.hy2.sh/'}


class DeployError(RuntimeError):
    pass


def info(message):
    print('→ ' + str(message))


def ok(message):
    print('✓ ' + str(message))


def warn(message):
    print('! ' + str(message))


def run(args, check=True, timeout=60, **kwargs):
    """Never interpret user input as shell syntax; never echo secrets in errors."""
    if isinstance(args, str):
        raise TypeError('Commands must be argument lists')
    args = [str(arg) for arg in args]
    kwargs.setdefault('text', True)
    kwargs.setdefault('capture_output', True)
    try:
        result = subprocess.run(args, timeout=timeout, **kwargs)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DeployError('{} 执行失败或超时'.format(Path(args[0]).name)) from exc
    if check and result.returncode:
        raise DeployError('{} 执行失败（退出码 {}）'.format(Path(args[0]).name, result.returncode))
    return result


def private_dir(path):
    path = Path(path)
    if path.is_symlink():
        raise DeployError('拒绝使用符号链接目录：' + str(path))
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)


def atomic_write(path, content, mode=0o600, uid=None, gid=None):
    path = Path(path)
    if path.is_symlink():
        raise DeployError('拒绝覆盖符号链接：' + str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.vh2-', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content.encode('utf-8') if isinstance(content, str) else content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, mode)
        if uid is not None and hasattr(os, 'chown'):
            os.chown(name, uid, gid)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def json_text(value):
    return json.dumps(value, ensure_ascii=False, indent=2) + '\n'


def config_text(kind, value):
    if kind == 'vless':
        return json_text(value)
    import yaml
    return yaml.safe_dump(value, allow_unicode=True, sort_keys=False)


def read_config(path):
    if not path.exists():
        return {}
    text = path.read_text(encoding='utf-8')
    try:
        value = json.loads(text)
    except ValueError:
        try:
            import yaml
        except ImportError as exc:
            raise DeployError('读取旧 YAML 需要 python3-yaml：apt-get install -y python3-yaml') from exc
        try:
            value = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise DeployError('旧配置不是有效 YAML，请先修复或恢复备份') from exc
    if not isinstance(value, dict):
        raise DeployError('配置必须是对象：' + str(path))
    return value


def load_state():
    return read_config(STATE_FILE)


def valid_domain(value):
    value = value.strip().rstrip('.').lower()
    if len(value) > 253 or '.' not in value:
        raise ValueError('请输入完整域名')
    if not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
               for label in value.split('.')):
        raise ValueError('域名格式无效')
    return value


def choose_family(value):
    if value not in ('4', '6'):
        raise ValueError('请输入 4 或 6')
    return value


def valid_host(value):
    value = value.strip()
    try:
        return str(ipaddress.ip_address(value.strip('[]')))
    except ValueError:
        return valid_domain(value)


def uri_host(value):
    value = valid_host(value)
    return '[' + value + ']' if ':' in value else value


def valid_port(value):
    port = int(value)
    if not 1 <= port <= 65535:
        raise ValueError('端口范围为 1–65535')
    return port


def valid_url(value):
    value = value.strip()
    parsed = urllib.parse.urlsplit(value)
    if (parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username
            or parsed.password or any(ord(c) < 32 for c in value)):
        raise ValueError('请输入不含用户名密码的 HTTP/HTTPS URL')
    valid_host(parsed.hostname)
    if parsed.port is not None:
        valid_port(parsed.port)
    return value


def prompt(label, default=None, validator=lambda x: x):
    while True:
        value = input(label + (' [{}]'.format(default) if default is not None else '') + '：').strip()
        try:
            return validator(value if value else default if default is not None else '')
        except (ValueError, TypeError) as exc:
            warn(str(exc))


def yes(label, default=False):
    return prompt(label + (' [Y/n]' if default else ' [y/N]'),
                  'y' if default else 'n', lambda s: s.lower()) in ('y', 'yes')


def secret(label, previous=None):
    suffix = '（回车保留）' if previous else '（回车随机生成）'
    value = getpass.getpass(label + suffix + '：')
    return value or previous or secrets.token_urlsafe(24)


def service_property(service, prop):
    return run(['systemctl', 'show', service, '--property=' + prop, '--value']).stdout.strip()


def svc_active(service):
    return run(['systemctl', 'is-active', '--quiet', service], check=False).returncode == 0


def svc_enabled(service):
    return run(['systemctl', 'is-enabled', '--quiet', service], check=False).returncode == 0


def service_identity(service):
    import pwd
    import grp
    user = service_property(service, 'User') or 'root'
    record = pwd.getpwnam(user) if not user.isdigit() else pwd.getpwuid(int(user))
    group = service_property(service, 'Group')
    gid = (int(group) if group.isdigit() else grp.getgrnam(group).gr_gid) if group else record.pw_gid
    return user, record.pw_uid, gid


def port_lines(port, protocol):
    flag = '-Hlnpt' if protocol == 'tcp' else '-Hlnpu'
    return [line for line in run(['ss', flag, 'sport = :{}'.format(valid_port(port))]).stdout.splitlines()
            if line.strip()]


def port_available(port, protocol, service):
    lines = port_lines(port, protocol)
    if not lines:
        return True
    pid = service_property(service, 'MainPID')
    return pid not in ('', '0') and all('pid=' + pid + ',' in line for line in lines)


def choose_port(default, protocol, service):
    while True:
        port = prompt('监听端口（' + protocol.upper() + '）', default, valid_port)
        if port_available(port, protocol, service):
            return port
        warn('该端口被其他进程占用，请换一个端口')


def wait_healthy(service, port, protocol, timeout=20):
    deadline = time.monotonic() + timeout
    consecutive = 0
    while time.monotonic() < deadline:
        pid = service_property(service, 'MainPID')
        listening = pid not in ('', '0') and any('pid=' + pid + ',' in line
                                                 for line in port_lines(port, protocol))
        consecutive = consecutive + 1 if svc_active(service) and listening else 0
        if consecutive >= 3:
            return
        time.sleep(1)
    raise DeployError(service + ' 未稳定运行并监听预期端口；请查看诊断/日志')


def public_endpoint(previous=None):
    if previous:
        return prompt('客户端连接地址（公网 IP 或域名）', previous, valid_host)
    family = prompt('公网地址类型（4 / 6）', '4', choose_family)
    detected = None
    for url in ('https://api64.ipify.org', 'https://ifconfig.me/ip'):
        result = run(['curl', '-' + family, '-fsS', '--connect-timeout', '3', '--max-time', '5', url],
                     check=False, timeout=10)
        try:
            address = ipaddress.ip_address(result.stdout.strip())
            if address.version == int(family):
                detected = str(address)
                break
        except ValueError:
            pass
    return prompt('客户端连接地址（确认是 VPS 入站地址，非 WARP 出口）', detected, valid_host)


class Snapshot:
    """Backup only explicitly listed files, preserving mode/owner for rollback."""
    def __init__(self, paths, label, directories=()):
        private_dir(BACKUP_DIR)
        self.directory = BACKUP_DIR / (time.strftime('%Y%m%d-%H%M%S-') + secrets.token_hex(4))
        private_dir(self.directory)
        self.records = []
        for index, path in enumerate(dict.fromkeys(Path(p) for p in paths)):
            if path.is_symlink():
                raise DeployError('拒绝备份/覆盖符号链接：' + str(path))
            record = {'path': str(path), 'exists': path.exists()}
            if path.exists():
                st = path.stat()
                record.update(mode=stat.S_IMODE(st.st_mode), uid=st.st_uid, gid=st.st_gid, file=str(index))
                atomic_write(self.directory / str(index), path.read_bytes())
            self.records.append(record)
        self.directories = []
        for directory in directories:
            directory = Path(directory)
            if directory.is_symlink():
                raise DeployError('拒绝修改符号链接目录：' + str(directory))
            if directory.exists():
                st = directory.stat()
                self.directories.append({'path': str(directory), 'mode': stat.S_IMODE(st.st_mode),
                                         'uid': st.st_uid, 'gid': st.st_gid})
        atomic_write(self.directory / 'manifest.json', json_text(
            {'label': label, 'files': self.records, 'directories': self.directories}))

    def restore(self):
        for record in self.records:
            path = Path(record['path'])
            if record['exists']:
                atomic_write(path, (self.directory / record['file']).read_bytes(),
                             record['mode'], record['uid'], record['gid'])
            else:
                path.unlink(missing_ok=True)
        for record in reversed(self.directories):
            path = Path(record['path'])
            if hasattr(os, 'chown'):
                os.chown(path, record['uid'], record['gid'])
            path.chmod(record['mode'])


def restore_service(service, active, enabled):
    run(['systemctl', 'enable' if enabled else 'disable', service])
    run(['systemctl', 'restart' if active else 'stop', service])


def validate_config(kind, cfg, candidate):
    if kind == 'vless':
        run([XRAY_BIN, 'run', '-test', '-config', candidate])
        return
    if cfg.get('auth', {}).get('type') != 'password' or not isinstance(cfg['auth'].get('password'), str) or not cfg['auth']['password']:
        raise DeployError('HY2 需要非空字符串密码')
    valid_port(cfg['listen'].rsplit(':', 1)[1])
    valid_url(cfg['masquerade']['proxy']['url'])
    if bool(cfg.get('tls')) == bool(cfg.get('acme')):
        raise DeployError('tls 和 acme 必须选择且只选择一种')
    if cfg.get('tls'):
        validate_certificate(Path(cfg['tls']['cert']), Path(cfg['tls']['key']))
    if cfg.get('acme'):
        for domain in cfg['acme']['domains']:
            valid_domain(domain)
    # Hysteria has no standalone --check command. Runtime validation follows with rollback.


def validate_certificate(cert, key):
    if not cert.is_file() or not key.is_file():
        raise DeployError('证书或私钥文件不存在')
    cert_public = run(['openssl', 'x509', '-in', cert, '-pubkey', '-noout']).stdout.strip()
    key_public = run(['openssl', 'pkey', '-in', key, '-passin', 'pass:', '-pubout']).stdout.strip()
    if cert_public != key_public:
        raise DeployError('证书与私钥不匹配')
    run(['openssl', 'x509', '-in', cert, '-checkend', '0', '-noout'])


def certificate_paths():
    return {'cert': str(CERT_DIR / 'server.crt'), 'key': str(CERT_DIR / 'server.key')}


def stage_certificate(cert, key):
    """Read validated material without replacing the running service's certificate."""
    validate_certificate(cert, key)
    return {'cert': cert.read_bytes(), 'key': key.read_bytes()}


def service_directory(path, gid):
    if path.is_symlink():
        raise DeployError('拒绝修改符号链接目录：' + str(path))
    path.mkdir(parents=True, exist_ok=True, mode=0o750)
    if hasattr(os, 'chown'):
        os.chown(path, 0, gid)
    path.chmod(0o750)


def write_certificate(material, gid):
    service_directory(CERT_DIR, gid)
    atomic_write(CERT_DIR / 'server.crt', material['cert'], 0o644, 0, gid)
    atomic_write(CERT_DIR / 'server.key', material['key'], 0o640, 0, gid)


def certificate_wizard(old_cfg, old_meta):
    print('证书：1. 内置 ACME HTTP  2. 内置 ACME Cloudflare DNS  3. 自签  4. 手动路径  5. 保留现有')
    choice = prompt('证书方式', '5' if old_cfg.get('tls') or old_cfg.get('acme') else '1')
    if choice == '5':
        if old_cfg.get('acme'):
            return {'acme': old_cfg['acme']}, {'sni': old_cfg['acme']['domains'][0], 'insecure': False}, None
        if old_cfg.get('tls'):
            meta = copy.deepcopy(old_meta.get('certificate', {}))
            if 'sni' not in meta:
                meta['sni'] = prompt('证书对应域名', old_meta.get('sni', 'bing.com'), valid_domain)
            if 'insecure' not in meta:
                meta['insecure'] = yes('该证书是否为自签证书？')
            # Copy even legacy /etc/ssl/private certs to a service-readable dedicated directory.
            original = old_cfg['tls']
            if not meta['insecure']:
                run(['openssl', 'x509', '-in', original['cert'], '-checkhost', meta['sni'], '-noout'])
            managed = any(Path(parent) in Path(original['cert']).parents
                          for parent in (CERT_DIR, HY2_CFG.parent / 'vh2-certs'))
            if not meta.get('source') and not managed and not meta['insecure']:
                meta['source'] = {'cert': original['cert'], 'key': original['key']}
            return {'tls': certificate_paths()}, meta, stage_certificate(Path(original['cert']), Path(original['key']))
        raise DeployError('没有现有证书')
    domain = prompt('证书域名', 'bing.com' if choice == '3' else None, valid_domain)
    meta = {'sni': domain, 'insecure': choice == '3'}
    if choice in ('1', '2'):
        acme = {'domains': [domain], 'email': prompt('ACME 联系邮箱'), 'ca': 'letsencrypt',
                'type': 'http' if choice == '1' else 'dns'}
        if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', acme['email']):
            raise DeployError('邮箱格式无效')
        if choice == '1':
            if port_lines(80, 'tcp'):
                raise DeployError('TCP 80 已被占用，请改用 DNS 验证；不会停止现有网站')
            info('域名须解析到本 VPS；GCP 和系统防火墙需放行 TCP 80，并在续期期间保持可达')
        else:
            token = getpass.getpass('Cloudflare API Token（对应 Zone 的 DNS 编辑权限）：').strip()
            if not token:
                raise DeployError('API Token 不能为空')
            acme['dns'] = {'name': 'cloudflare', 'config': {'cloudflare_api_token': token}}
        return {'acme': acme}, meta, None
    if choice == '3':
        warn('自签模式的通用分享链接将设置 insecure=1；它不能验证服务器身份')
        with tempfile.TemporaryDirectory(prefix='vh2-cert-') as directory:
            cert, key = Path(directory) / 'cert.pem', Path(directory) / 'key.pem'
            run(['openssl', 'req', '-x509', '-nodes', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                 '-keyout', key, '-out', cert, '-subj', '/CN=' + domain,
                 '-addext', 'subjectAltName=DNS:' + domain, '-days', '365'])
            return {'tls': certificate_paths()}, meta, stage_certificate(cert, key)
    if choice == '4':
        cert = Path(prompt('证书 fullchain 路径')).expanduser().absolute()
        key = Path(prompt('私钥路径')).expanduser().absolute()
        run(['openssl', 'x509', '-in', cert, '-checkhost', domain, '-noout'])
        meta['source'] = {'cert': str(cert), 'key': str(key)}
        info('外部证书复制到专用目录；Certbot 续期可自动刷新，其他工具续期后运行 --refresh-cert')
        return {'tls': certificate_paths()}, meta, stage_certificate(cert, key)
    raise DeployError('证书选项无效')


def parse_key_pair(output):
    values = {}
    for line in output.splitlines():
        label, sep, value = line.partition(':')
        if not sep:
            continue
        label = label.lower().replace(' ', '')
        if label in ('privatekey', 'private'):
            values['private'] = value.strip()
        elif label in ('publickey', 'public', 'password', 'password(publickey)'):
            values['public'] = value.strip()
    for key in ('private', 'public'):
        value = values.get(key, '')
        try:
            if not re.fullmatch(r'[A-Za-z0-9_-]{43}', value) or len(base64.urlsafe_b64decode(value + '=')) != 32:
                raise ValueError()
        except ValueError as exc:
            raise DeployError('无法解析 Xray 密钥输出，请检查 Xray 版本') from exc
    return values['private'], values['public']


def build_link(kind, meta):
    endpoint = uri_host(meta['host']) + ':' + str(valid_port(meta['port']))
    if kind == 'vless':
        query = {'encryption': 'none', 'flow': 'xtls-rprx-vision', 'security': 'reality',
                 'sni': meta['sni'], 'fp': 'chrome', 'pbk': meta['public_key'],
                 'sid': meta['short_id'], 'type': 'tcp'}
        return 'vless://' + meta['uuid'] + '@' + endpoint + '?' + urllib.parse.urlencode(query) + '#VLESS-Reality'
    query = {'sni': meta['sni']}
    if meta.get('insecure'):
        query['insecure'] = '1'
    if meta.get('obfs'):
        query.update({'obfs': 'salamander', 'obfs-password': meta['obfs']})
    if meta.get('hopping'):
        query['mport'] = '{}-{}'.format(*meta['hopping'])
    return ('hysteria2://' + urllib.parse.quote(meta['password'], safe='') + '@' + endpoint + '?'
            + urllib.parse.urlencode(query) + '#HY2-Server')


def client_configs(state):
    mihomo, singbox = [], []
    links = []
    for kind in ('vless', 'hy2'):
        m = state.get(kind)
        if not m:
            continue
        links.append(build_link(kind, m))
        name = 'VLESS-Reality' if kind == 'vless' else 'HY2-Server'
        clash = {'name': name, 'type': 'vless' if kind == 'vless' else 'hysteria2',
                 'server': m['host'], 'port': m['port']}
        sb = {'tag': name, 'type': 'vless' if kind == 'vless' else 'hysteria2',
              'server': m['host'], 'server_port': m['port'],
              'tls': {'enabled': True, 'server_name': m['sni']}}
        if kind == 'vless':
            clash.update({'uuid': m['uuid'], 'flow': 'xtls-rprx-vision', 'tls': True,
                          'servername': m['sni'], 'client-fingerprint': 'chrome', 'udp': True,
                          'reality-opts': {'public-key': m['public_key'], 'short-id': m['short_id']}})
            sb.update({'uuid': m['uuid'], 'flow': 'xtls-rprx-vision'})
            sb['tls'].update({'utls': {'enabled': True, 'fingerprint': 'chrome'},
                              'reality': {'enabled': True, 'public_key': m['public_key'], 'short_id': m['short_id']}})
        else:
            clash.update({'password': m['password'], 'sni': m['sni'], 'skip-cert-verify': m['insecure']})
            sb['password'] = m['password']
            sb['tls']['insecure'] = m['insecure']
            if m.get('obfs'):
                clash.update({'obfs': 'salamander', 'obfs-password': m['obfs']})
                sb['obfs'] = {'type': 'salamander', 'password': m['obfs']}
            if m.get('hopping'):
                first, last = m['hopping']
                clash['ports'] = '{}-{}'.format(first, last)
                sb.pop('server_port')
                sb['server_ports'] = ['{}:{}'.format(first, last)]
        mihomo.append(clash)
        singbox.append(sb)
    names = [p['name'] for p in mihomo]
    clash_config = {'mixed-port': 7890, 'allow-lan': False, 'mode': 'rule', 'proxies': mihomo,
                    'proxy-groups': [{'name': 'PROXY', 'type': 'select', 'proxies': names or ['DIRECT']}],
                    'rules': ['MATCH,PROXY']}
    sb_config = {'inbounds': [{'type': 'mixed', 'tag': 'mixed-in', 'listen': '127.0.0.1', 'listen_port': 7890}],
                 'outbounds': [{'type': 'selector', 'tag': 'proxy', 'outbounds': names or ['direct']}] + singbox
                 + [{'type': 'direct', 'tag': 'direct'}], 'route': {'final': 'proxy'}}
    import yaml
    surge = surge_config(state)
    return {'mihomo.json': json_text(clash_config),
            'clash.yaml': yaml.safe_dump(clash_config, allow_unicode=True, sort_keys=False),
            'sing-box.json': json_text(sb_config), 'sing-box.yaml': json_text(sb_config),
            'surge.conf': surge, 'surge.yaml': surge,
            'links.txt': '\n'.join(links) + '\n',
            'hy2_url_scheme.txt': build_link('hy2', state['hy2']) + '\n' if state.get('hy2') else '',
            'vless_url_scheme.txt': build_link('vless', state['vless']) + '\n' if state.get('vless') else ''}


def surge_config(state):
    # Surge uses an INI profile, not YAML. Never silently fall back to direct traffic.
    notes = ['# VH2: 此模板仅导出 HY2；VLESS Reality 请使用 Mihomo / sing-box。']
    meta = state.get('hy2')
    policy = 'REJECT'
    proxy = ''
    if meta:
        values = [meta['host'], meta['sni'], meta['password'], meta.get('obfs', '')]
        # Escaping quotes/backslashes/control characters is not specified by Surge's manual.
        if any(any(ord(c) < 32 or c in '\\"' for c in value) for value in values):
            notes.append('# 未导出节点：凭据包含无法可靠转义的字符，请使用 Mihomo / sing-box。')
        else:
            quoted = lambda value: json.dumps(value, ensure_ascii=False)
            fields = ['hysteria2', meta['host'], str(meta['port']),
                      'password=' + quoted(meta['password']), 'sni=' + meta['sni'],
                      'skip-cert-verify=' + str(meta['insecure']).lower()]
            if meta.get('hopping'):
                fields.append('port-hopping={}-{}'.format(*meta['hopping']))
            if meta.get('obfs'):
                notes.append('# Salamander 需要支持该功能的 Surge 版本（官方文档标注 Mac 6.4.3+）。')
                fields.append('salamander-password=' + quoted(meta['obfs']))
            proxy = 'HY2-Server = ' + ', '.join(fields) + '\n'
            policy = 'HY2-Server'
    else:
        notes.append('# 没有 HY2 节点，此模板会拒绝流量。')
    return ('\n'.join(notes) + '\n[General]\nloglevel = notify\n\n[Proxy]\n' + proxy
            + '\n[Proxy Group]\nPROXY = select, ' + policy + '\n\n[Rule]\nFINAL,PROXY\n')


def export_paths():
    return [EXPORT_DIR / name for name in ('mihomo.json', 'clash.yaml', 'sing-box.json',
            'sing-box.yaml', 'surge.conf', 'surge.yaml', 'links.txt',
            'hy2_url_scheme.txt', 'vless_url_scheme.txt')]


def export_clients(state=None):
    state = load_state() if state is None else state
    private_dir(EXPORT_DIR)
    configs = client_configs(state)
    for name, content in configs.items():
        atomic_write(EXPORT_DIR / name, content)
    copy_exports_to_sudo_home(configs)


def copy_exports_to_sudo_home(configs):
    username = os.environ.get('SUDO_USER')
    if not username or username == 'root':
        info('未找到 SUDO_USER 普通用户，跳过 Home 副本；配置保留在 ' + str(EXPORT_DIR))
        return
    try:
        import pwd
        user = pwd.getpwnam(username)
        if user.pw_uid == 0:
            warn('SUDO_USER 指向 root，跳过 Home 副本')
            return
        home = Path(user.pw_dir)
        if not home.is_absolute() or not home.is_dir():
            raise DeployError('普通用户 Home 目录不存在或不是绝对路径')
        for name in configs:
            atomic_write(home / name, (EXPORT_DIR / name).read_bytes(),
                         0o600, user.pw_uid, user.pw_gid)
        ok('客户端配置已额外复制到 ' + str(home) + '，归属用户 ' + username)
    except (KeyError, OSError, DeployError) as exc:
        warn('复制配置到普通用户 Home 失败（{}）；原配置保留在 {}'.format(
            exc, EXPORT_DIR))


def print_link(kind, meta):
    link = build_link(kind, meta)
    print('\n' + link + '\n')
    if shutil.which('qrencode'):
        result = run(['qrencode', '-t', 'ANSIUTF8', '-o', '-'], input=link, check=False)
        if result.returncode == 0:
            print(result.stdout)
    info('客户端配置已在本地生成：' + str(EXPORT_DIR))


def nft_rules(ports, target):
    first, last = [valid_port(p) for p in ports]
    if first > last or first <= valid_port(target) <= last:
        raise ValueError('跳跃范围必须递增且不能包含服务监听端口')
    return ('table inet vh2_hopping {\n chain prerouting {\n'
            '  type nat hook prerouting priority dstnat; policy accept;\n'
            '  fib daddr type local udp dport ' + str(first) + '-' + str(last)
            + ' redirect to :' + str(target) + '\n }\n}\n')


def hopping_range_available(ports):
    first, last = ports
    lines = run(['ss', '-Hlnu']).stdout.splitlines()
    for line in lines:
        columns = line.split()
        if len(columns) < 4:
            continue
        try:
            port = int(columns[3].rsplit(':', 1)[1])
        except (ValueError, IndexError):
            continue
        if first <= port <= last:
            raise DeployError('跳跃范围包含已占用的 UDP 端口 ' + str(port))


def sync_hopping(meta):
    exists = False
    if shutil.which('nft'):
        exists = run(['nft', 'list', 'table', 'inet', 'vh2_hopping'], check=False).returncode == 0
    ports = meta.get('hopping') if meta else None
    if ports:
        rules = nft_rules(ports, meta['port'])
        # Delete/recreate ONLY this table in one atomic nft batch; never flush ruleset.
        batch = ('delete table inet vh2_hopping\n' if exists else '') + rules
        run(['nft', '--check', '-f', '-'], input=batch)
        run(['nft', '-f', '-'], input=batch)
        # `add table` is idempotent (unlike `create`); one atomic batch works at boot and restart.
        persistent = 'add table inet vh2_hopping\ndelete table inet vh2_hopping\n' + rules
        run(['nft', '--check', '-f', '-'], input=persistent)
        atomic_write(NFT_FILE, persistent, 0o600)
        nft = shutil.which('nft')
        atomic_write(NFT_UNIT, '[Unit]\nDescription=VH2 UDP port hopping\nAfter=network-pre.target nftables.service\n'
                     'Before=hysteria-server.service\n[Service]\nType=oneshot\nRemainAfterExit=yes\n'
                     'ExecStart=' + nft + ' -f ' + str(NFT_FILE) + '\n'
                     'ExecStop=-' + nft + ' delete table inet vh2_hopping\n'
                     '[Install]\nWantedBy=multi-user.target\n', 0o644)
        run(['systemctl', 'daemon-reload'])
        run(['systemctl', 'enable', NFT_SVC])
    else:
        if exists:
            run(['nft', 'delete', 'table', 'inet', 'vh2_hopping'])
        if NFT_UNIT.exists():
            run(['systemctl', 'disable', '--now', NFT_SVC])
            NFT_UNIT.unlink()
            NFT_FILE.unlink(missing_ok=True)
            run(['systemctl', 'daemon-reload'])


def manage_renew_hook(meta):
    source = meta.get('certificate', {}).get('source') if meta else None
    if source:
        atomic_write(HELPER, Path(__file__).read_bytes(), 0o700)
        atomic_write(RENEW_HOOK, '#!/bin/sh\n# Owned by VH2\nexec /usr/bin/python3 '
                     + str(HELPER) + ' --refresh-cert\n', 0o700)
    else:
        RENEW_HOOK.unlink(missing_ok=True)


def remove_legacy_cron(preserve_renewal=False):
    result = run(['crontab', '-l'], check=False) if shutil.which('crontab') else None
    if result and result.returncode == 0:
        lines = result.stdout.splitlines()
        kept = [line for line in lines if line.strip() != OLD_CRON]
        if kept != lines:
            if preserve_renewal:
                if service_property('certbot.timer', 'LoadState') != 'loaded':
                    warn('保留旧续期任务：未找到 certbot.timer。请配置外部续期计划后移除旧任务')
                    return
                run(['systemctl', 'enable', '--now', 'certbot.timer'])
            run(['crontab', '-'], input='\n'.join(kept) + '\n')
            info('已移除旧版 VH2 的精确匹配续期任务；其他任务保留')


def read_optional(path):
    try:
        return Path(path).read_text(encoding='utf-8').strip()
    except OSError:
        return ''


def host_resources():
    memory = {}
    for line in read_optional(PROC_DIR / 'meminfo').splitlines():
        key, _, value = line.partition(':')
        if value.strip():
            memory[key] = int(value.split()[0]) * 1024
    total = memory.get('MemTotal', 0)
    if not total:
        raise DeployError('无法读取 VPS 内存信息，未应用性能参数')
    # Respect a finite cgroup v2 memory limit when the guest exposes one.
    limits = [total]
    groups = [CGROUP_DIR]
    for line in read_optional(PROC_DIR / 'self/cgroup').splitlines():
        if line.startswith('0::'):
            relative = Path(line[3:].lstrip('/'))
            if '..' not in relative.parts:
                group = CGROUP_DIR / relative
                while group != CGROUP_DIR and CGROUP_DIR in group.parents:
                    groups.append(group)
                    group = group.parent
    for group in groups:
        value = read_optional(group / 'memory.max')
        if value.isdigit() and int(value) > 0:
            limits.append(int(value))
    return {'memory_bytes': min(limits), 'available_bytes': memory.get('MemAvailable'),
            'visible_cpus': os.cpu_count() or 1}


def performance_dropin(kind):
    return SYSTEMD_DIR / (SERVICES[kind][2] + '.d') / '90-vh2-performance.conf'


def prepare_performance(kind):
    resources = host_resources()
    desired = {}
    if kind == 'hy2':
        # Hysteria recommends 16 MiB; 8 MiB on <512 MiB machines is our conservative policy.
        target = (16 if resources['memory_bytes'] >= 512 * 1024**2 else 8) * 1024**2
        for key in ('net.core.rmem_max', 'net.core.wmem_max'):
            desired[key] = str(target)
    available = run(['sysctl', '-n', 'net.ipv4.tcp_available_congestion_control']).stdout.split()
    if 'bbr' not in available and shutil.which('modprobe'):
        run(['modprobe', 'tcp_bbr'], check=False)
        available = run(['sysctl', '-n', 'net.ipv4.tcp_available_congestion_control']).stdout.split()
    if 'bbr' in available:
        desired.update({'net.ipv4.tcp_congestion_control': 'bbr', 'net.core.default_qdisc': 'fq'})
    else:
        warn('内核未提供 TCP BBR，保留现有 TCP 算法；HY2 QUIC 算法独立运行')
    previous = {key: run(['sysctl', '-n', key]).stdout.strip() for key in desired}
    for key in ('net.core.rmem_max', 'net.core.wmem_max'):
        if key in desired:
            desired[key] = str(max(int(previous[key]), int(desired[key])))
    # Preserve higher socket ceilings already set by an administrator. Change no defaults,
    # tcp_mem, conntrack limits, CPU quotas, GOMAXPROCS, GOGC, or realtime scheduling.
    nice = min(-5, int(service_property(SERVICES[kind][2], 'Nice') or '0'))
    return {'resources': resources, 'settings': desired, 'previous': previous,
            'dropin': '[Service]\nNice={}\n'.format(nice)}


def write_performance(kind, plan):
    saved = {}
    if PERF_FILE.exists():
        for line in PERF_FILE.read_text(encoding='utf-8').splitlines():
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                saved[key.strip()] = value.strip()
    saved.update(plan['settings'])
    atomic_write(PERF_FILE, '# Owned by VH2; socket ceilings do not preallocate memory\n'
                 + ''.join(key + '=' + value + '\n' for key, value in sorted(saved.items())), 0o644)
    # Apply only this plan's keys, not stale or unrelated settings from other files.
    for key, value in plan['settings'].items():
        run(['sysctl', '-w', key + '=' + value])
        if run(['sysctl', '-n', key]).stdout.strip() != value:
            raise DeployError('性能参数未生效：' + key)
    atomic_write(performance_dropin(kind), plan['dropin'], 0o644)
    run(['systemctl', 'daemon-reload'])
    info('性能配置：可见 CPU {}，有效内存 {:.0f} MiB；普通调度 Nice≤-5'.format(
        plan['resources']['visible_cpus'], plan['resources']['memory_bytes'] / 1024**2))


def restore_performance(plan):
    for key, value in plan['previous'].items():
        run(['sysctl', '-w', key + '=' + value])
    run(['systemctl', 'daemon-reload'])


def lean_hy2_defaults(cfg):
    # No invented link capacity: with no client bandwidth hint HY2 defaults to QUIC BBR.
    # Existing explicit choices are retained, including a measured Brutal setup.
    cfg.setdefault('sniff', {'enable': False})
    cfg.setdefault('ignoreClientBandwidth', False)
    cfg.setdefault('quic', {}).setdefault('disablePathMTUDiscovery', False)
    return cfg


def performance_counters():
    cpu_line = next((line for line in read_optional(PROC_DIR / 'stat').splitlines()
                     if line.startswith('cpu ')), '')
    cpu = [int(value) for value in cpu_line.split()[1:9]] if cpu_line else []
    udp = {}
    lines = read_optional(PROC_DIR / 'net/snmp').splitlines()
    for index in range(len(lines) - 1):
        if lines[index].startswith('Udp:') and lines[index + 1].startswith('Udp:'):
            udp = dict(zip(lines[index].split()[1:], map(int, lines[index + 1].split()[1:])))
            break
    return {'cpu': cpu, 'udp': udp}


def counter_delta(before, after):
    result = {}
    if len(before['cpu']) >= 8 and len(after['cpu']) >= 8:
        values = [max(0, b - a) for a, b in zip(before['cpu'], after['cpu'])]
        total = sum(values)
        if total:
            result['busy_pct'] = 100 * (total - values[3] - values[4] - values[7]) / total
            result['steal_pct'] = 100 * values[7] / total
    result['udp_errors'] = {key: max(0, after['udp'][key] - before['udp'][key])
                            for key in ('RcvbufErrors', 'SndbufErrors')
                            if key in before['udp'] and key in after['udp']}
    return result


def performance_report(seconds=5):
    resources = host_resources()
    print('可见 CPU：{}；有效内存：{:.0f} MiB；主机可用内存：{}'.format(
        resources['visible_cpus'], resources['memory_bytes'] / 1024**2,
        '{:.0f} MiB'.format(resources['available_bytes'] / 1024**2) if resources['available_bytes'] is not None else '未知'))
    info('采样 {} 秒；请同时使用客户端传输。此命令不产生测速下载流量。'.format(seconds))
    before = performance_counters()
    time.sleep(seconds)
    measured = counter_delta(before, performance_counters())
    if 'busy_pct' in measured:
        print('系统 CPU 忙碌：{:.1f}%；steal：{:.1f}%（无法据此精确推算共享 CPU 配额）'.format(
            measured['busy_pct'], measured['steal_pct']))
    print('采样期 UDP 缓冲区错误增量（全系统）：' + str(measured['udp_errors']))
    for key in ('net.core.rmem_max', 'net.core.wmem_max', 'net.ipv4.tcp_congestion_control'):
        print(key + '=' + run(['sysctl', '-n', key]).stdout.strip())
    for kind, (binary, _, service, _, _) in SERVICES.items():
        if binary.exists():
            print(service + ':')
            print(run(['systemctl', 'show', service, '--property=MemoryCurrent,Nice,CPUQuotaPerSecUSec,LimitNOFILE']).stdout.strip())
    info('e2-micro 的 2 个可见 vCPU 不代表 2 个专用核；持续速度应在超过突发阶段后比较')


def apply_config(kind, cfg, meta, show_link=True, certificate=None):
    _, config_path, service, link_path, protocol = SERVICES[kind]
    command = service_property(service, 'ExecStart')
    if str(config_path) not in command:
        raise DeployError('服务使用了自定义启动路径，请先确认 ExecStart 指向 ' + str(config_path))
    user, _, gid = service_identity(service)
    if kind == 'hy2' and user != 'hysteria':
        raise DeployError('HY2 服务必须使用 User=hysteria；请检查 systemctl cat ' + service)
    previous_state = load_state()
    next_state = copy.deepcopy(previous_state)
    next_state[kind] = meta
    active, enabled = svc_active(service), svc_enabled(service)
    performance = prepare_performance(kind)
    paths = [config_path, link_path, STATE_FILE, PERF_FILE, performance_dropin(kind)] + export_paths()
    if kind == 'hy2':
        paths += [NFT_FILE, NFT_UNIT, HELPER, RENEW_HOOK]
        if certificate is not None:
            if cfg.get('tls') != certificate_paths():
                raise DeployError('待安装证书必须使用固定的 HY2 证书路径')
            paths += list(certificate_paths().values())
    directories = [config_path.parent]
    if certificate is not None:
        directories.append(CERT_DIR)
    snapshot = Snapshot(paths, 'configure ' + kind, directories=directories)
    info('备份：' + str(snapshot.directory))
    candidate = config_path.with_name('.vh2-candidate' + config_path.suffix)
    changed = False
    try:
        atomic_write(candidate, config_text(kind, cfg))
        if certificate is None:
            validate_config(kind, cfg, candidate)
        else:
            # Validate staged material as root, without binding a socket or replacing live files.
            with tempfile.TemporaryDirectory(prefix='vh2-check-') as directory:
                checked = copy.deepcopy(cfg)
                checked['tls'] = {}
                for name, content in certificate.items():
                    path = Path(directory) / name
                    atomic_write(path, content)
                    checked['tls'][name] = str(path)
                validate_config(kind, checked, candidate)
        changed = True
        service_directory(config_path.parent, gid)
        if certificate is not None:
            write_certificate(certificate, gid)
        write_performance(kind, performance)
        atomic_write(config_path, config_text(kind, cfg), 0o640, 0, gid)
        if kind == 'hy2':
            sync_hopping(meta)
        run(['systemctl', 'enable', service])
        run(['systemctl', 'restart', service])
        wait_healthy(service, meta['port'], protocol, timeout=150 if cfg.get('acme') else 20)
        private_dir(DATA_DIR)
        atomic_write(STATE_FILE, json_text(next_state))
        atomic_write(link_path, build_link(kind, meta) + '\n')
        export_clients(next_state)
        if kind == 'hy2':
            manage_renew_hook(meta)
    except BaseException as exc:
        if not changed:
            raise
        warn('应用失败，恢复配置、连接信息和原服务状态')
        try:
            run(['systemctl', 'stop', service])
            # Clear active table/unit before restoring old files.
            if kind == 'hy2':
                sync_hopping(None)
            snapshot.restore()
            restore_performance(performance)
            if kind == 'hy2':
                sync_hopping(previous_state.get('hy2'))
            restore_service(service, active, enabled)
            if active and previous_state.get(kind):
                wait_healthy(service, previous_state[kind]['port'], protocol)
        except Exception as rollback_error:
            raise DeployError('自动恢复未完成，请使用备份 {}；{}'.format(snapshot.directory, rollback_error)) from exc
        raise
    finally:
        candidate.unlink(missing_ok=True)
    if kind == 'hy2':
        try:
            remove_legacy_cron(preserve_renewal=bool(meta.get('certificate', {}).get('source')))
        except DeployError:
            warn('部署已完成，但旧版精确匹配续期任务清理失败，请检查 crontab')
    ok(service + ' 已通过本机启动和监听检查；公网连通性仍需客户端验证')
    if show_link:
        print_link(kind, meta)


def configure_vless():
    if not XRAY_BIN.exists():
        raise DeployError('请先安装 Xray')
    old_cfg = read_config(XRAY_CFG)
    old_meta = load_state().get('vless', {})
    cfg = copy.deepcopy(old_cfg)
    inbound = next((x for x in cfg.get('inbounds', []) if x.get('protocol') == 'vless'
                    and x.get('streamSettings', {}).get('security') == 'reality'), None)
    if inbound is None and cfg.get('inbounds'):
        raise DeployError('已有非 VH2 配置；请先备份并手动迁移，避免覆盖其他节点')
    old_reality = inbound.get('streamSettings', {}).get('realitySettings', {}) if inbound else {}
    port = choose_port(inbound.get('port', 443) if inbound else 443, 'tcp', XRAY_SVC)
    host = public_endpoint(old_meta.get('host'))
    dest = prompt('Reality 目标（域名:端口）', old_reality.get('target', old_reality.get('dest', 'www.microsoft.com:443')))
    dest_host, sep, dest_port = dest.rpartition(':')
    if not sep:
        raise DeployError('Reality 目标必须包含端口')
    sni = valid_domain(dest_host)
    dest = sni + ':' + str(valid_port(dest_port))
    preserve = bool(inbound) and not yes('重新生成身份凭据？现有客户端将需要更新')
    key_args = [XRAY_BIN, 'x25519']
    if preserve:
        key_args += ['-i', old_reality['privateKey']]
    private, public = parse_key_pair(run(key_args).stdout)
    clients = inbound['settings']['clients'] if preserve else [{'id': str(uuid.uuid4()), 'flow': 'xtls-rprx-vision'}]
    if len(clients) != 1:
        raise DeployError('检测到多用户配置；当前向导仅管理单用户，请手动迁移')
    identity = str(uuid.UUID(clients[0]['id']))
    short_ids = old_reality.get('shortIds', []) if preserve else []
    short_ids = short_ids or [secrets.token_hex(8)]
    if inbound is None:
        inbound = {'protocol': 'vless', 'settings': {'decryption': 'none'},
                   'streamSettings': {'network': 'tcp', 'security': 'reality'}}
        cfg = {'inbounds': [inbound], 'outbounds': [{'protocol': 'freedom'}]}
    inbound.update({'listen': prompt('监听地址（IPv4 用 0.0.0.0，IPv6 用 ::）',
                                     inbound.get('listen', '::' if ':' in host else '0.0.0.0'),
                                     lambda v: str(ipaddress.ip_address(v))), 'port': port})
    inbound['settings']['clients'] = clients
    reality = inbound['streamSettings'].setdefault('realitySettings', {})
    reality.update({'show': False, 'dest': dest, 'xver': 0, 'serverNames': [sni],
                    'privateKey': private, 'shortIds': short_ids})
    reality.pop('target', None)
    meta = {'host': host, 'port': port, 'uuid': identity, 'public_key': public, 'short_id': short_ids[0], 'sni': sni}
    apply_config('vless', cfg, meta)


def configure_hy2(fresh=False):
    if not HY2_BIN.exists():
        raise DeployError('请先安装 Hysteria2')
    old_cfg = {} if fresh else read_config(HY2_CFG)
    old_meta = load_state().get('hy2', {})
    cfg = copy.deepcopy(old_cfg)
    if old_cfg.get('auth', {}).get('type') not in (None, 'password'):
        raise DeployError('已有非单密码认证配置；请手动迁移')
    port = choose_port(int(str(old_cfg.get('listen', ':443')).rsplit(':', 1)[-1]), 'udp', HY2_SVC)
    host = public_endpoint(old_meta.get('host'))
    password = secret('连接密码', old_cfg.get('auth', {}).get('password'))
    masq = prompt('伪装目标 URL', old_cfg.get('masquerade', {}).get('proxy', {}).get('url', 'https://www.bing.com'), valid_url)
    cert_cfg, cert_meta, certificate = certificate_wizard(old_cfg, old_meta)
    cfg.pop('tls', None)
    cfg.pop('acme', None)
    cfg.update(cert_cfg)
    cfg.update({'listen': ':' + str(port), 'auth': {'type': 'password', 'password': password},
                'masquerade': {'type': 'proxy', 'proxy': {'url': masq, 'rewriteHost': True}}})
    lean_hy2_defaults(cfg)
    meta = {'host': host, 'port': port, 'password': password, 'sni': cert_meta['sni'],
            'insecure': cert_meta['insecure'], 'certificate': cert_meta}
    info('新节点默认关闭嗅探/混淆/跳跃，保留 QUIC 窗口和 MTU 自动发现；已有自定义设置保留')
    if yes('打开高级选项（嗅探/带宽策略/混淆/跳跃）？'):
        info('嗅探用于识别目标域名，不是加速开关；无域名分流需求时保持关闭')
        sniff = yes('开启协议嗅探？', bool(old_cfg.get('sniff', {}).get('enable')))
        cfg['sniff'] = {'enable': sniff, 'timeout': '2s', 'rewriteDomain': False,
                        'tcpPorts': '80,443,8000-9000', 'udpPorts': 'all'}
        cfg['ignoreClientBandwidth'] = yes('忽略客户端带宽提示，使用非 Brutal 控制器？',
                                           bool(old_cfg.get('ignoreClientBandwidth')))
        info('不忽略提示也不会自动开启 Brutal：客户端填写带宽才参与选择；带宽应来自实测')
        if yes('开启 Salamander 混淆？将不再提供标准 HTTP/3 伪装', bool(old_cfg.get('obfs'))):
            pwd = secret('混淆密码', old_cfg.get('obfs', {}).get('salamander', {}).get('password'))
            cfg['obfs'] = {'type': 'salamander', 'salamander': {'password': pwd}}
        else:
            cfg.pop('obfs', None)
        if yes('开启 UDP 端口跳跃？需额外放行整个范围', bool(old_meta.get('hopping'))):
            require_packages({'nft': 'nftables'})
            ports = [prompt('起始端口', 20000, valid_port), prompt('结束端口', 20100, valid_port)]
            nft_rules(ports, port)
            hopping_range_available(ports)
            meta['hopping'] = ports
    else:
        if old_meta.get('hopping'):
            meta['hopping'] = old_meta['hopping']
            nft_rules(meta['hopping'], port)
    if cfg.get('obfs'):
        if cfg['obfs'].get('type') != 'salamander':
            raise DeployError('当前导出支持 Salamander；其他混淆请手动管理')
        meta['obfs'] = cfg['obfs']['salamander']['password']
    if cert_cfg.get('acme'):
        info('首次 ACME 申请可能需要两分钟；失败将恢复旧配置')
    apply_config('hy2', cfg, meta, certificate=certificate)


def require_packages(commands):
    missing = sorted({package for command, package in commands.items() if not shutil.which(command)})
    if missing:
        info('安装依赖：' + ', '.join(missing))
        run(['apt-get', 'update'], timeout=300, capture_output=False)
        run(['apt-get', 'install', '-y'] + missing, timeout=600, capture_output=False)


def install_core(kind, version='', upgrade=False):
    binary, config, service, _, protocol = SERVICES[kind]
    if version and not re.fullmatch(r'v?\d+(?:\.\d+){1,3}(?:[-.][A-Za-z0-9]+)*', version):
        raise DeployError('版本号格式无效')
    if binary.exists() and not upgrade:
        info('已安装，直接进入配置；更新请使用“升级内核”')
        return
    snapshot = None
    active, enabled = svc_active(service), svc_enabled(service)
    if upgrade:
        if not binary.exists():
            raise DeployError('尚未安装，请先部署')
        unit = SYSTEMD_DIR / service
        paths = [binary, config, unit] + list(unit.with_name(service + '.d').glob('*.conf'))
        snapshot = Snapshot(paths, 'upgrade ' + kind)
        info('升级备份：' + str(snapshot.directory))
    try:
        with tempfile.TemporaryDirectory(prefix='vh2-installer-') as directory:
            installer = Path(directory) / 'install.sh'
            run(['curl', '-fL', '--proto', '=https', '--tlsv1.2', '--connect-timeout', '10',
                 '--max-time', '120', '--retry', '2', '-o', installer, INSTALLERS[kind]], timeout=300)
            if not installer.stat().st_size:
                raise DeployError('下载的安装脚本为空')
            # Official installers expect normal directory traversal permissions. Manager
            # secrets retain umask 077; only this child uses 022. No input enters shell code.
            args = ['bash', '-c', 'umask 022; exec bash "$@"', 'vh2-installer', str(installer)]
            args += ['install'] if kind == 'vless' else []
            if version:
                args += ['--version', 'v' + version.lstrip('v')]
            if upgrade and kind == 'vless':
                args += ['--no-update-service']
            run(args, timeout=900, capture_output=False)
        if not binary.exists():
            raise DeployError('安装结束但找不到程序')
        run([binary, 'version'])
        if upgrade:
            # Installer is not allowed to rotate configuration/identity during an upgrade.
            rec = next(r for r in snapshot.records if r['path'] == str(config))
            if rec['exists']:
                atomic_write(config, (snapshot.directory / rec['file']).read_bytes(), rec['mode'], rec['uid'], rec['gid'])
            restore_service(service, active, enabled)
            if active:
                cfg = read_config(config)
                port = (next(x for x in cfg['inbounds'] if x.get('protocol') == 'vless')['port']
                        if kind == 'vless' else int(cfg['listen'].rsplit(':', 1)[1]))
                wait_healthy(service, port, protocol)
    except BaseException as exc:
        if snapshot:
            try:
                run(['systemctl', 'stop', service], check=False)
                snapshot.restore()
                run(['systemctl', 'daemon-reload'])
                restore_service(service, active, enabled)
                if active and not svc_active(service):
                    raise DeployError('旧服务未恢复运行')
            except Exception as rollback_error:
                raise DeployError('升级恢复未完成；备份 {}；{}'.format(snapshot.directory, rollback_error)) from exc
            warn('升级失败，已恢复旧程序和配置')
        raise
    ok(kind + ' 安装/升级完成')


def refresh_certificate():
    state = load_state()
    meta = state.get('hy2', {})
    cert_meta = meta.get('certificate', {})
    source = cert_meta.get('source')
    if not source:
        return
    lineage = os.environ.get('RENEWED_LINEAGE')
    if lineage and Path(source['cert']).parent != Path(lineage):
        return
    if not svc_active(HY2_SVC):
        raise DeployError('HY2 未运行，未自动启动；启动后再执行 --refresh-cert')
    if not meta.get('insecure'):
        run(['openssl', 'x509', '-in', source['cert'], '-checkhost', meta['sni'], '-noout'])
    cfg = read_config(HY2_CFG)
    certificate = stage_certificate(Path(source['cert']), Path(source['key']))
    cfg['tls'] = certificate_paths()
    apply_config('hy2', cfg, meta, show_link=False, certificate=certificate)


def diagnostics(kind=None, logs=False):
    for name in ([kind] if kind else SERVICES):
        binary, config, service, _, proto = SERVICES[name]
        print('\n' + name.upper() + ': ' + ('运行中' if svc_active(service) else '未运行'))
        if binary.exists():
            print(run([binary, 'version'], check=False).stdout.strip())
        print('配置：' + str(config))
        print(run(['systemctl', 'show', service, '--property=User,Group,MainPID,Result,ExecMainStatus,FragmentPath'], check=False).stdout)
        meta = load_state().get(name, {})
        if meta:
            print('期望入站：{} / {}'.format(meta['port'], proto))
            print('\n'.join(port_lines(meta['port'], proto)))
        if logs:
            print(run(['journalctl', '-u', service, '-n', '60', '--no-pager'], check=False).stdout)
    info('本机监听不代表公网可达：检查 GCP VPC 入站规则、目标标签、系统防火墙及客户端')


def restart_services():
    state = load_state()
    for kind, (_, config, service, _, proto) in SERVICES.items():
        if config.exists():
            run(['systemctl', 'restart', service])
            meta = state.get(kind)
            if meta:
                wait_healthy(service, meta['port'], proto)
            elif not svc_active(service):
                raise DeployError(service + ' 启动失败')
            ok(service + ' 已重启')


def enable_bbr():
    info('此项调整系统 TCP；不会直接改变 HY2 的 QUIC 拥塞控制')
    if not yes('开启 TCP BBR？'):
        return
    run(['modprobe', 'tcp_bbr'], check=False)
    available = run(['sysctl', '-n', 'net.ipv4.tcp_available_congestion_control']).stdout.split()
    if 'bbr' not in available:
        raise DeployError('当前内核不支持 BBR；未更换内核')
    keys = ('net.core.default_qdisc', 'net.ipv4.tcp_congestion_control')
    previous = {key: run(['sysctl', '-n', key]).stdout.strip() for key in keys}
    snapshot = Snapshot([BBR_FILE], 'enable bbr')
    try:
        atomic_write(BBR_FILE, 'net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n', 0o644)
        run(['sysctl', '-p', BBR_FILE])
        if run(['sysctl', '-n', keys[1]]).stdout.strip() != 'bbr':
            raise DeployError('BBR 验证失败')
    except BaseException:
        snapshot.restore()
        for key, value in previous.items():
            run(['sysctl', '-w', key + '=' + value])
        raise
    ok('TCP BBR 已开启')


def uninstall(kind):
    binary, config, service, link, _ = SERVICES[kind]
    if not yes('停止并卸载 {}？配置和证书将保留，客户端导出将移除此节点'.format(kind)):
        return
    state = load_state()
    if kind not in state:
        raise DeployError('此节点未被新版 VH2 接管；请使用官方卸载方式，避免误删其他配置')
    paths = [binary, config, STATE_FILE, link, performance_dropin(kind)] + export_paths()
    if kind == 'hy2':
        paths += [NFT_FILE, NFT_UNIT, RENEW_HOOK]
    snapshot = Snapshot(paths, 'uninstall ' + kind)
    active, enabled = svc_active(service), svc_enabled(service)
    previous = copy.deepcopy(state)
    try:
        run(['systemctl', 'disable', '--now', service])
        # Retain units/config/certificates for recovery. Delete only known files.
        binary.unlink(missing_ok=True)
        link.unlink(missing_ok=True)
        performance_dropin(kind).unlink(missing_ok=True)
        run(['systemctl', 'daemon-reload'])
        if kind == 'hy2':
            sync_hopping(None)
            manage_renew_hook(None)
        state.pop(kind, None)
        atomic_write(STATE_FILE, json_text(state))
        export_clients(state)
    except BaseException as exc:
        try:
            snapshot.restore()
            run(['systemctl', 'daemon-reload'])
            if kind == 'hy2':
                sync_hopping(previous.get('hy2'))
            restore_service(service, active, enabled)
        except Exception as rollback_error:
            raise DeployError('卸载恢复未完成；备份 {}；{}'.format(snapshot.directory, rollback_error)) from exc
        raise
    if kind == 'hy2':
        try:
            remove_legacy_cron()
        except DeployError:
            warn('程序已卸载，旧版精确匹配 cron 清理失败，请检查 crontab')
    ok('已停止、禁用并删除 {} 程序；保留配置/证书/备份'.format(kind))


@contextmanager
def process_lock():
    import fcntl
    private_dir(DATA_DIR)
    with (DATA_DIR / 'manager.lock').open('a') as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise DeployError('另一个 VH2 管理任务正在运行，请稍后重试') from exc
        yield


def preflight(install_dependencies=False):
    if sys.platform != 'linux' or not hasattr(os, 'geteuid') or os.geteuid() != 0:
        raise DeployError('请在 Linux VPS 上以 root 运行：sudo python3 VH2.py')
    if not Path('/run/systemd/system').exists():
        raise DeployError('需要 systemd 系统')
    if not shutil.which('apt-get'):
        raise DeployError('当前自动安装支持 Debian/Ubuntu')
    os.umask(0o077)
    if install_dependencies:
        require_packages({'curl': 'curl', 'openssl': 'openssl', 'ss': 'iproute2'})
        # Use the system interpreter so apt's python3-yaml is importable.
        try:
            import yaml  # noqa: F401
        except ImportError:
            run(['apt-get', 'update'], timeout=300, capture_output=False)
            run(['apt-get', 'install', '-y', 'python3-yaml'], timeout=300, capture_output=False)
            try:
                import yaml  # noqa: F401
            except ImportError as exc:
                raise DeployError('请使用系统 Python：sudo /usr/bin/python3 VH2.py') from exc


def agree_treaty():
    """Reuse the old hy2 acknowledgement; never modify the system after a refusal."""
    marker = EXPORT_DIR / 'agree.txt'
    if EXPORT_DIR.is_symlink() or marker.is_symlink():
        raise DeployError('同意记录不能使用符号链接')
    if marker.is_file():
        return True
    print('使用说明：请仅在你有权管理的服务器上部署，并遵守适用法律。\n'
          '安装和配置操作会修改服务、证书及网络参数；请保管好导出文件中的连接凭据。')
    if not yes('是否同意并继续？'):
        info('未同意，已退出；未安装依赖或修改服务')
        return False
    private_dir(EXPORT_DIR)
    atomic_write(marker, 'VH2 accepted\n')
    return True


def export_all(show_links=True):
    state = load_state()
    if not any(state.get(kind) for kind in SERVICES):
        raise DeployError('没有已保存的节点；请先在“配置 → 一键修改”中接管已有配置，再导出')
    snapshot = Snapshot(export_paths(), 'export clients')
    try:
        export_clients(state)
    except BaseException:
        snapshot.restore()
        raise
    if show_links:
        for kind in SERVICES:
            if state.get(kind):
                print_link(kind, state[kind])
    ok('已一键导出到 ' + str(EXPORT_DIR))
    info('clash.yaml / sing-box.json / surge.conf；旧 sing-box.yaml、surge.yaml 为同内容兼容副本')
    if not state.get('hy2') or '[Proxy]\n\n' in surge_config(state):
        warn('Surge 模板没有可用 HY2 节点；请使用 Mihomo / sing-box，详情见模板注释')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--diagnose', action='store_true', help='查看本机服务与监听状态')
    parser.add_argument('--logs', action='store_true', help='诊断时包含服务日志')
    parser.add_argument('--export', action='store_true', help='从保存的状态本地导出客户端配置')
    parser.add_argument('--refresh-cert', action='store_true', help='外部证书续期后刷新 HY2 副本')
    parser.add_argument('--performance-report', action='store_true', help='采样 5 秒，检查 CPU/内存/UDP 缓冲区错误')
    args = parser.parse_args()
    preflight()
    if args.diagnose or args.export or args.refresh_cert or args.performance_report:
        with process_lock():
            if args.performance_report:
                performance_report()
            elif args.diagnose:
                diagnostics(logs=args.logs)
            elif args.export:
                export_all(show_links=False)
            else:
                refresh_certificate()
        return
    if not agree_treaty():
        return
    preflight(install_dependencies=True)
    while True:
        print('\nVH2 — VLESS Reality + Hysteria2\n'
              '1. 安装/更新\n2. 卸载\n3. 配置\n4. 服务管理\n0. 退出')
        choice = input('请选择：').strip()
        if choice == '0':
            return
        try:
            menu_action(choice)
        except (DeployError, ValueError, KeyError, OSError) as exc:
            warn(str(exc))
        except KeyboardInterrupt:
            warn('已取消当前操作')


def select_protocol():
    choice = prompt('协议：1. HY2  2. VLESS  3. 双协议  0. 返回', '1')
    choices = {'1': ('hy2',), '2': ('vless',), '3': ('vless', 'hy2'), '0': ()}
    if choice not in choices:
        raise DeployError('协议选项无效')
    return choices[choice]


def menu_action(choice):
    # Submenu prompts do not hold the process lock while waiting for user input.
    if choice == '1':
        action = prompt('1. 安装并配置  2. 更新内核（保留配置）  0. 返回', '1')
        if action == '0':
            return
        if action not in ('1', '2'):
            raise DeployError('选项无效')
        kinds = select_protocol()
        if not kinds:
            return
        versions = {kind: prompt(kind.upper() + ' 版本号（回车使用官方最新稳定版）', '')
                    if action == '2' else '' for kind in kinds}
        with process_lock():
            for kind in kinds:
                fresh = not SERVICES[kind][0].exists() and not SERVICES[kind][1].exists()
                install_core(kind, versions[kind], upgrade=action == '2')
                if action == '1':
                    if kind == 'hy2':
                        configure_hy2(fresh=fresh)
                    else:
                        configure_vless()
    elif choice == '2':
        kinds = select_protocol()
        if kinds:
            with process_lock():
                for kind in kinds:
                    uninstall(kind)
    elif choice == '3':
        action = prompt('1. 配置查看  2. 配置一键修改  3. 一键导出配置/链接  4. 性能优化与采样  0. 返回', '1')
        if action == '0':
            return
        if action == '3':
            with process_lock():
                export_all()
        elif action == '4':
            option = prompt('1. 性能采样（5 秒）  2. 启用 TCP BBR  0. 返回', '1')
            if option == '0':
                return
            if option not in ('1', '2'):
                raise DeployError('选项无效')
            with process_lock():
                (performance_report if option == '1' else enable_bbr)()
        elif action in ('1', '2'):
            kinds = select_protocol()
            if kinds:
                with process_lock():
                    for kind in kinds:
                        if action == '1':
                            path = SERVICES[kind][1]
                            print(str(path) + ':\n' + config_text(kind, read_config(path)))
                        else:
                            (configure_hy2 if kind == 'hy2' else configure_vless)()
        else:
            raise DeployError('选项无效')
    elif choice == '4':
        action = prompt('1. 状态/版本  2. 启动  3. 停止  4. 重启  5. 诊断/日志  0. 返回', '1')
        if action == '0':
            return
        if action not in ('1', '2', '3', '4', '5'):
            raise DeployError('选项无效')
        kinds = select_protocol()
        if kinds:
            with process_lock():
                state = load_state()
                for kind in kinds:
                    if action in ('1', '5'):
                        diagnostics(kind, logs=action == '5')
                        continue
                    _, _, service, _, protocol = SERVICES[kind]
                    command = {'2': 'start', '3': 'stop', '4': 'restart'}[action]
                    run(['systemctl', command, service])
                    if action != '3' and state.get(kind):
                        wait_healthy(service, state[kind]['port'], protocol)
                    ok(service + '：' + command)
    else:
        warn('选项无效')


if __name__ == '__main__':
    try:
        main()
    except (DeployError, KeyboardInterrupt, EOFError) as exc:
        print('VH2: ' + str(exc), file=sys.stderr)
        sys.exit(1)
