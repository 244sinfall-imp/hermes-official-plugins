"""Deployment acceptance: synthetic state only; no real auth, CLI, or network."""
import copy
import builtins
import io
import os
import json
import ast
from concurrent.futures import ThreadPoolExecutor
from email.message import Message
import hashlib
from pathlib import Path
import socket
import subprocess
from types import SimpleNamespace

import pytest
import hermes_constants
from agent import secret_scope as scopes
import profile_policy as p

MODEL = 'claude-opus-5-5[1m]'


def forbidden(*args, **kwargs):
    raise AssertionError('Offline acceptance must not spawn a process or connect to a network')


@pytest.fixture(autouse=True)
def offline(monkeypatch, tmp_path):
    # Tripwires intercept BEFORE real private state can be opened, including Path I/O.
    protected = ('/home/hermes/.hermes/config.yaml', '/home/hermes/.hermes/.env',
                 '/home/hermes/.hermes/auth.json', '/home/hermes/.hermes/claude-policy.json',
                 '/home/hermes/.hermes/claude-config',
                 '/home/hermes/.hermes/claude-home',
                 '/home/hermes/.hermes/claude-runtime',
                 '/home/hermes/.hermes/profiles/newo')
    def guard(original):
        def checked(path, *args, **kwargs):
            if not isinstance(path, int):
                candidate = os.path.abspath(os.fsdecode(path))
                if any(candidate == root or candidate.startswith(root + '/') for root in protected):
                    raise AssertionError('Offline acceptance blocked real private-state access')
            return original(path, *args, **kwargs)
        return checked
    for module in (builtins, io, os):
        monkeypatch.setattr(module, 'open', guard(module.open))
    monkeypatch.setattr(socket.socket, 'connect', forbidden)
    monkeypatch.setattr(socket.socket, 'connect_ex', forbidden)
    monkeypatch.setattr(socket, 'create_connection', forbidden)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    monkeypatch.setattr(hermes_constants, 'get_hermes_home', lambda: p.HOME)
    monkeypatch.setattr(scopes, '_MULTIPLEX_ACTIVE', False)
    monkeypatch.setattr(scopes, 'serves_routed_profile', lambda: scopes.is_multiplex_active())
    monkeypatch.setenv('TMPDIR', str(tmp_path))
    token = scopes.set_secret_scope(dict(p.PATH_KEYS), profile_home=str(p.HOME))
    try:
        yield
    finally:
        scopes.reset_secret_scope(token)


@pytest.fixture
def account(monkeypatch):
    declaration = {'activated': True, 'subscription_type': 'pro', 'approved_models': [MODEL],
                   'identity_pins': {'email': {'path': ['email'], 'value': 'owner@example.invalid'},
                                     'organization': {'path': ['orgId'], 'value': 'synthetic-personal-org'}}}
    status = {'loggedIn': True, 'authMethod': 'claude.ai', 'apiProvider': 'firstParty',
              'subscriptionType': 'pro', 'configDirectory': str(p.CONFIG),
              'email': 'owner@example.invalid', 'orgId': 'synthetic-personal-org'}
    monkeypatch.setattr(p, 'policy', lambda: declaration)
    monkeypatch.setattr(p, 'credentials', lambda: {'accessToken': 'synthetic-native-token'})
    monkeypatch.setattr(p, 'auth_status', lambda env=None: status)
    return declaration, status


def test_pinned_default_paths():
    assert p.HOME == Path('/home/hermes/.hermes')
    assert p.CONFIG == p.HOME / 'claude-config'
    assert p.CLI_HOME == p.HOME / 'claude-home'
    assert p.RUNTIME == p.HOME / 'claude-runtime'
    assert p.BINARY == p.CLI_HOME / '.local/share/claude/versions/2.1.292'


@pytest.mark.parametrize('home', ['/home/hermes/.hermes/profiles/newo', '/other'])
def test_foreign_profile_rejected(monkeypatch, home):
    monkeypatch.setattr(hermes_constants, 'get_hermes_home', lambda: Path(home))
    with pytest.raises(p.PolicyError):
        p.scope()


@pytest.mark.parametrize('multiplex', [False, True])
@pytest.mark.parametrize('owner', [None, '/home/hermes/.hermes/profiles/newo', '/other'])
def test_foreign_or_unstamped_scope_rejected(monkeypatch, owner, multiplex):
    monkeypatch.setattr(scopes, '_MULTIPLEX_ACTIVE', multiplex)
    token = scopes.set_secret_scope({}, profile_home=owner)
    try:

        with pytest.raises(p.PolicyError):
            p.scope()
    finally:
        scopes.reset_secret_scope(token)


def test_default_multiplex_requires_owner_even_when_mapping_empty(monkeypatch):
    monkeypatch.setattr(scopes, '_MULTIPLEX_ACTIVE', True)
    token = scopes.set_secret_scope(None)
    try:
        with pytest.raises(p.PolicyError):
            p.scope()
    finally:
        scopes.reset_secret_scope(token)
    assert p.scope() == p.PATH_KEYS


@pytest.mark.parametrize('key,value', [
    ('CLAUDE_CONFIG_DIR', '/foreign'), ('CLAUDE_SUBSCRIPTION_DIRECTSDK_CONFIG_DIR', '/foreign'),
    ('CLAUDE_SUBSCRIPTION_DIRECTSDK_COMMAND', '/foreign/claude'),
    ('ANTHROPIC_API_KEY', 'synthetic'), ('ANTHROPIC_BASE_URL', 'https://foreign.invalid'),
    ('CLAUDE_CODE_OAUTH_TOKEN', 'synthetic'), ('CLAUDE_CODE_USE_BEDROCK', '0'),
    ('HTTPS_PROXY', 'http://foreign.invalid'), ('http_proxy', 'http://foreign.invalid'),
    ('NODE_OPTIONS', '--require foreign'), ('LD_PRELOAD', 'foreign'),
    ('CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC', '0')])
def test_environment_selectors_rejected(key, value):
    with pytest.raises(p.PolicyError) as error:
        p.validate_env({key: value})
    assert value not in str(error.value)


def test_minimal_environment_no_ambient_fallback(monkeypatch):
    monkeypatch.setattr(scopes, '_MULTIPLEX_ACTIVE', True)
    monkeypatch.setattr(p, 'private_path', lambda *args, **kwargs: None)
    monkeypatch.setenv('ANTHROPIC_API_KEY', 'foreign-ambient-synthetic')
    child = p.environment()
    assert child == {'PATH': '/usr/bin:/bin', 'HOME': str(p.CLI_HOME), 'LANG': 'C.UTF-8',
                     'XDG_CONFIG_HOME': str(p.CLI_HOME / '.config'), 'TMPDIR': str(p.RUNTIME),
                     'CLAUDE_CONFIG_DIR': str(p.CONFIG), **p.SAFE_FLAGS}
    token = scopes.set_secret_scope({}, profile_home=str(p.HOME))
    try:
        with pytest.raises(p.PolicyError):
            p.environment()
    finally:
        scopes.reset_secret_scope(token)
    for explicit in ({'HOME': '/foreign'}, {'PATH': '/foreign'}, {'UNREVIEWED': '1'}):
        with pytest.raises(p.PolicyError):
            p.environment(explicit)


@pytest.mark.parametrize('plan', ['pro', 'max'])
def test_matching_personal_plan_accepted(account, plan):
    declaration, status = account
    declaration['subscription_type'] = status['subscriptionType'] = plan
    assert p.ready(MODEL) is status


@pytest.mark.parametrize('field,value', [
    ('loggedIn', False), ('authMethod', 'apiKey'), ('apiProvider', 'bedrock'),
    ('configDirectory', '/foreign'), ('email', 'foreign@example.invalid'), ('orgId', 'foreign-org')])
def test_wrong_auth_config_identity_rejected(account, field, value):
    account[1][field] = value
    with pytest.raises(p.PolicyError):
        p.ready(MODEL)


@pytest.mark.parametrize('plan', [None, '', 'enterprise', 'team', 'Pro'])
def test_plan_not_inferred(account, plan):
    account[0]['subscription_type'] = plan
    before = copy.deepcopy(account)
    assert p.ready(MODEL) is account[1]
    assert account == before  # No plan guessing or credential/policy metadata writes.


@pytest.mark.parametrize('plan', [None, 'max', 'future_personal_tier', 'enterprise', 'team'])
def test_tariff_metadata_is_not_admission(account, plan):
    account[1]['subscriptionType'] = plan
    before = copy.deepcopy(account)
    assert p.ready(MODEL) is account[1]
    assert account == before


def test_missing_tariff_fields_accepted_without_inference(account):
    account[0].pop('subscription_type')
    account[1].pop('subscriptionType')
    before = copy.deepcopy(account)
    assert p.ready(MODEL) is account[1]
    assert account == before


@pytest.mark.parametrize('field', ['email', 'orgId'])
@pytest.mark.parametrize('value', [None, '', {}, [], 'foreign@example.invalid'])
def test_missing_or_malformed_identity_rejected_with_unknown_tariff(account, field, value):
    account[1]['subscriptionType'] = None
    account[1][field] = value
    with pytest.raises(p.PolicyError, match='identity'):
        p.ready(MODEL)


@pytest.mark.parametrize('plan,label', [(None, ''), ('max', 'Claude Max'),
                                       ('future_personal_tier', 'Claude Future Personal Tier')])
def test_setup_tariff_is_optional_information(account, monkeypatch, plan, label):
    import directsdk_setup as setup
    monkeypatch.setattr(p, 'environment', lambda env=None: {})
    monkeypatch.setattr(p, 'validate_command', lambda cmd=None: ['synthetic-never-executed'])
    account[1]['subscriptionType'] = plan
    assert setup.setup_status()['plan'] == label


@pytest.mark.parametrize('pins', [{}, {'email': {}}, None, {'email': None, 'organization': {}},
                                 {'email': {'path': ['email'], 'value': 'owner@example.invalid'},
                                  'organization': {'path': ['missing'], 'value': 'synthetic-personal-org'}}])
def test_both_identity_pins_mandatory(account, pins):
    account[0]['identity_pins'] = pins
    with pytest.raises(p.PolicyError):
        p.ready(MODEL)


@pytest.mark.parametrize('models', [None, [], MODEL, {'other': True}])
def test_approved_models_must_be_explicit_list(account, models):
    account[0]['approved_models'] = models
    with pytest.raises(p.PolicyError):
        p.ready(MODEL)


def test_pending_or_unapproved_rejected(account):
    with pytest.raises(p.PolicyError):
        p.ready('foreign-model')
    account[0]['activated'] = False
    with pytest.raises(p.PolicyError):
        p.ready(MODEL)


def test_missing_policy_and_credential_files_no_fallback(monkeypatch, tmp_path):
    monkeypatch.setattr(p, 'scope', lambda: None)
    monkeypatch.setattr(p, 'HOME', tmp_path)
    monkeypatch.setattr(p, 'CONFIG', tmp_path / 'missing-config')
    for operation in (p.policy, p.credentials):
        with pytest.raises(p.PolicyError):
            operation()


def test_private_path_and_pinned_binary(monkeypatch, tmp_path):
    path = tmp_path / 'binary'
    path.write_bytes(b'synthetic-test-binary-never-executed')
    path.chmod(0o600)
    p.private_path(path, 0o600)
    with pytest.raises(p.PolicyError):
        p.private_path(path, 0o700)
    link = tmp_path / 'link'
    link.symlink_to(path)
    with pytest.raises(p.PolicyError):
        p.private_path(link, 0o600)
    monkeypatch.setattr(p, 'BINARY', path)
    monkeypatch.setattr(p, 'BINARY_SHA256', hashlib.sha256(path.read_bytes()).hexdigest())
    assert p.validate_command() == [str(path)]
    for command, args in [('/foreign', None), (str(path), ['--foreign'])]:
        with pytest.raises(p.PolicyError):
            p.validate_command(command, args)
    path.write_bytes(b'tampered')
    with pytest.raises(p.PolicyError):
        p.binary()


def headers(token='synthetic-native-token'):
    result = Message()
    result['Authorization'] = 'Bearer ' + token
    return result


def test_native_headers_exact_and_rotation(account):
    p.validate_headers(headers())
    for name in ['x-api-key', 'proxy-authorization', 'Authorization']:
        bad = headers()
        bad[name] = 'foreign'
        with pytest.raises(p.PolicyError):
            p.validate_headers(bad)
    with pytest.raises(p.PolicyError):
        p.validate_headers(headers('foreign'))
    account[0]['activated'] = True


def test_native_header_rotation_rereads_credentials(account, monkeypatch):
    current = {'accessToken': 'synthetic-native-token'}
    monkeypatch.setattr(p, 'credentials', lambda: current)
    p.validate_headers(headers())
    current['accessToken'] = 'synthetic-rotated-token'
    with pytest.raises(p.PolicyError):
        p.validate_headers(headers())
    p.validate_headers(headers('synthetic-rotated-token'))


def test_real_private_state_open_tripwire():
    with pytest.raises(AssertionError, match='private-state'):
        (p.CONFIG / '.credentials.json').read_text()
    with pytest.raises(AssertionError, match='private-state'):
        (p.HOME / 'claude-policy.json').read_text()


@pytest.mark.parametrize('field', ['email', 'orgId'])
def test_absent_identity_rejected(account, field):
    account[1]['subscriptionType'] = None
    account[1].pop(field)
    with pytest.raises(p.PolicyError, match='identity'):
        p.ready(MODEL)


def test_baseline_origin_and_package_closure():
    root = Path(__file__).resolve().parents[1]
    baseline = json.loads((root.parent / 'baseline-manifest.json').read_text())
    assert baseline['upstream_main'] == 'f98c0999c6dd4e59680addc8f3480208018ab5b0'
    assert baseline['catalog_pin'] == '6dacaaddbfd8e98dfc524096c44f712f743246b8'
    assert baseline['actual_baseline']['pyproject_version'] == '0.3.1'
    assert baseline['actual_baseline']['plugin_manifest_version'] == '0.3.2'
    assert baseline['actual_baseline']['git_repository'] is False
    entries = {entry['path']: entry for entry in baseline['files']}
    assert len(entries) == len(baseline['files']) == 34
    actual = {str(file.relative_to(root)) for file in root.rglob('*')
              if file.is_file() and '__pycache__' not in file.parts}
    assert actual == set(entries)
    changed = {'profile_policy.py', 'README.md', 'pyproject.toml', 'plugin.yaml',
               'tests/test_personal_isolation.py', 'tests/test_personal_provider.py'}
    for name, entry in entries.items():
        if name not in changed:
            assert hashlib.sha256((root / name).read_bytes()).hexdigest() == entry['sha256']
    local = {'admission', 'directsdk', 'directsdk_setup', 'inert_mcp', 'model_catalog', 'profile_policy'}
    for file in root.glob('*.py'):
        for node in ast.walk(ast.parse(file.read_text())):
            if isinstance(node, ast.ImportFrom):
                if node.level and node.module is None:
                    names = {alias.name for alias in node.names}
                else:
                    names = {node.module.split('.')[0]} if node.module else set()
                for name in names & local:
                    assert name + '.py' in entries


def test_admission_header_guard_keeps_owner_context(account, monkeypatch):
    from admission import Admission
    monkeypatch.setattr(scopes, '_MULTIPLEX_ACTIVE', True)
    original = p.credentials
    def scoped_credentials():
        p.scope()
        return original()
    monkeypatch.setattr(p, 'credentials', scoped_credentials)
    gate = Admission(p.ENDPOINT, 1)
    token = scopes.set_secret_scope({}, profile_home='/foreign')
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            pool.submit(gate.header_guard, headers()).result()
            with pytest.raises(p.PolicyError):
                pool.submit(gate.header_guard, headers('foreign')).result()
        assert not gate.used
    finally:
        scopes.reset_secret_scope(token)
        gate.close()


@pytest.mark.parametrize('endpoint', ['https://foreign.invalid', p.ENDPOINT + '/', 'http://api.anthropic.com'])
def test_fixed_endpoint(endpoint):
    with pytest.raises(p.PolicyError):
        p.validate_endpoint(endpoint)


def test_usage_disabled_without_credential_read(monkeypatch):
    monkeypatch.setattr(p, 'credentials', forbidden)
    assert p.usage_token()[0] is None


def test_discovery_denies_before_any_cli_or_network(monkeypatch, account):
    import directsdk_setup as setup
    monkeypatch.setattr(p, 'environment', lambda env=None: {})
    monkeypatch.setattr(p, 'validate_command', lambda cmd=None: ['never-executed'])
    account[1]['email'] = 'foreign@example.invalid'
    with pytest.raises(p.PolicyError):
        setup.discover_models()


def test_setup_auth_status_command_is_private(monkeypatch):
    child = {'HOME': 'synthetic-home'}
    monkeypatch.setattr(p, 'environment', lambda env=None: child)
    monkeypatch.setattr(p, 'binary', lambda: ['synthetic-never-executed'])
    def fake_run(argv, **kwargs):
        assert argv == ['synthetic-never-executed', 'auth', 'status', '--json']
        assert kwargs['env'] is child and kwargs['cwd'] == str(p.RUNTIME)
        return SimpleNamespace(stdout='{}', returncode=0)
    monkeypatch.setattr(p.subprocess, 'run', fake_run)
    assert p.auth_status() == {}
    monkeypatch.setattr(p.subprocess, 'run', lambda *a, **kw: SimpleNamespace(stdout='{}', returncode=1))
    with pytest.raises(p.PolicyError):
        p.auth_status()
