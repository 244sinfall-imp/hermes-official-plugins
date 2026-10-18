"""Exercise public provider seams using the same offline guard as isolation tests."""
import runpy
from pathlib import Path

import pytest
import providers
import profile_policy as p
from test_personal_isolation import offline, account, forbidden, MODEL


@pytest.fixture
def provider(monkeypatch):
    # Match core's own test fixture: avoid both helper and direct Git probes
    # when an isolated checkout has no installed build-metadata stamp.
    from hermes_cli import version_info
    monkeypatch.setattr(version_info, '_cached_version_info', version_info.VersionInfo(
        'unknown', 'git.0000000', None, '0' * 40, 'main', 'git'))
    # A lazy account_usage -> auth -> config import enumerates providers; keep that
    # unrelated metadata hook away from real config and installed plugin discovery.
    monkeypatch.setattr(providers, 'list_providers', lambda: [])
    monkeypatch.setattr(providers, 'register_provider', lambda profile: None)
    return runpy.run_path(str(Path(__file__).resolve().parents[1] / '__init__.py'))['profile']


def test_usage_public_hook_disabled(provider, monkeypatch):
    monkeypatch.setattr(p, 'credentials', forbidden)
    snapshot = provider.fetch_account_usage()
    assert snapshot.unavailable_reason.startswith('Personal Claude quota helper disabled')


@pytest.mark.parametrize('method', ['setup_status', 'discover_models', 'create_client'])
@pytest.mark.parametrize('owner', ['/foreign', '/home/hermes/.hermes/profiles/newo'])
def test_public_entrypoints_reject_foreign_owner(provider, method, owner):
    from agent.secret_scope import set_secret_scope, reset_secret_scope
    token = set_secret_scope({}, profile_home=owner)
    try:
        with pytest.raises(p.PolicyError):
            getattr(provider, method)()
    finally:
        reset_secret_scope(token)


@pytest.mark.parametrize('field,value', [('email', 'foreign@example.invalid'), ('orgId', 'foreign-org')])
def test_client_denies_wrong_identity_before_process(provider, account, monkeypatch, field, value):
    monkeypatch.setattr(p, 'private_path', lambda *a, **kw: None)
    monkeypatch.setattr(p, 'binary', lambda: [str(p.BINARY)])
    client = provider.create_client()
    account[1]['subscriptionType'] = None
    account[1][field] = value
    try:
        with pytest.raises(p.PolicyError, match='identity'):
            client.chat.completions.create(model=MODEL, messages=[])
    finally:
        client.close()
