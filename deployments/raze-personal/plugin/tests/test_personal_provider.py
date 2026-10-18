"""Exercise public provider seams using the same offline guard as isolation tests."""
import runpy
from pathlib import Path

import pytest
import providers
import profile_policy as p
from test_personal_isolation import offline, account, forbidden, MODEL


@pytest.fixture
def provider(monkeypatch):
    # Core's lazy usage import probes its git version; suppress only that metadata probe.
    from hermes_cli import version_info
    monkeypatch.setattr(version_info, '_run_git', lambda *a, **kw: None)
    monkeypatch.setattr(providers, 'register_provider', lambda profile: None)
    return runpy.run_path(str(Path(__file__).resolve().parents[1] / '__init__.py'))['profile']


def test_usage_public_hook_disabled(provider, monkeypatch):
    monkeypatch.setattr(p, 'credentials', forbidden)
    snapshot = provider.fetch_account_usage()
    assert snapshot.unavailable_reason.startswith('Personal Claude quota helper disabled')


@pytest.mark.parametrize('method', ['setup_status', 'discover_models', 'create_client'])
def test_public_entrypoints_reject_foreign_owner(provider, method):
    from agent.secret_scope import set_secret_scope, reset_secret_scope
    token = set_secret_scope({}, profile_home='/foreign')
    try:
        with pytest.raises(p.PolicyError):
            getattr(provider, method)()
    finally:
        reset_secret_scope(token)


def test_client_denies_wrong_identity_before_process(provider, account, monkeypatch):
    monkeypatch.setattr(p, 'private_path', lambda *a, **kw: None)
    monkeypatch.setattr(p, 'binary', lambda: [str(p.BINARY)])
    client = provider.create_client()
    account[1]['orgId'] = 'foreign-org'
    try:
        with pytest.raises(p.PolicyError):
            client.chat.completions.create(model=MODEL, messages=[])
    finally:
        client.close()
