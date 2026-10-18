"""Default-profile-only personal fail-closed policy. No tokens in environment or diagnostics.

Linux official CLI 2.1.292; patch is deliberately deployment-specific.
The public binary digest pins integrity, NOT account entitlement or billing.
"""
import hashlib
import hmac
import json
import os
from pathlib import Path
import stat
import subprocess

HOME = Path('/home/hermes/.hermes')
CONFIG = HOME / 'claude-config'
CLI_HOME = HOME / 'claude-home'
RUNTIME = HOME / 'claude-runtime'
BINARY = CLI_HOME / '.local/share/claude/versions/2.1.292'
BINARY_SHA256 = 'a967e7b1d8b4e47ee421d5433027880347952b0c0857abf880e2c942a4ec93b3'
PROVIDER = 'claude-subscription-directsdk-experimental'
ENDPOINT = 'https://api.anthropic.com'
SAFE_FLAGS = {
    'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC': '1', 'DISABLE_TELEMETRY': '1',
    'DISABLE_ERROR_REPORTING': '1', 'DISABLE_FEEDBACK_COMMAND': '1',
    'DISABLE_AUTOUPDATER': '1', 'DISABLE_UPDATES': '1',
    'CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY': '1',
    'CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL': '1',
}
PATH_KEYS = {'CLAUDE_CONFIG_DIR': str(CONFIG),
             'CLAUDE_SUBSCRIPTION_DIRECTSDK_CONFIG_DIR': str(CONFIG),
             'CLAUDE_SUBSCRIPTION_DIRECTSDK_COMMAND': str(BINARY)}
DANGEROUS_EXACT = {'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY',
                   'SSL_CERT_FILE', 'SSL_CERT_DIR', 'CURL_CA_BUNDLE',
                   'REQUESTS_CA_BUNDLE', 'NODE_EXTRA_CA_CERTS', 'BASH_ENV', 'ENV'}
DANGEROUS_PREFIXES = ('ANTHROPIC_', 'CLAUDE_', 'OTEL_', 'LD_', 'DYLD_',
                      'NODE_', 'BUN_', 'AWS_', 'GOOGLE_', 'GCP_', 'AZURE_')

class PolicyError(RuntimeError):
    pass

def scope():
    from hermes_constants import get_hermes_home
    from agent.secret_scope import (current_secret_scope, current_secret_scope_home,
                                    is_multiplex_active, serves_routed_profile)
    if Path(get_hermes_home()) != HOME:
        raise PolicyError('Claude DirectSDK is restricted to the default personal profile')
    bound = current_secret_scope()
    owner = current_secret_scope_home()
    if ((bound is not None and owner != str(HOME)) or
            ((is_multiplex_active() or serves_routed_profile()) and bound is None)):
        raise PolicyError('Claude DirectSDK requires an owner-stamped default-profile secret scope')
    if owner is not None and owner != str(HOME):
        raise PolicyError('Claude secret scope belongs to another profile')
    return bound

def validate_env(values):
    # Unknown native selectors fail closed, even values such as "0". Only explicit safe
    # switches and exact deployment paths are permitted. Names, never values, in errors.
    allowed = {**SAFE_FLAGS, **PATH_KEYS}
    bad = []
    for key, value in values.items():
        if not value:
            continue
        upper = key.upper()
        if upper in allowed:
            if key != upper or value != allowed[upper]:
                bad.append(key)
        elif upper in DANGEROUS_EXACT or upper.startswith(DANGEROUS_PREFIXES):
            bad.append(key)
    if bad:
        raise PolicyError('Unsafe Claude environment variables: ' + ', '.join(sorted(bad)))

def private_path(path, mode, directory=False):
    try:
        info = path.lstat()
    except OSError:
        raise PolicyError('Required private Claude state is unavailable') from None
    if (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)) is False:
        raise PolicyError('Claude state must be a real file/directory, not a symlink')
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != mode:
        raise PolicyError('Claude state ownership or private permissions are invalid')
    return info

def binary():
    scope()
    # Check every path segment below the profile. No launcher symlink/PATH resolution.
    for parent in BINARY.parents:
        if parent == HOME:
            break
        if parent.is_symlink():
            raise PolicyError('Claude binary path contains a symlink')
    info = BINARY.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise PolicyError('Untrusted Claude binary ownership or permissions')
    digest = hashlib.sha256(BINARY.read_bytes()).hexdigest()
    if not hmac.compare_digest(digest, BINARY_SHA256):
        raise PolicyError('Claude binary failed the pinned official release digest')
    return [str(BINARY)]

def environment(explicit=None):
    bound = scope()
    # No ambient credentials from launch profile in a multiplexed process. In a
    # standalone owner process get_secret observes the supported dotenv overlay.
    source = dict(bound) if bound is not None else dict(os.environ)
    validate_env(source)
    if explicit is not None:
        validate_env(explicit)
        # env cannot change HOME, paths, loader behavior, or supply unreviewed switches.
        safe_os = {'PATH': '/usr/bin:/bin', 'HOME': str(CLI_HOME),
                   'LANG': 'C.UTF-8', 'XDG_CONFIG_HOME': str(CLI_HOME / '.config'),
                   'TMPDIR': str(RUNTIME)}
        allowed = {**safe_os, **PATH_KEYS, **SAFE_FLAGS}
        if any(key not in allowed or value != allowed[key] for key, value in explicit.items()):
            raise PolicyError('Explicit Claude client environment is not the pinned environment')
    for key, expected in PATH_KEYS.items():
        if source.get(key) != expected:
            raise PolicyError('The default profile must configure matching private Claude paths in its secret scope')
    for directory in (CONFIG, CLI_HOME, RUNTIME):
        private_path(directory, 0o700, directory=True)
    child = {'PATH': '/usr/bin:/bin', 'HOME': str(CLI_HOME), 'LANG': 'C.UTF-8',
             'XDG_CONFIG_HOME': str(CLI_HOME / '.config'), 'TMPDIR': str(RUNTIME),
             'CLAUDE_CONFIG_DIR': str(CONFIG), **SAFE_FLAGS}
    return child

def validate_command(command=None, args=None):
    trusted = binary()
    candidate = [command] if isinstance(command, str) else list(command or trusted)
    if candidate != trusted or args:
        raise PolicyError('Only the pinned original Claude binary without caller arguments is allowed')
    return trusted

def policy():
    scope()
    target = HOME / 'claude-policy.json'
    private_path(target, 0o600)
    try:
        declaration = json.loads(target.read_text())
        if not isinstance(declaration, dict):
            raise PolicyError('Claude activation policy must be an object')
        return declaration
    except (ValueError, OSError):
        raise PolicyError('Claude activation policy is unreadable') from None

def credentials():
    scope()
    target = CONFIG / '.credentials.json'
    private_path(target, 0o600)
    try:
        raw = json.loads(target.read_text())
    except (OSError, ValueError):
        raise PolicyError('Claude credentials are unreadable') from None
    if not isinstance(raw, dict) or set(raw) != {'claudeAiOauth'}:
        raise PolicyError('Only the private claude.ai OAuth credential record is accepted')
    oauth = raw['claudeAiOauth']
    token = oauth.get('accessToken') if isinstance(oauth, dict) else None
    if not isinstance(token, str) or not token.startswith('sk-ant-oat01-') or any(c.isspace() for c in token):
        raise PolicyError('Private Claude OAuth credential is unavailable')
    return oauth

def auth_status(env=None):
    child = environment(env)
    result = subprocess.run(binary() + ['auth', 'status', '--json'], env=child,
                            cwd=str(RUNTIME), stdin=subprocess.DEVNULL, capture_output=True,
                            text=True, timeout=20)
    try:
        data = json.loads(result.stdout)
    except ValueError:
        raise PolicyError('Claude auth status returned an unreadable response') from None
    if result.returncode != 0 or not isinstance(data, dict):
        raise PolicyError('Claude auth status failed or returned an invalid response')
    return data

def identity_matches(status, declaration):
    # Field paths come from the real authenticated CLI output and owner
    # confirmation. Never guess organization IDs or derive them from token prefixes.
    pins = declaration.get('identity_pins', {})
    if not isinstance(pins, dict) or set(pins) != {'email', 'organization'}:
        raise PolicyError('Owner-confirmed email and organization pins are required')
    for pin in pins.values():
        if not isinstance(pin, dict):
            raise PolicyError('Identity pin must be an owner-confirmed object')
        path, expected = pin.get('path'), pin.get('value')
        if (not isinstance(path, list) or not path or
                not all(isinstance(key, str) and key for key in path) or
                not isinstance(expected, str) or not expected):
            raise PolicyError('Identity pin requires a confirmed CLI field path and value')
        value = status
        for key in path:
            value = value.get(key) if isinstance(value, dict) else None
        if value != expected:
            raise PolicyError('Claude personal identity does not match the confirmed account')

def ready(model=None):
    declaration = policy()
    if declaration.get('activated') is not True:
        raise PolicyError('Claude activation is pending owner OAuth and explicit routing approval; default model routing is unchanged')
    models = declaration.get('approved_models')
    if (not isinstance(models, list) or not models or
            not all(isinstance(item, str) and item for item in models)):
        raise PolicyError('An explicit nonempty owner-approved model list is required')
    if model is not None and model not in models:
        raise PolicyError('Claude model lacks owner-confirmed subscription entitlement')
    credentials()
    status = auth_status()
    if status.get('loggedIn') is not True or status.get('authMethod') != 'claude.ai' or status.get('apiProvider') != 'firstParty':
        raise PolicyError('Claude requires the confirmed first-party claude.ai login')
    # Tariff is optional informational metadata, never an account/profile invariant.
    # Native refresh may omit it and legitimate plan changes do not change identity.
    if status.get('configDirectory') != str(CONFIG):
        raise PolicyError('Claude auth status reports a different config directory')
    identity_matches(status, declaration)
    return status

def validate_endpoint(upstream):
    scope()
    if upstream != ENDPOINT:
        raise PolicyError('Claude outbound inference endpoint must be https://api.anthropic.com')

def validate_headers(headers):
    # Native auth passes through unmodified. No spoofed identity/beta/User-Agent.
    if headers.get_all('x-api-key') or headers.get_all('proxy-authorization'):
        raise PolicyError('Claude native API-key/proxy authentication is forbidden')
    auth = headers.get_all('Authorization') or []
    token = credentials()['accessToken']
    if len(auth) != 1 or not hmac.compare_digest(auth[0], 'Bearer ' + token):
        raise PolicyError('Claude native authorization does not match private OAuth credentials')

def usage_token():
    # Kept disabled: no credentials opened, no user-agent impersonation, no HTTP call.
    scope()
    return None, 'Personal Claude quota helper disabled; use the scoped official CLI for account metadata'
