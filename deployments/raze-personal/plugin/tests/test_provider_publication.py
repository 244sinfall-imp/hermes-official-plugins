"""Synthetic publication regression: never expose a partially adapted live plugin tree."""
import importlib.util
import sys


def test_new_directory_namespace_avoids_resident_lazy_submodule(tmp_path):
    from providers import _user_module_name

    plugins = tmp_path / 'plugins'
    plugins.mkdir()
    old = plugins / 'adapter-staging-visible'
    old.mkdir()
    (old / '__init__.py').write_text('from .client import policy_name\n')
    (old / 'client.py').write_text("def policy_name(): return 'newo_policy'\n")
    home_key = str(tmp_path)
    first_name = _user_module_name(old, home_key)
    final = plugins / 'adapter-personal-v1'
    second_name = _user_module_name(final, home_key)
    assert first_name != second_name
    prefixes = (first_name, second_name)

    def load(path, name):
        spec = importlib.util.spec_from_file_location(
            name, path / '__init__.py', submodule_search_locations=[str(path)])
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module

    try:
        original = load(old, first_name)
        assert original.policy_name() == 'newo_policy'
        # Disk is corrected, but a parent-only hot reload retains its old lazy child.
        (old / 'client.py').write_text("def policy_name(): return 'profile_policy'\n")
        parent_reloaded = load(old, first_name)
        assert parent_reloaded.policy_name() == 'newo_policy'
        # Atomic publication under a new directory gives all siblings a fresh namespace.
        old.rename(final)
        published = load(final, second_name)
        assert published.policy_name() == 'profile_policy'
        assert original.policy_name() == 'newo_policy'
    finally:
        for name in list(sys.modules):
            if any(name == prefix or name.startswith(prefix + '.') for prefix in prefixes):
                sys.modules.pop(name, None)
