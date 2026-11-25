"""Offline personal picker admission regression; no core/auth imports."""
import ast
from pathlib import Path
import runpy
import unittest
ROOT=Path(__file__).resolve().parents[1]

class PersonalPicker(unittest.TestCase):
    def test_explicit_personal_routes_and_capabilities(self):
        ns=runpy.run_path(str(ROOT/'model_catalog.py'))
        tree=ast.parse((ROOT/'__init__.py').read_text())
        selected: list[ast.stmt]=[n for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id in {'MODEL_METADATA','MODEL_CAPABILITIES','ALIASES'} for t in n.targets)]
        exec(compile(ast.Module(body=selected,type_ignores=[]),'personal-catalog-only','exec'),ns)
        self.assertEqual(set(ns['MODEL_METADATA']),{'claude-opus-5-5[1m]','claude-sonnet-5-5[1m]','claude-opus-4-8[1m]'})
        self.assertEqual(ns['ALIASES']['opus'],'claude-opus-5-5')
        self.assertEqual(ns['MODEL_METADATA']['claude-opus-4-8[1m]']['context_window'],1000000)
        for m in ['claude-opus-4-8','claude-opus-4-8[1m]']:
            self.assertTrue(ns['MODEL_CAPABILITIES'][m]['supports_vision'])
        self.assertNotIn('claude-fable-5-1[1m]',ns['MODEL_METADATA'])
    def test_existing_account_identity_guard_is_retained(self):
        text=(ROOT/'profile_policy.py').read_text()
        self.assertIn("HOME = Path('/home/raze/.hermes')",text)
        self.assertIn('identity_matches(status, declaration)',text)
        self.assertIn('model not in models',text)
        self.assertIn('requires an owner-stamped default-profile secret scope',text)
if __name__=='__main__':unittest.main()
