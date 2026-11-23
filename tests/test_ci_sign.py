import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import contextlib
import zipfile

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
def load(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
ci = load('ci_sign')
helper = load('sign_mac_builds')

class SigningSafetyTests(unittest.TestCase):
    def test_tag_rejects_shell_and_path_injection(self):
        for tag in ['../x', 'kit-1.1.3-715bd9c4; echo secret', '$(id)', '--help', 'kit-1.1.3-715bd9c4\n']:
            with self.assertRaises(ValueError):
                ci.validate_tag(tag)
        self.assertEqual(ci.validate_tag('kit-1.1.3-715bd9c4'), 'kit-1.1.3-715bd9c4')

    def test_diagnostics_redact_raw_and_encoded_credentials(self):
        self.assertEqual(ci.redact(b'raw-secret encoded-secret keep', [b'raw-secret', b'encoded-secret']),
                         b'[REDACTED] [REDACTED] keep')

    def make_kit(self, path, demo, commit='715bd9c4', extra=None):
        script = 'electron-builder --mac dir --universal --config.mac.notarize=true'
        if demo:
            script += ' --config.extraMetadata.taDemo=true'
        with zipfile.ZipFile(path, 'w') as z:
            z.writestr('package.json', json.dumps({'name':'traffic-architect','version':'1.1.3','scripts':{'mac:steam:signed':script}}))
            z.writestr('dist/build.json', json.dumps({'version':'1.1.3','commit':commit}))
            z.writestr('build-mac.sh','echo build')
            z.writestr('build/entitlements.mac.plist','plist')
            if extra:
                z.writestr(extra, 'bad')

    def test_pair_requires_same_build_and_distinct_products(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, b = Path(tmp)/'a.zip', Path(tmp)/'b.zip'
            self.make_kit(a, True)
            self.make_kit(b, False)
            self.assertEqual(len(ci.inspect_pair([a,b], helper)),2)
            self.make_kit(b, False, commit='12345678')
            with self.assertRaises(ValueError):ci.inspect_pair([a,b],helper)
            self.make_kit(b, True)
            with self.assertRaises(ValueError):ci.inspect_pair([a,b],helper)
            with self.assertRaises(ValueError):ci.inspect_pair([a],helper)

    def test_zip_escape_rejected_before_build(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'unsafe.zip'
            self.make_kit(path, True, extra='../leak')
            with self.assertRaises(ValueError):helper.kit_info(path)

    def test_process_failure_does_not_expose_private_output(self):
        with self.assertRaisesRegex(RuntimeError, '^Private operation failed$'):
            ci.checked(['python3','-c','print("private-code-secret"); raise SystemExit(1)'])

    def test_bad_request_does_not_echo_input_or_start_tools(self):
        env={k:'secret-value' for k in ci.REQUIRED}
        env.update(KIT_TAG='$(print-private-source)',GITHUB_RUN_ID='123',GITHUB_RUN_ATTEMPT='1')
        output=io.StringIO()
        with patch.dict(ci.os.environ,env,clear=True), patch.object(ci,'checked') as tool, contextlib.redirect_stdout(output):
            self.assertEqual(ci.main(),1)
        tool.assert_not_called()
        self.assertNotIn('print-private-source',output.getvalue())
        self.assertNotIn('secret-value',output.getvalue())

    def test_missing_secrets_stops_before_any_network_call(self):
        with patch.dict(ci.os.environ,{},clear=True), patch.object(ci,'checked') as tool, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(ci.main(),1)
        tool.assert_not_called()

    def test_no_credential_or_game_artifact_upload_action(self):
        workflow=(SCRIPTS.parent/'.github/workflows/sign.yml').read_text()
        self.assertNotIn('upload-artifact', workflow)
        self.assertNotIn('pull_request',workflow)
        self.assertIn('persist-credentials: false', workflow)

if __name__ == '__main__':unittest.main()
