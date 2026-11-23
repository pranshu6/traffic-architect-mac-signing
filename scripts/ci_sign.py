#!/usr/bin/env python3
"""Keep all game files and subprocess output out of public Actions logs/artifacts.
Only repository writers should be allowed to dispatch trusted game kits.
"""
import base64
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import zipfile

PRIVATE_REPO = 'pranshu6/traffic-architect-mac-builds'
DIAGNOSTICS = None
REQUIRED = ('PRIVATE_BUILDS_TOKEN', 'APPLE_CERTIFICATE_BASE64',
            'APPLE_CERTIFICATE_PASSWORD', 'APPLE_API_KEY_BASE64',
            'APPLE_API_KEY_ID', 'APPLE_API_ISSUER')


def validate_tag(tag):
    if not re.fullmatch(r'kit-\d+\.\d+\.\d+-[a-fA-F0-9]{7,40}', tag):
        raise ValueError('Invalid kit tag')
    return tag


def redact(data, sensitive):
    for value in sorted(set(sensitive), key=len, reverse=True):
        if value:
            data = data.replace(value, b'[REDACTED]')
    return data


def checked(args, *, env=None, cwd=None, timeout=180, stdin=None, allow_existing_certificate=False):
    # Never inherit stdout/stderr: inputs, npm output, paths and tool errors are private.
    result = subprocess.run(args, cwd=cwd, env=env, input=stdin,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            timeout=timeout)
    if result.returncode:
        if allow_existing_certificate and b'SecKeychainItemImport: The specified item already exists in the keychain.' in result.stdout:
            return result.stdout
        if DIAGNOSTICS:
            with DIAGNOSTICS.open('ab') as log:
                log.write(result.stdout + b'\n')
        raise RuntimeError('Private operation failed')
    return result.stdout


def inspect_pair(paths, helper):
    if len(paths) != 2:
        raise ValueError('Exactly two kit ZIPs are required')
    infos = [helper.kit_info(path) for path in paths]
    if len({(i['version'], i['commit']) for i in infos}) != 1 or {i['demo'] for i in infos} != {True, False}:
        raise ValueError('Kits must be a matching demo and full pair')
    return infos


def main():
    # Public messages below are fixed strings only. Never print exception text.
    global DIAGNOSTICS
    root = Path(__file__).resolve().parent
    missing = [key for key in REQUIRED if not os.environ.get(key)]
    if missing:
        print('Setup incomplete: add all required repository secrets. See README.')
        return 1
    try:
        tag = validate_tag(os.environ.get('KIT_TAG', ''))
        run_id = os.environ['GITHUB_RUN_ID']
        attempt = os.environ['GITHUB_RUN_ATTEMPT']
        if not run_id.isdecimal() or not attempt.isdecimal():
            raise ValueError('Invalid run ID')
    except Exception:
        print('Invalid signing request. No build started.')
        return 1
    private_env = dict(os.environ, GH_TOKEN=os.environ['PRIVATE_BUILDS_TOKEN'], GH_PROMPT_DISABLED='1')
    # The vendor's build does not need any GitHub token or certificate-import password.
    build_env = {k: v for k, v in os.environ.items() if k not in REQUIRED and k not in ('GH_TOKEN', 'GITHUB_TOKEN')}
    keychain = None
    old_keychains = None
    sensitive = [os.environ[k].encode() for k in REQUIRED]
    success = False
    with tempfile.TemporaryDirectory(prefix='ta-private-', dir=os.environ.get('RUNNER_TEMP')) as tmp:
        work = Path(tmp)
        DIAGNOSTICS = work / 'setup.log'
        stage = 'private kit access'
        try:
            os.chmod(work, 0o700)
            inputs = work / 'inputs'
            inputs.mkdir()
            print('Fetching private kits...', flush=True)
            checked(['gh', 'release', 'download', tag, '--repo', PRIVATE_REPO,
                     '--pattern', '*mac-kit.zip', '--dir', str(inputs)], env=private_env)
            spec = importlib.util.spec_from_file_location('helper', root / 'sign_mac_builds.py')
            helper = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(helper)
            paths = sorted(inputs.glob('*.zip'))
            infos = inspect_pair(paths, helper)
            expected_tag = 'kit-' + infos[0]['version'] + '-' + infos[0]['commit']
            if tag != expected_tag:
                raise ValueError('Tag and kit metadata differ')
            stage = 'temporary signing credential setup'
            # Copy helper into temporary private work, away from checked-out public source.
            shutil.copyfile(root / 'sign_mac_builds.py', work / 'sign_mac_builds.py')
            (work / 'settings.json').write_text(json.dumps({'cache_root': str(work / 'cache')}))
            api_key = base64.b64decode(os.environ['APPLE_API_KEY_BASE64'], validate=True)
            certificate = base64.b64decode(os.environ['APPLE_CERTIFICATE_BASE64'], validate=True)
            sensitive.extend([api_key, certificate])
            key = work / 'AuthKey.p8'
            cert = work / 'certificate.p12'
            key.write_bytes(api_key)
            cert.write_bytes(certificate)
            key.chmod(0o600)
            cert.chmod(0o600)
            import shlex
            (work / 'signing.env').write_text('\n'.join(k + '=' + shlex.quote(v) for k, v in {
                'APPLE_API_KEY': str(key), 'APPLE_API_KEY_ID': os.environ['APPLE_API_KEY_ID'],
                'APPLE_API_ISSUER': os.environ['APPLE_API_ISSUER']}.items()) + '\n')
            (work / 'signing.env').chmod(0o600)
            keychain = work / 'signing.keychain-db'
            keychain_password = secrets.token_urlsafe(32)
            sensitive.append(keychain_password.encode())
            old_keychains = checked(['security', 'list-keychains', '-d', 'user'])
            checked(['security', 'create-keychain', '-p', keychain_password, str(keychain)])
            checked(['security', 'set-keychain-settings', '-lut', '21600', str(keychain)])
            checked(['security', 'unlock-keychain', '-p', keychain_password, str(keychain)])
            checked(['security', 'import', str(cert), '-P', os.environ['APPLE_CERTIFICATE_PASSWORD'],
                     '-A', '-t', 'cert', '-f', 'pkcs12', '-k', str(keychain)])
            checked(['security', 'set-key-partition-list', '-S', 'apple-tool:,apple:',
                     '-s', '-k', keychain_password, str(keychain)])
            checked(['security', 'list-keychains', '-d', 'user', '-s', str(keychain), *shlex.split(old_keychains.decode())])
            # Import Apple's public intermediate into the temporary keychain.
            intermediate = work / 'DeveloperIDG2CA.cer'
            checked(['curl', '--fail', '--silent', '--show-error', '--location', '--max-time', '60',
                     'https://www.apple.com/certificateauthority/DeveloperIDG2CA.cer', '-o', str(intermediate)])
            checked(['security', 'import', str(intermediate), '-k', str(keychain)], allow_existing_certificate=True)
            cert.unlink()
            # Avoid Finder interaction on a headless runner.
            source = (work / 'sign_mac_builds.py').read_text()
            source = source.replace("if sys.platform == 'darwin':", 'if False:  # headless CI')
            (work / 'sign_mac_builds.py').write_text(source)
            stage = 'build and Apple notarization'
            print('Building, signing and checking Apple notarization. Detailed output stays private.', flush=True)
            with (work / 'build-output.log').open('wb') as output:
                process = subprocess.Popen([sys.executable, str(work / 'sign_mac_builds.py'), *map(str, paths)],
                                           cwd=work, env=build_env, stdout=output, stderr=subprocess.STDOUT)
                # Heartbeats have no game data. No automatic rebuild or resubmission.
                import time
                deadline = time.monotonic() + 100 * 60
                while process.poll() is None:
                    if time.monotonic() >= deadline:
                        process.terminate()
                        process.wait(timeout=20)
                        raise RuntimeError('Build timeout')
                    time.sleep(20)
                    print('Signing job is still running; no user action needed.', flush=True)
                if process.returncode:
                    raise RuntimeError('Signing failed')
            results = [json.loads(p.read_text()) for p in (work / 'Builds').glob('*/SIGNING_RESULT.json')]
            if len(results) != 2 or {r['demo'] for r in results} != {True, False}:
                raise ValueError('Missing verified archives')
            outputs = work / 'outputs'
            outputs.mkdir()
            for result in results:
                archive = Path(result['archive'])
                shutil.copyfile(archive, outputs / archive.name)
                result['archive'] = archive.name
            (outputs / 'SIGNING_RESULTS.json').write_text(json.dumps(results, indent=2) + '\n')
            stage = 'saving private downloads'
            out_tag = 'signed-' + tag[4:] + '-' + run_id + '-' + attempt
            checked(['gh', 'release', 'create', out_tag, '--repo', PRIVATE_REPO,
                     '--title', 'Verified Mac builds ' + tag[4:], '--notes',
                     'Both demo and full builds passed packaged metadata, Intel/Apple Silicon, signature, Gatekeeper and notarization ticket checks after archive extraction.',
                     *map(str, sorted(outputs.iterdir()))], env=private_env, timeout=600)
            success = True
            summary = os.environ.get('GITHUB_STEP_SUMMARY')
            if summary:
                with open(summary, 'a') as f:
                    f.write('Both builds passed. [Download privately](https://github.com/' + PRIVATE_REPO + '/releases/tag/' + out_tag + ').\n')
            print('Both builds passed. Downloads are in the private builds repository.', flush=True)
        except Exception:
            # Raw tool output is never printed to the public job log.
            print('Signing stopped during ' + stage + '. Checking private diagnostics storage.', flush=True)
            if stage == 'private kit access':
                print('Check that PRIVATE_BUILDS_TOKEN can read the private builds repository and has Contents read/write access.', flush=True)
        finally:
            try:
                logs = list(work.glob('*.log')) + list((work / 'Builds').glob('*/*.log'))
                if logs:
                    log_zip = work / 'diagnostics.zip'
                    with zipfile.ZipFile(log_zip, 'w', zipfile.ZIP_DEFLATED) as z:
                        for n, path in enumerate(logs):
                            z.writestr(str(n) + '-' + path.name, redact(path.read_bytes(), sensitive))
                    diag_tag = 'diagnostics-' + run_id + '-' + attempt
                    checked(['gh', 'release', 'create', diag_tag, '--repo', PRIVATE_REPO,
                             '--title', 'Private signing diagnostics', '--notes',
                             'Private tool output for this signing run. Do not publish these logs.',
                             str(log_zip)], env=private_env, timeout=300)
            except Exception:
                print('Private diagnostics could not be saved.', flush=True)
            if keychain:
                try:
                    if old_keychains:
                        import shlex
                        checked(['security', 'list-keychains', '-d', 'user', '-s', *shlex.split(old_keychains.decode())])
                    checked(['security', 'delete-keychain', str(keychain)])
                except Exception:
                    print('Temporary keychain cleanup deferred to runner disposal.', flush=True)
    return 0 if success else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception:
        print('Signing stopped safely. No private error output was published.')
        sys.exit(1)
