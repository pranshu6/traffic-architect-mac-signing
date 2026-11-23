#!/usr/bin/env python3
"""Local Traffic Architect build helper. Uses the developer's supplied build script."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import queue
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import zipfile

HERE = Path(__file__).resolve().parent


def require_space(path, gib):
    free = shutil.disk_usage(path).free / 1024**3
    if free < gib:
        raise RuntimeError('Not enough free disk space: %.1f GB available; at least %.1f GB needed. '
                           'Free space, then run again. Existing apps and archives have been kept.' % (free, gib))


def kit_info(path):
    """Validate a kit without running or extracting any of its code."""
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        names = [item.filename for item in entries if not item.is_dir()]
        if len(names) != len(set(names)):
            raise ValueError('ZIP contains duplicate files')
        if sum(item.file_size for item in entries) > 2 * 1024**3:
            raise ValueError('Kit ZIP is unexpectedly large')
        for item in entries:
            p = PurePosixPath(item.filename)
            if p.is_absolute() or '..' in p.parts or '\\' in item.filename or stat.S_ISLNK(item.external_attr >> 16):
                raise ValueError('Unsafe ZIP path or link: ' + item.filename)
        packages = [name for name in names if name == 'package.json' or name.endswith('/package.json')]
        if len(packages) != 1:
            raise ValueError('Expected exactly one kit package.json')
        prefix = packages[0][:-len('package.json')]
        if any(not name.startswith(prefix) for name in names if not name.startswith('__MACOSX/')):
            raise ValueError('ZIP contains files outside its kit folder')
        package = json.loads(archive.read(prefix + 'package.json'))
        build = json.loads(archive.read(prefix + 'dist/build.json'))
        archive.getinfo(prefix + 'build-mac.sh')
        archive.getinfo(prefix + 'build/entitlements.mac.plist')
        version, commit = build['version'], build['commit']
        if package.get('name') != 'traffic-architect' or package.get('version') != version:
            raise ValueError('This is not a matching Traffic Architect kit')
        if not re.fullmatch(r'\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?', version) or not re.fullmatch(r'[a-fA-F0-9]{7,40}', commit):
            raise ValueError('Unrecognized version or build ID')
        script = package.get('scripts', {}).get('mac:steam:signed', '')
        if not script.startswith('electron-builder ') or '--universal' not in script or '--config.mac.notarize=true' not in script:
            raise ValueError('Kit does not contain the expected universal signed build command')
        demo = '--config.extraMetadata.taDemo=true' in script
        return dict(version=version, commit=commit, demo=demo, prefix=prefix,
                    name='Traffic Architect Demo' if demo else 'Traffic Architect',
                    stem='TrafficArchitectDemo' if demo else 'TrafficArchitect')


def run(command, cwd, log, env=None, heartbeat=False, capture=False):
    tool = Path(str(command[0])).name
    labels = {'node': 'Checking the packaged game', 'bash': 'Building and signing',
              'plutil': 'Preparing signing settings', 'codesign': 'Checking the signature',
              'spctl': 'Checking macOS acceptance', 'ditto': 'Preparing the Apple submission',
              'tar': 'Extracting the archive for checking' if '-xzf' in command else 'Packing the archive'}
    label = labels.get(tool, 'Running ' + tool)
    if tool == 'xcrun':
        label = 'Submitting to Apple' if 'notarytool' in command else 'Checking or attaching the notarization ticket'
    print(label + '...', flush=True)
    log.write(label + '\n')
    process = subprocess.Popen(list(map(str, command)), cwd=cwd, env=env, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True, errors='replace', start_new_session=True)
    messages = queue.Queue()
    def pump():
        for line in process.stdout:
            messages.put(line)
        messages.put(None)
    reader = threading.Thread(target=pump, daemon=True)
    reader.start()
    last = time.monotonic()
    captured = []
    try:
        while True:
            try:
                line = messages.get(timeout=1)
            except queue.Empty:
                line = ''
            if line is None:
                break
            if line:
                if capture:
                    captured.append(line)
                print(line, end='', flush=True)
                log.write(line)
                log.flush()
                last = time.monotonic()
            if heartbeat and time.monotonic() - last >= 30:
                print('Still working. Signing and Apple review can take a while; no automatic retry will be made.', flush=True)
                last = time.monotonic()
        code = process.wait()
        if code:
            raise RuntimeError('Command failed (exit %s). Keep the log to send to the developer.' % code)
        return ''.join(captured)
    except BaseException:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGINT)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
        raise
    finally:
        reader.join(timeout=2)
        process.stdout.close()


def signing_environment(env):
    source = HERE / 'signing.env'
    source.chmod(0o600)
    required = {'APPLE_API_KEY', 'APPLE_API_KEY_ID', 'APPLE_API_ISSUER'}
    values = {}
    for line in source.read_text().splitlines():
        line = line.strip()
        if line.startswith('export '):
            line = line[7:]
        words = shlex.split(line, comments=True)
        if not words:
            continue
        if len(words) != 1 or '=' not in words[0]:
            raise ValueError('signing.env must contain literal KEY=value lines')
        key, value = words[0].split('=', 1)
        if key not in required or key in values or not value:
            raise ValueError('Unexpected, duplicated, or empty signing.env setting: ' + key)
        values[key] = value
    if set(values) != required:
        raise ValueError('signing.env is missing an Apple API setting')
    values['APPLE_API_KEY'] = os.path.expandvars(os.path.expanduser(values['APPLE_API_KEY']))
    if not Path(values['APPLE_API_KEY']).is_file():
        raise ValueError('The saved Apple API key file is missing')
    return dict(env, **values)


def apple_key_args(env):
    return ['--key', env['APPLE_API_KEY'], '--key-id', env['APPLE_API_KEY_ID'],
            '--issuer', env['APPLE_API_ISSUER']]


def check_apple_account(env):
    print('Checking Apple account access before building...', flush=True)
    result = subprocess.run(['xcrun', 'notarytool', 'history', *apple_key_args(env), '--output-format', 'json'],
                            env=env, capture_output=True, text=True, timeout=45)
    if result.returncode:
        error = result.stderr + result.stdout
        (HERE / 'account-check.log').write_text(error)
        raise RuntimeError('Apple account check failed. If this mentions a missing or expired agreement, '
                           'the developer account holder must accept it at developer.apple.com/account. '
                           'No build was started. Details:\n' + error)
    (HERE / 'account-check.log').write_text('Apple account access: OK\nChecked: ' + datetime.datetime.now().isoformat() + '\n')
    print('Apple account access: OK', flush=True)


def info_from_kit(kit):
    p = json.loads((kit / 'package.json').read_text())
    b = json.loads((kit / 'dist/build.json').read_text())
    if p.get('name') != 'traffic-architect' or p.get('version') != b['version']:
        raise ValueError('Unrecognized kit folder')
    if not re.fullmatch(r'\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?', b['version']) or not re.fullmatch(r'[a-fA-F0-9]{7,40}', b['commit']):
        raise ValueError('Unrecognized version or build ID in saved kit')
    demo = '--config.extraMetadata.taDemo=true' in p['scripts']['mac:steam:signed']
    return dict(version=b['version'], commit=b['commit'], demo=demo,
                name='Traffic Architect Demo' if demo else 'Traffic Architect',
                stem='TrafficArchitectDemo' if demo else 'TrafficArchitect')


def check_tar(path, root):
    with tarfile.open(path, 'r:gz') as archive:
        for item in archive:
            p = PurePosixPath(item.name)
            if p.is_absolute() or '..' in p.parts or not p.parts or p.parts[0] != root:
                raise ValueError('Archive contains an unexpected path: ' + item.name)
            if not (item.isfile() or item.isdir() or item.issym() or item.islnk()):
                raise ValueError('Archive contains a special file')
            if item.issym() or item.islnk():
                target = item.linkname if item.islnk() else posixpath.join(posixpath.dirname(item.name), item.linkname)
                target = posixpath.normpath(target)
                if target.startswith('/') or PurePosixPath(target).parts[0] != root:
                    raise ValueError('Archive contains an escaping link')


def verify(kit, info, env, log):
    require_space(tempfile.gettempdir(), 1)
    app = kit / 'release/steam/mac-universal' / (info['name'] + '.app')
    archive = kit / ('%s-%s-%s-mac.tar.gz' % (info['stem'], info['version'], info['commit']))
    if not app.is_dir() or not archive.is_file():
        raise ValueError('The expected app or archive is missing')
    # Check the actual packaged game, not just the loose source files.
    js = r'''
const asar=require('@electron/asar'),fs=require('fs');
const app=process.argv[1],expected=JSON.parse(process.argv[2]);
const file=app+'/Contents/Resources/app.asar';
const p=JSON.parse(asar.extractFile(file,'package.json'));
const b=JSON.parse(asar.extractFile(file,'dist/build.json'));
if(p.version!==expected.version||b.commit!==expected.commit||!!p.taDemo!==expected.demo||p.taTestBuild||asar.listPackage(file).includes('/dist/DEMO')!==expected.demo)throw Error('Packaged build metadata mismatch');
const config=JSON.parse(fs.readFileSync('package.json')).build.electronFuses;
if(config){
 const bin=fs.readFileSync(app+'/Contents/Frameworks/Electron Framework.framework/Electron Framework');
 const marker=Buffer.from('dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX');
 const indices={runAsNode:0,enableNodeOptionsEnvironmentVariable:2,enableNodeCliInspectArguments:3,grantFileProtocolExtraPrivileges:7};
 let pos=-1,count=0;
 while((pos=bin.indexOf(marker,pos+1))!==-1){count++;const start=pos+marker.length;
  if(bin[start]!==1)throw Error('Unknown Electron fuse version');
  for(const [name,index] of Object.entries(indices))if(name in config&&bin[start+2+index] !== (config[name]?49:48))throw Error('Runtime setting mismatch: '+name);
 }
 if(count!==2)throw Error('Expected two architecture fuse wires');
}
console.log('Packaged version, build ID, demo/full flags, and runtime settings: OK');
'''
    run(['node', '--input-type=commonjs', '-e', js, app, json.dumps(info)], kit, log, env)
    arch = subprocess.check_output(['lipo', '-archs', app / 'Contents/MacOS' / info['name']], text=True).split()
    if set(arch) != {'x86_64', 'arm64'}:
        raise ValueError('App is not a universal Intel + Apple Silicon build')
    check_tar(archive, info['name'] + '.app')
    with tempfile.TemporaryDirectory(prefix='traffic-architect-check-') as directory:
        run(['tar', '-xzf', archive, '-C', directory], kit, log, env)
        extracted = Path(directory) / (info['name'] + '.app')
        run(['codesign', '--verify', '--deep', '--strict', extracted], kit, log, env)
        run(['spctl', '-a', '-t', 'exec', '-vv', extracted], kit, log, env)
        run(['xcrun', 'stapler', 'validate', extracted], kit, log, env)
    digest = hashlib.sha256()
    with archive.open('rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(block)
    result = dict(archive=str(archive), sha256=digest.hexdigest(), **{k: info[k] for k in ('version', 'commit', 'demo')})
    (kit / 'SIGNING_RESULT.json').write_text(json.dumps(result, indent=2) + '\n')
    print('\nREADY TO SEND: ' + str(archive), flush=True)
    return result


def finish_saved_kit(kit, info, env, log):
    """Resume a signed app after an account/notarization failure; never rebuild it."""
    app = kit / 'release/steam/mac-universal' / (info['name'] + '.app')
    archive = kit / ('%s-%s-%s-mac.tar.gz' % (info['stem'], info['version'], info['commit']))
    if archive.is_file():
        return verify(kit, info, env, log)
    require_space(kit, 2)
    require_space(tempfile.gettempdir(), 2)
    if not app.is_dir():
        raise ValueError('No completed signed app found in this kit. Use its ZIP to build it first.')
    run(['codesign', '--verify', '--deep', '--strict', app], kit, log, env)
    ticket = subprocess.run(['xcrun', 'stapler', 'validate', app], capture_output=True, text=True, env=env)
    if ticket.returncode:
        check_apple_account(env)
        print('Resuming Apple notarization for the existing signed app. It will not be rebuilt.', flush=True)
        with tempfile.TemporaryDirectory(prefix='traffic-architect-submit-') as directory:
            upload = Path(directory) / (info['name'] + '.zip')
            run(['ditto', '-c', '-k', '--sequesterRsrc', '--keepParent', app, upload], kit, log, env)
            output = run(['xcrun', 'notarytool', 'submit', upload, *apple_key_args(env),
                          '--wait', '--output-format', 'json'], kit, log, env, heartbeat=True, capture=True)
            (kit / 'notarization-result.json').write_text(output)
            result = json.loads(output)
            if result.get('status') != 'Accepted':
                raise RuntimeError('Apple did not accept the app. Keep notarization-result.json and the log.')
        run(['xcrun', 'stapler', 'staple', app], kit, log, env)
    run(['spctl', '-a', '-t', 'exec', '-vv', app], kit, log, env)
    run(['xcrun', 'stapler', 'validate', app], kit, log, env)
    run(['tar', '-czf', archive, '-C', app.parent, app.name], kit, log, dict(env, COPYFILE_DISABLE='1'))
    return verify(kit, info, env, log)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('zips', nargs='*', type=Path)
    parser.add_argument('--check-only', action='store_true', help='Inspect ZIPs without building')
    parser.add_argument('--verify-kit', type=Path, help='Verify an already completed kit without rebuilding')
    args = parser.parse_args()
    env = os.environ.copy()
    env['PATH'] = '/opt/homebrew/bin:/usr/local/bin:' + env.get('PATH', '')
    if args.verify_kit:
        kit = args.verify_kit.resolve()
        info = info_from_kit(kit)
        with (kit / 'archive-verification.log').open('a') as log:
            verify(kit, info, env, log)
        return
    paths = args.zips
    if not paths:
        print('Traffic Architect Mac Signing\n\nDrag BOTH new kit ZIP files here, then press Return.\nTo resume after a notarization error, drag the saved kit FOLDERS instead.')
        paths = [Path(p) for p in shlex.split(input('Kit ZIP files: ').strip())]
    if not paths:
        raise ValueError('No ZIP files selected')
    paths = [p.expanduser().resolve() for p in paths]
    if any(p.is_dir() for p in paths):
        if not all(p.is_dir() for p in paths) or args.check_only:
            raise ValueError('Choose either kit ZIPs or saved kit folders, not a mixture')
        selected = [(p, info_from_kit(p)) for p in paths]
        if len({(i['version'], i['commit']) for _, i in selected}) != 1 or len({i['demo'] for _, i in selected}) != len(selected):
            raise ValueError('Choose matching demo/full kit folders')
        env = signing_environment(env)
        for kit, info in sorted(selected, key=lambda x: not x[1]['demo']):
            with (kit / 'resume-signing.log').open('a') as log:
                result = finish_saved_kit(kit, info, env, log)
                if sys.platform == 'darwin':
                    subprocess.run(['open', '-R', result['archive']], check=False)
        print('\nALL DONE. Send the .tar.gz files listed above. Keep the kit folders as backups.')
        return
    selected = [(p.expanduser().resolve(), kit_info(p.expanduser())) for p in paths]
    pairs = {(i['version'], i['commit']) for _, i in selected}
    if len(pairs) != 1 or len({i['demo'] for _, i in selected}) != len(selected):
        raise ValueError('Choose matching demo/full ZIPs with the same version and build ID')
    for p, info in selected:
        print('%s: version %s, build %s' % (p.name, info['version'], info['commit']))
    if args.check_only:
        print('ZIP checks passed. No build was started.')
        return
    for tool in ('node', 'npm', 'codesign', 'xcrun', 'plutil', 'tar'):
        if not shutil.which(tool, path=env['PATH']):
            raise ValueError('Required tool is missing: ' + tool)
    signing = HERE / 'signing.env'
    if not signing.is_file():
        raise ValueError('The saved signing.env is missing from this tool folder')
    signing.chmod(0o600)
    env = signing_environment(env)
    require_space(HERE, 4)
    require_space(tempfile.gettempdir(), 4)
    check_apple_account(env)
    cache = Path(json.loads((HERE / 'settings.json').read_text())['cache_root']).expanduser()
    cache.mkdir(parents=True, exist_ok=True)
    # Electron icon utilities use CommonJS, even though the game uses modules.
    if not (cache / 'package.json').exists():
        (cache / 'package.json').write_text('{"private":true,"type":"commonjs"}\n')
    env.update(npm_config_cache=str(cache / 'npm'), ELECTRON_CACHE=str(cache / 'electron'),
               ELECTRON_BUILDER_CACHE=str(cache / 'electron-builder'))
    builds = HERE / 'Builds'
    builds.mkdir(exist_ok=True)
    results = []
    for path, info in sorted(selected, key=lambda x: not x[1]['demo']):
        require_space(builds, 4)
        require_space(tempfile.gettempdir(), 4)
        kit = Path(tempfile.mkdtemp(prefix='%s-%s-%s-' % (info['stem'], info['version'], info['commit']), dir=builds))
        print('\nBUILD FOLDER: ' + str(kit), flush=True)
        with zipfile.ZipFile(path) as archive:
            for item in archive.infolist():
                if item.is_dir() or item.filename.startswith('__MACOSX/'):
                    continue
                relative = item.filename[len(info['prefix']):]
                dest = kit / relative
                dest.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(item) as source, dest.open('wb') as target:
                    shutil.copyfileobj(source, target)
        shutil.copyfile(signing, kit / 'signing.env')
        (kit / 'signing.env').chmod(0o600)
        (kit / '.gitignore').write_text('signing.env\n*.p8\n*.p12\nnode_modules/\nrelease/\n*.log\n')
        logpath = kit / 'signed-build.log'
        print('Keep this folder and log if anything fails. No Steam upload is performed.\nLog: ' + str(logpath))
        with logpath.open('w') as log:
            run(['plutil', '-convert', 'xml1', 'build/entitlements.mac.plist'], kit, log, env)
            run(['bash', 'build-mac.sh', 'steam', 'signed'], kit, log, env, heartbeat=True)
            results.append(verify(kit, info, env, log))
    summary = builds / ('Ready-to-send-' + datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '.json')
    summary.write_text(json.dumps(results, indent=2) + '\n')
    print('\nALL DONE. Send only the .tar.gz files listed above. Keep the kit folders as backups.')
    if sys.platform == 'darwin':
        for result in results:
            subprocess.run(['open', '-R', result['archive']], check=False)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\nStopped. Keep the build folder and log. An Apple submission may still be processing.', file=sys.stderr)
        sys.exit(130)
    except Exception as error:
        print('\nSTOPPED: ' + str(error) + '\nNothing was retried automatically. Keep the build folder and log.', file=sys.stderr)
        sys.exit(1)
