#!/usr/bin/env python3
"""Reproduce vendored npm sources/artifacts; verify archive integrity before use.
No npm lifecycle scripts are executed. Python 3.12+ required for safe tar filter.
"""
import base64
import hashlib
import io
import json
import shutil
import tarfile
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
for pin in json.loads((ROOT / 'packages.json').read_text()):
    short = pin['name'].split('/')[-1]
    directory = {'v2-core': 'uniswap-v2-core', 'v2-periphery': 'uniswap-v2-periphery',
                 'core-v3': 'aave-core-v3'}[short]
    url = f"https://registry.npmjs.org/{pin['name']}/-/{short}-{pin['version']}.tgz"
    archive = urllib.request.urlopen(url, timeout=60).read()
    integrity = 'sha512-' + base64.b64encode(hashlib.sha512(archive).digest()).decode()
    assert integrity == pin['integrity'], 'upstream archive integrity mismatch'
    with tempfile.TemporaryDirectory() as tmp:
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(tmp, filter='data')
        src = Path(tmp) / 'package'
        dst = ROOT / directory
        dst.mkdir(exist_ok=True)
        # npm packages may bundle huge compiler caches inside contracts/.
        # Keep original sources; executable artifacts are normalized below.
        shutil.copytree(src / 'contracts', dst / 'contracts', dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns('artifacts', 'cache', '.DS_Store'))
        for path in [src / 'package.json', *src.glob('LICENSE*')]:
            shutil.copy2(path, dst / path.name)
        paths = (src / 'artifacts' / 'contracts').rglob('*.json') if short == 'core-v3' else (src / 'build').glob('*.json')
        artifacts = {}
        for path in sorted(paths):
            data = json.loads(path.read_text())
            code = data.get('bytecode', '')
            if not isinstance(code, str) or not code.removeprefix('0x'):
                continue
            name = data.get('contractName', path.stem)
            assert name not in artifacts, f'duplicate contract {name}'
            artifacts[name] = {'abi': data['abi'], 'bytecode': code,
                               'linkReferences': data.get('linkReferences', {}),
                               'sourceName': data.get('sourceName', '')}
        (dst / 'artifacts.json').write_text(json.dumps(dict(sorted(artifacts.items())), separators=(',', ':')) + '\n')
# Verify against reviewed hashes; never silently bless a changed source/artifact.
for name, expected in json.loads((ROOT / 'SHA256SUMS.json').read_text()).items():
    actual = hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
    assert actual == expected, f'vendored file mismatch: {name}'
print('All vendored files match SHA256SUMS.json')
