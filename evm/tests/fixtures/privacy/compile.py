#!/usr/bin/env python3
"""Regenerate pinned bytecode; npm/solc is NOT required to run Rust tests."""
import json
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parent
request = {
    "language": "Solidity",
    "sources": {p.name: {"content": p.read_text()} for p in sorted(root.glob("*.sol"))},
    "settings": {
        "optimizer": {"enabled": True, "runs": 200},
        "evmVersion": "shanghai",
        "metadata": {"bytecodeHash": "none"},
        "outputSelection": {"*": {"*": ["evm.bytecode.object", "abi"]}},
    },
}
with tempfile.TemporaryFile(mode="w+") as src, tempfile.TemporaryFile(mode="w+") as dst:
    src.write(json.dumps(request))
    src.seek(0)
    subprocess.run(["npm", "exec", "--yes", "--package=solc@0.8.30", "--",
                    "solcjs", "--standard-json"], stdin=src, stdout=dst, check=True)
    dst.seek(0)
    raw = dst.read()
result = json.loads(raw[raw.index("{"):])
errors = [e for e in result.get("errors", []) if e["severity"] == "error"]
if errors:
    raise SystemExit("\n".join(e["formattedMessage"] for e in errors))
for name, contract in sorted((n,c) for contracts in result["contracts"].values() for n,c in contracts.items()):
    (root / f"{name}.bin").write_text(contract["evm"]["bytecode"]["object"] + "\n")
    (root / f"{name}.abi.json").write_text(json.dumps(contract["abi"], indent=2) + "\n")
    print(name)
