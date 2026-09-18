#!/usr/bin/env python3
"""Lint the shell embedded in a composite action.

actionlint covers workflows but not `action.yml`, so the `run:` blocks of the
composite action would otherwise ship unlinted. Two checks:

  1. no `run:` block interpolates `${{ ... }}` inline. Inputs such as a PR body
     or a branch name are attacker-controlled; they must arrive through `env:`.
  2. every block passes shellcheck.

Dependency-free on purpose (no PyYAML): it must run on a bare runner image.
"""
import re
import subprocess
import sys
import tempfile


def run_blocks(text):
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        m = re.match(r"^(\s*)run:\s*\|[-+]?\s*$", lines[i])
        if not m:
            if re.match(r"^\s*run:\s*\S", lines[i]):
                yield i + 1, lines[i].split("run:", 1)[1].strip()
            i += 1
            continue
        indent, start, body = len(m.group(1)), i + 1, []
        i += 1
        while i < len(lines) and (not lines[i].strip() or len(lines[i]) - len(lines[i].lstrip()) > indent):
            body.append(lines[i])
            i += 1
        yield start, "\n".join(body)


def main(path):
    text = open(path, encoding="utf-8").read()
    blocks = list(run_blocks(text))
    if not blocks:
        sys.exit(f"{path}: found no run: blocks; the extractor is broken or the file is wrong")

    failed = False
    for line, body in blocks:
        if "${{" in body:
            print(f"{path}:{line}: run block interpolates ${{{{ }}}} inline; pass it through env:")
            failed = True
        with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as f:
            f.write("#!/usr/bin/env bash\n" + body + "\n")
        result = subprocess.run(["shellcheck", "--shell=bash", f.name], capture_output=True, text=True)
        if result.returncode != 0:
            print(f"{path}:{line}: shellcheck failed\n{result.stdout}{result.stderr}")
            failed = True
    print(f"{path}: {len(blocks)} run block(s) checked")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "action.yml")
