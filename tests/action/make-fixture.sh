#!/usr/bin/env bash
# Builds a throwaway git repository for exercising the action / hook end to end.
#
#   make-fixture.sh <dir> clean   a change every gate accepts
#   make-fixture.sh <dir> bad     a change that trips five named gates
#   make-fixture.sh <dir> staged  the `bad` change left staged, uncommitted
#
# The repository has a `main` branch (the base) and a `work` branch (the change).
set -euo pipefail

dir="${1:?usage: make-fixture.sh <dir> clean|bad|staged}"
kind="${2:?usage: make-fixture.sh <dir> clean|bad|staged}"

rm -rf "${dir}"
mkdir -p "${dir}/src" "${dir}/tests" "${dir}/docs"
cd "${dir}"
git init -q -b main
git config user.email "fixture@example.invalid"
git config user.name "fixture"
git config commit.gpgsign false

cat > AGENTS.md <<'MD'
# Agent guide
MD
cat > src/lib.rs <<'RS'
pub fn read(p: *const u8) -> u8 {
    // SAFETY: callers pass a pointer that is valid for reads.
    unsafe { *p }
}
RS
cat > tests/arith.rs <<'RS'
#[test]
fn adds() {
    assert_eq!(1 + 1, 2);
    assert_eq!(2 + 2, 4);
}
RS
cat > docs/plan.md <<'MD'
# Plan

Phase 1, then Phase 2 once the parser tests pass.
MD
git add -A
git commit -q -m "chore: base"
git checkout -q -b work

case "${kind}" in
  clean)
    cat >> tests/arith.rs <<'RS'

#[test]
fn multiplies() {
    assert_eq!(3 * 3, 9);
}
RS
    printf '\nPhase 3 is blocked on Phase 2.\n' >> docs/plan.md
    git add -A
    git commit -q -m "test: cover multiplication"
    ;;
  bad|staged)
    # assertion-reduction: equality weakened to a truthiness check.
    cat > tests/arith.rs <<'RS'
#[test]
fn adds() {
    assert!(1 + 1 == 2);
}

#[test]
fn ghost() {}
RS
    # unsafe-safety-comment: new undocumented block.
    cat >> src/lib.rs <<'RS'

pub fn peek(p: *const u8) -> u8 { let v = unsafe{ *p }; v }
RS
    # time-estimates, and pii (path assembled so this script stays clean).
    printf '\nPhase 2 (1 week).\n' >> docs/plan.md
    printf 'built in /%s/alice/src\n' "Users" > docs/notes.md
    git add -A
    if [ "${kind}" = "bad" ]; then
      git commit -q -m "test: simplify"
    fi
    ;;
  *)
    echo "unknown fixture kind: ${kind}" >&2
    exit 2
    ;;
esac
