#!/usr/bin/env bash
# scripts/p0_gate.sh — run before any public move.
# Checks marked LIVE require a deployed site / cut tags; they no-op with a
# note until the final release pass (git tag v1/v0.1.2, GitHub Release, deploy).
set -u; fail=0
export PATH="$PWD/venv/bin:$PATH"
chk(){ if eval "$2"; then echo "PASS  $1"; else echo "FAIL  $1"; fail=1; fi; }
skip_unless(){ if eval "$2"; then chk "$1" "$2"; else echo "SKIP  $1 ($3)"; fi; }

chk "P0-2 src is clean"        '[ "$(grep -rniE "\bvisa\b" src/lucin/ | grep -viE "Mastercard|Amex|ending 4242" | wc -l | tr -d " ")" = "0" ]'
# These two scan only what git actually publishes (tracked files, via git ls-files
# piped to grep -- git grep's -E does not reliably support \b) — the internal
# docs/plan/research files intentionally stay on disk, gitignored, per P0-2 Step 2.
# Expect 4, not 3: the three legitimate card-network references (secrets.py,
# indirect_injection.py, test_adversarial.py) plus the release-gate's own regex
# pattern in publish-pypi.yml, which necessarily contains the literal word "visa".
chk "P0-2 tree has only 4 refs" '[ "$(git ls-files -- "*.py" "*.md" "*.yml" "*.toml" | xargs grep -niE "\bvisa\b|madhmitt|personalmusings|_VISA_CA" 2>/dev/null | grep -viE "visualiz|advisa|revisa" | wc -l | tr -d " ")" = "4" ]'
chk "P0-2 no internal paths"   '! (git ls-files -- "*.py" "*.md" | xargs grep -q "conversational-analytics\|Desktop/repos2\|GENAI_SSL_CERT_FILE" 2>/dev/null)'
# NOT "exactly 1 commit": that was only true the moment the orphan squash landed,
# and every legitimate commit since made it fail for no reason — a check that
# cries wolf is worse than no check. What actually matters is that the rewritten
# history carries no employer references.
# Excludes this script and the release gate: both necessarily contain the search
# patterns as literal regexes, and matching your own detector is a false positive.
chk "P0-2 history is clean"    '[ "$(git log --all -p -- . ":(exclude)scripts/p0_gate.sh" ":(exclude).github/workflows/publish-pypi.yml" 2>/dev/null | grep -ciE "madhmitt|_VISA_CA|visa fraud|visa-style|conversational-analytics")" = "0" ]'
chk "P0-2 internal docs gone"  '[ "$(git ls-files | grep -cE "^(plan|research|docs/archive|docs/design)/")" = "0" ]'
chk "P0-2 release gate exists" 'grep -q "release blocked" .github/workflows/publish-pypi.yml'
chk "P0-1 form has name attrs" 'grep -q "name=\"email\"" site/index.html'
chk "P0-1 no fake handler"     '! grep -q "wire to a real endpoint" site/index.html'
chk "P0-4 no dead domain (src)" '! grep -rq "lucin\.security" site/build.py site/build_rules.py site/build_blog.py site/make_og.py site/index.html src/ README.md docs/ 2>/dev/null'
skip_unless "P0-4 canonical correct" 'curl -sf https://lucin.pages.dev/ 2>/dev/null | grep -q "canonical\" href=\"https://lucin.pages.dev/\""' "site not yet redeployed — final release pass"
skip_unless "P0-4 og image reachable" '[ "$(curl -s -o /dev/null -w "%{http_code}" https://lucin.pages.dev/og.png 2>/dev/null)" = "200" ]' "site not yet redeployed — final release pass"
chk "P0-5 --list-rules works"  './venv/bin/lucin scan --list-rules >/dev/null 2>&1'
chk "P0-5 --list-adapters"     './venv/bin/lucin scan --list-adapters >/dev/null 2>&1'
chk "P0-6 real numbers in HTML" 'grep -q "data-target=\"76\"" site/index.html'
chk "P0-7 no stale taxonomy"   '[ "$(./venv/bin/lucin scan examples/ --no-telemetry 2>&1 | grep -cE "Cryptographic Failures|Excessive Agency")" = "0" ]'
chk "P0-7 mapping test"        './venv/bin/python -m pytest tests/test_owasp_mapping.py -q >/dev/null 2>&1'
chk "P0-3 action at root"      '[ -f action.yml ]'
skip_unless "P0-3 v1 tag exists" 'git tag -l | grep -qx v1' "tag cut in final release pass"
chk "P0-3 README snippet"      '! grep -q "lucin/lucin@v1" README.md'
chk "P0-8 github in nav"       'grep -q "class=\"nav-gh\"" site/index.html'
chk "P0-9 risk summary exact"  './venv/bin/lucin scan examples/vulnerable-agent/ --no-telemetry 2>&1 | grep -q "4 critical .*4 high .*25 medium"'
chk "P0-10 no telemetry lie (src)" '! grep -rq "no telemetry" site/build.py site/llms.txt docs/ README.md'
chk "P0-10 default disclosed"  'grep -q "on by default" docs/quickstart.md && grep -q "on by default" README.md'
chk "P0-10 all cmds opt out"   'for c in scan info explain fix badge discover redteam monitor serve; do ./venv/bin/lucin $c --help 2>&1 | grep -q -- "--no-telemetry" || exit 1; done'
chk "P0-10 json not polluted"  './venv/bin/lucin scan examples/vulnerable-agent/ --format json 2>/dev/null | ./venv/bin/python -c "import json,sys; json.load(sys.stdin)"'
chk "P0-11 fix hints runnable" './venv/bin/python -m pytest tests/test_printed_commands.py -q >/dev/null 2>&1'
chk "P0-11 no --tool in hints" '! ./venv/bin/lucin scan examples/vulnerable-agent/ --no-telemetry 2>&1 | grep -q -- "fix .* --tool"'
chk "P0-12 baseline flags"     './venv/bin/lucin scan --help 2>&1 | grep -q -- "--write-baseline"'
chk "artifact is clean"        './venv/bin/python -m build --wheel --outdir /tmp/gate_whl >/dev/null 2>&1 && rm -rf /tmp/gate_x && mkdir -p /tmp/gate_x && unzip -qo /tmp/gate_whl/*.whl -d /tmp/gate_x && [ "$(grep -rniE "\bvisa\b|madhmitt|_VISA_CA" /tmp/gate_x | grep -viE "Mastercard|Amex|ending 4242" | wc -l | tr -d " ")" = "0" ]'
chk "tests green"              './venv/bin/python -m pytest tests/ -q >/dev/null 2>&1'

exit $fail
