# mcpscan

**Security auditor for MCP servers.** Find prompt-injection surfaces, overprivileged tools, data exfiltration and supply-chain risks in Model Context Protocol servers — *before* your agent runs them. JS/TS + Python, zero dependencies, fully offline.

Every MCP server you install runs **inside your agent's trust boundary**. Its tool descriptions are concatenated into your model's context. Its code can reach the network, spawn shells, and read your files. mcpscan audits that surface statically, in milliseconds.

```
  mcpscan v0.2.0  ./my-mcp-server
  scanned 4 files in 14ms
  ──────────────────────────────────────────────
  Risk score: 100/100 (F)   critical 6  high 13  medium 7  low 1
  ──────────────────────────────────────────────
  [CRITICAL] PYX-001 Python 使用 os.system / os.popen 执行 shell 命令
        tools.py:9 (×1)
        > os.system('ls ' + user_input)
        why: 等价于把宿主机 shell 交给 agent 输入…
        fix: 用 subprocess.run(参数列表, shell=False) 替代…
  ...
```

## Quickstart

```bash
# from source (v0.2)
git clone https://github.com/shaoshi20/mcpscan && cd mcpscan
node bin/mcpscan.js scan ./some-mcp-server

# scan a remote repo (shallow clone, then audit)
node bin/mcpscan.js scan https://github.com/xxx/yyy-mcp --json --out report.json

# SARIF for GitHub Security tab (code scanning)
node bin/mcpscan.js scan ./my-mcp-server --sarif --out mcp-results.sarif

# CI gate: exits 1 when critical/high findings exist
node bin/mcpscan.js scan ./my-mcp-server
```

## What it detects — 23 rules, 5 categories, JS/TS + Python

| Category | Example rules | Why it matters |
|----------|--------------|----------------|
| **Prompt-injection surface** | directive language in tool descriptions (`ignore previous instructions`), jailbreak templates, dynamically-built descriptions, "visit this URL" bait, oversized base64 blobs | Tool descriptions are concatenated into the host LLM's context — a hostile description *is* a hostile instruction |
| **Dangerous execution** | `child_process`, `eval`/`new Function`/Python `exec()`, `shell: true`, template-interpolated commands, `os.system`, dynamic `require(变量)` | The agent inherits whatever the server can execute |
| **Data exfiltration** | hardcoded public IPs, plaintext HTTP egress, POST of locally-collected data | "Read-only" tools that phone home |
| **Supply chain** | `postinstall` scripts, git/URL dependencies, floating `*`/`latest`, unpinned pip requirements, known typosquat names | npm-install-time payloads and unpatchable upstream swaps |
| **Secrets exposure** | `sk-…`/`sk-ant-…`/`AKIA…`/`ghp_…`/`AIza…`/`xox…` literals, long credential assignments, credential logging | Published keys are scraped within minutes |

## Scoring model

Per-category weighted findings → **category caps** (one noisy category can't swamp the report) → **decay** for repeated hits of the same rule → normalized 0–100 risk score, `A` (clean) to `F` (severe). Designed to err toward **fewer false positives**: a security tool burns its credibility one false alarm at a time.

## Validation

- Against the **official `modelcontextprotocol/servers` reference implementation**: `12/100 (B)`, zero critical/high — 3 medium heuristic findings (2 genuinely dynamic descriptions, 1 embedded test PNG), all defensible. Re-verified after every rule addition.
- Against a deliberately poisoned fixture (`fixtures/demo-mcp-server`, flaws planted across all 5 categories in both JS and Python): `100/100 (F)`, **27 findings across 20 rules, 0 missed plants**.
- Test suite: `npm test` (node:test, 6 cases covering end-to-end detection, scoring caps/decay, SARIF structure, regression for the hyphenated-key miss fixed in v0.2).

## Positioning

mcpscan is **not** a competitor to Snyk agent-scan or Cisco mcp-scanner — it's a different layer of the same defense:

| Layer | Tool | Needs account | Runs your code |
|-------|------|--------------|----------------|
| Config (`mcp.json`, skills) | Snyk agent-scan | Snyk token required | Yes (starts stdio servers) |
| Behavior (remote servers, packages, binaries) | cisco-ai-defense/mcp-scanner | Optional keys | No (sandboxed) |
| **Source code (SAST, offline, ms-fast)** | **mcpscan** | **Nothing** | **Never** |

Rules mcpscan checks that the big scanners above don't: `postinstall` hooks and source-level hardcoded secrets (Cisco skips both; Snyk doesn't read source). Use all three; they don't overlap.

## Suppressing findings

For rule self-bootstrapping, test fixtures, or confirmed false positives, append the marker to the offending line — the match is excluded from counting and scoring:

```js
const s = 'shell: true'; // mcpscan-disable-line
```

mcpscan dogfoods this marker in its own rule definitions, and its CI self-scan (`scan src`) is expected to come back **0/100 (A)**.

## Limitations (honest ones)

- Regex-based static analysis — no AST/dataflow yet. It finds *surfaces*, not proven exploits.
- Findings are review guidance, not verdicts. `INJ-004` flags the official servers' embedded test PNGs; humans decide.

## Roadmap

- [ ] Typosquat detection via edit-distance (beyond the curated list)
- [ ] GitHub Action (`mcpscan-action`) + PR comments
- [ ] HTML reports
- [ ] Hosted registry-scanning dashboard (Pro)

## License

MIT
