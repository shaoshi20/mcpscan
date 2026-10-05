#!/usr/bin/env node
// mcpscan CLI 入口：零依赖，仅用 Node 内置模块（安全工具不引第三方依赖，以身作则）
'use strict';

const path = require('path');
const { scanTarget, VERSION } = require('../src/scanner.js');

function printHelp() {
  console.log(`
  mcpscan v${VERSION} - Security auditor for MCP servers

  USAGE
    mcpscan scan <directory>        静态扫描一个 MCP server 源码目录（JS/TS + Python）
    mcpscan scan <git-url>          浅克隆远端仓库后扫描（需要 git 可用）
    mcpscan help                    显示本帮助

  OPTIONS
    --json                          以 JSON 输出（供 CI / 上游系统消费，遵循 --min-severity 过滤）
    --sarif                         以 SARIF 2.1.0 输出（可上传 GitHub Security tab）
    --out <file>                    将完整报告（不过滤）写入文件
    --min-severity <level>          低于该级别的发现不显示：low|medium|high|critical

  EXIT CODES
    0  未发现 high 及以上风险
    1  发现 high/critical 风险（CI 可直接用作门禁）
    2  扫描执行出错

  EXAMPLES
    mcpscan scan ./my-mcp-server
    mcpscan scan ./my-mcp-server --sarif --out mcp-results.sarif
    mcpscan scan https://github.com/xxx/yyy-mcp --json --out report.json
  `);
}

async function main() {
  const argv = process.argv.slice(2);
  const cmd = argv[0];

  if (!cmd || cmd === 'help' || cmd === '--help' || cmd === '-h') {
    printHelp();
    process.exit(0);
  }
  if (cmd === '--version' || cmd === '-v') {
    console.log(VERSION);
    process.exit(0);
  }
  if (cmd !== 'scan') {
    console.error(`未知命令: ${cmd}（可用命令见 mcpscan help）`);
    process.exit(2);
  }

  const target = argv[1];
  if (!target) {
    console.error('缺少扫描目标：mcpscan scan <directory|git-url>');
    process.exit(2);
  }

  const fs = require('fs');
  const os = require('os');
  const opts = { json: false, sarif: false, out: null, minSeverity: 'low' };
  for (let i = 2; i < argv.length; i++) {
    if (argv[i] === '--json') opts.json = true;
    else if (argv[i] === '--sarif') opts.sarif = true;
    else if (argv[i] === '--out') { opts.out = argv[++i]; }
    else if (argv[i] === '--min-severity') { opts.minSeverity = argv[++i]; }
  }

  let scanDir = target;
  let tmpClone = null;

  // 远端仓库：浅克隆到临时目录（失败则明确报错，不静默降级）
  if (/^https?:\/\/|^git@/.test(target)) {
    const { execSync } = require('child_process');
    tmpClone = path.join(os.tmpdir(), 'mcpscan-clone-' + Date.now());
    try {
      console.error('[mcpscan] 浅克隆远端仓库…');
      execSync(`git clone --depth 1 "${target}" "${tmpClone}"`, { stdio: 'ignore', timeout: 120000 });
      scanDir = tmpClone;
    } catch (e) {
      console.error('[mcpscan] 克隆失败：' + e.message);
      process.exit(2);
    }
  }

  if (!fs.existsSync(scanDir) || !fs.statSync(scanDir).isDirectory()) {
    console.error(`目标不存在或不是目录: ${scanDir}`);
    process.exit(2);
  }

  const report = await scanTarget(scanDir);

  // 输出：stdout 遵循 min-severity 过滤；--out 始终写完整报告（审计留档需要全量）
  const severityRank = { low: 0, medium: 1, high: 2, critical: 3 };
  const visible = report.findings.filter(f => severityRank[f.severity] >= severityRank[opts.minSeverity]);
  const shownReport = Object.assign({}, report, { findings: visible });

  if (opts.sarif) {
    const { toSarif } = require('../src/sarif.js');
    const text = JSON.stringify(toSarif(report), null, 2);
    if (opts.out) fs.writeFileSync(opts.out, text, 'utf8');
    else console.log(text);
  } else if (opts.json) {
    const text = JSON.stringify(shownReport, null, 2);
    if (opts.out) fs.writeFileSync(opts.out, text, 'utf8');
    else console.log(text);
  } else {
    const { renderTable } = require('../src/report.js');
    renderTable(shownReport);
    if (opts.out) fs.writeFileSync(opts.out, JSON.stringify(report, null, 2), 'utf8');
  }

  if (tmpClone) { try { fs.rmSync(tmpClone, { recursive: true, force: true }); } catch (_) {} }

  // 退出码门禁：critical/high → 1
  const blocked = report.findings.some(f => f.severity === 'critical' || f.severity === 'high');
  process.exit(blocked ? 1 : 0);
}

main().catch(e => { console.error('[mcpscan] 执行出错: ' + e.message); process.exit(2); });
