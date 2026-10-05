// mcpscan 测试套件（node:test，零第三方依赖，跨平台）
'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { scanTarget, computeScore, VERSION } = require('../src/scanner.js');
const { toSarif } = require('../src/sarif.js');

const FIXTURE = path.join(__dirname, '..', 'fixtures', 'demo-mcp-server');

// 找到指定规则的命中（没有则返回 undefined）
function hit(report, ruleId) {
  return report.findings.find(f => f.rule === ruleId);
}

test('含毒夹具：评级 F，含 critical，核心规则全部命中', async () => {
  const report = await scanTarget(FIXTURE);

  assert.strictEqual(report.score.grade, 'F');
  assert.ok(report.score.total >= 80, '风险分应 >= 80');
  assert.ok(report.summary.critical >= 3, '至少 3 个 critical（EXE-001/SUP-001/PYX-001/PYX-002）');

  // 五类覆盖
  const mustHave = ['INJ-001', 'INJ-002', 'INJ-005', 'EXE-001', 'EXE-005', 'PYX-001', 'PYX-002', 'PYX-003',
    'NET-001', 'SUP-001', 'SUP-002', 'SEC-001', 'SEC-002'];
  for (const id of mustHave) {
    assert.ok(hit(report, id), `缺少预期命中: ${id}`);
  }
  // Python 侧文件确实被扫到
  assert.ok(hit(report, 'PYX-001').file.includes('tools.py'), 'PYX-001 应定位在 tools.py');
  // requirements.txt 的 git 依赖（同规则也会命中 package.json，检查存在性而非唯一性）
  assert.ok(report.findings.some(f => f.rule === 'SUP-002' && f.file.includes('requirements.txt')),
    'SUP-002 应命中 requirements.txt 的 git+https 依赖');
});

test('SEC-001 覆盖连字符密钥格式（v0.1 漏报回归）', async () => {
  const report = await scanTarget(FIXTURE);
  const pyHit = report.findings.find(f => f.rule === 'SEC-001' && f.file.includes('tools.py'));
  assert.ok(pyHit, 'SEC-001 必须命中 tools.py（sk-ant-api03- 连字符格式）');
  assert.ok(pyHit.samples.some(s => s.includes('sk-ant-')), '样本应包含 sk-ant- 前缀密钥');
});

test('干净代码：0 发现，评级 A', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcpscan-clean-'));
  fs.writeFileSync(path.join(dir, 'server.ts'), `
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

const server = new McpServer({ name: 'clean-demo', version: '1.0.0' });

server.tool('add', { a: 1, b: 2 }, async ({ a, b }) => ({
  content: [{ type: 'text', text: String(a + b) }]
}));
`);
  fs.writeFileSync(path.join(dir, 'tools.py'), `
from mcp.server import Server

server = Server("clean-py")

def add(a: int, b: int) -> int:
    return a + b
`);
  try {
    const report = await scanTarget(dir);
    assert.strictEqual(report.findings.length, 0, '干净代码不应有发现: ' + JSON.stringify(report.findings));
    assert.strictEqual(report.score.grade, 'A');
    assert.strictEqual(report.score.total, 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('计分：类别封顶 + 同规则衰减', () => {
  // 同一条 critical 规则命中 6 次：3 次全额 25 + 3 次衰减 5 = 90 → exec 封顶 40
  const findings = Array.from({ length: 6 }, (_, i) => ({
    rule: 'EXE-001', category: 'exec', severity: 'critical'
  }));
  const s = computeScore(findings);
  assert.strictEqual(s.perCategory.exec, 40, 'exec 类应被封顶在 40');
  assert.strictEqual(s.total, 40, '单类封顶后总分 = 40/100');
  assert.strictEqual(s.grade, 'C');

  // 空发现 → 0 分 A
  const empty = computeScore([]);
  assert.strictEqual(empty.total, 0);
  assert.strictEqual(empty.grade, 'A');
});

test('SARIF 输出：结构与级别映射正确', async () => {
  const report = await scanTarget(FIXTURE);
  const sarif = toSarif(report);

  assert.strictEqual(sarif.version, '2.1.0');
  assert.strictEqual(sarif.runs.length, 1);
  assert.strictEqual(sarif.runs[0].tool.driver.name, 'mcpscan');
  assert.strictEqual(sarif.runs[0].results.length, report.findings.length);

  // critical/high → error，medium → warning
  const byRule = Object.fromEntries(sarif.runs[0].results.map(r => [r.ruleId, r.level]));
  assert.strictEqual(byRule['EXE-001'], 'error');
  assert.ok(byRule['SEC-003'] === 'warning' || byRule['SUP-003'] === 'warning' || byRule['INJ-003'] === 'warning' || byRule['SUP-005'] === 'note',
    '至少存在一个 warning/note 级别的 medium/low 项');
  // 行号定位存在
  const first = sarif.runs[0].results[0];
  assert.ok(first.locations[0].physicalLocation.region.startLine > 0);
});

test('版本号一致性', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
  assert.strictEqual(VERSION, pkg.version, 'scanner.js VERSION 应与 package.json 同步');
});
