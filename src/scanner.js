// mcpscan 扫描引擎：目录遍历 → 规则匹配（语言过滤 + 清单限定）→ 计分（封顶+衰减）→ 报告
'use strict';

const fs = require('fs');
const path = require('path');
const { RULES, SEVERITY_WEIGHT, CATEGORY_CAP, DECAY_AFTER, DECAY_FACTOR, MANIFEST_BASENAMES } = require('./rules.js');

const VERSION = '0.2.0';

// 文本扩展名：JS/TS + Python + TOML 清单
const SCAN_EXT = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.json', '.md', '.py', '.toml']);
// 无扩展名但必须扫的清单（requirements.txt）
const MANIFEST_NAME_RE = /^requirements[\w.-]*\.txt$/i;
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'out', 'vendor', 'coverage', '.next', '__pycache__', '.venv', 'venv']);
const SKIP_FILE_RE = /(^|[\\/])(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|\.min\.(js|css))$/i;
const MAX_FILE_BYTES = 512 * 1024;

// 行级抑制标记：命中行包含此标记则不计分（用于规则库自举、测试夹具、确证误报的豁免）
const SUPPRESS_MARKER = 'mcpscan-disable-line';

function extOf(name) { return path.extname(name).toLowerCase(); }
function langOf(name) {
  const e = extOf(name);
  if (['.js', '.jsx', '.mjs', '.cjs'].includes(e)) return 'js';
  if (['.ts', '.tsx'].includes(e)) return 'ts';
  if (e === '.py') return 'py';
  return 'other';
}
function isManifest(name) {
  return MANIFEST_BASENAMES.includes(name.toLowerCase()) || MANIFEST_NAME_RE.test(name);
}

// 递归收集待扫文件
function collectFiles(dir, out = []) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch (_) { return out; }
  for (const ent of entries) {
    const full = path.join(dir, ent.name);
    if (ent.isDirectory()) {
      if (SKIP_DIRS.has(ent.name) || ent.name.startsWith('.')) continue;
      collectFiles(full, out);
    } else if (ent.isFile()) {
      if (SKIP_FILE_RE.test(ent.name)) continue;
      const ok = SCAN_EXT.has(extOf(ent.name)) || MANIFEST_NAME_RE.test(ent.name);
      if (!ok) continue;
      let size = 0;
      try { size = fs.statSync(full).size; } catch (_) { continue; }
      if (size > MAX_FILE_BYTES) continue;
      out.push(full);
    }
  }
  return out;
}

// 对单文件跑规则，返回命中数组
function scanFile(filePath, rootDir) {
  let text;
  try { text = fs.readFileSync(filePath, 'utf8'); }
  catch (_) { return []; }

  const rel = path.relative(rootDir, filePath).replace(/\\/g, '/');
  const base = path.basename(filePath).toLowerCase();
  const lang = langOf(filePath);
  const manifest = isManifest(base);
  const hits = [];

  for (const rule of RULES) {
    // 语言过滤：限定语言的规则只作用于对应扩展名
    if (rule.langs && !rule.langs.includes(lang)) continue;
    // 清单限定：供应链/密钥规则只作用于清单文件；代码文件跳过供应链规则（防误报）
    if (manifest) {
      if (!['supplychain', 'secrets'].includes(rule.category)) continue;
    } else if (rule.category === 'supplychain') {
      continue;
    }

    const re = new RegExp(rule.pattern.source, rule.pattern.flags.includes('g') ? rule.pattern.flags : rule.pattern.flags + 'g');
    let m, count = 0, firstLine = -1;
    const samples = [];

    while ((m = re.exec(text)) !== null && count < 50) {
      const lineStart = text.lastIndexOf('\n', m.index) + 1;
      let lineEnd = text.indexOf('\n', m.index);
      if (lineEnd === -1) lineEnd = text.length;
      const lineText = text.slice(lineStart, lineEnd);
      // 行级抑制：标记行不计数（规则库自举 / 夹具 / 确证误报）
      if (lineText.includes(SUPPRESS_MARKER)) {
        if (m[0].length === 0) re.lastIndex++;
        continue;
      }
      count++;
      if (firstLine === -1) firstLine = text.slice(0, m.index).split('\n').length;
      if (samples.length < 3) {
        samples.push(lineText.trim().slice(0, 120));
      }
      if (m[0].length === 0) re.lastIndex++; // 空匹配保护
    }

    if (count > 0) {
      hits.push({
        rule: rule.id,
        category: rule.category,
        severity: rule.severity,
        title: rule.desc,
        why: rule.why,
        fix: rule.fix,
        file: rel,
        line: firstLine,
        count: count,
        samples: samples
      });
    }
  }
  return hits;
}

// 计分：每类 = 命中得分之和（同规则衰减后），封顶；总分归一到 100，风险语义（越高越危险）
function computeScore(findings) {
  const perCat = {};
  const ruleCount = {};
  for (const f of findings) {
    ruleCount[f.rule] = (ruleCount[f.rule] || 0) + 1;
    let w = SEVERITY_WEIGHT[f.severity];
    if (ruleCount[f.rule] > DECAY_AFTER) w = w * DECAY_FACTOR;
    perCat[f.category] = (perCat[f.category] || 0) + w;
  }
  let total = 0;
  for (const cat of Object.keys(CATEGORY_CAP)) {
    const raw = perCat[cat] || 0;
    perCat[cat] = Math.min(raw, CATEGORY_CAP[cat]);
    total += perCat[cat];
  }
  const maxTotal = Object.values(CATEGORY_CAP).reduce((a, b) => a + b, 0); // 175
  const normalized = Math.round(Math.min(100, (total / maxTotal) * 100 * 1.75));
  const grade = normalized <= 9 ? 'A' : normalized <= 29 ? 'B' : normalized <= 54 ? 'C' : normalized <= 79 ? 'D' : 'F';
  return { perCategory: perCat, total: normalized, grade };
}

async function scanTarget(rootDir) {
  const t0 = Date.now();
  const files = collectFiles(rootDir);
  const findings = [];
  for (const f of files) {
    findings.push(...scanFile(f, rootDir));
  }
  const rank = { critical: 0, high: 1, medium: 2, low: 3 };
  findings.sort((a, b) => rank[a.severity] - rank[b.severity] || a.category.localeCompare(b.category) || a.file.localeCompare(b.file));
  const score = computeScore(findings);

  return {
    tool: 'mcpscan',
    version: VERSION,
    scannedAt: new Date().toISOString(),
    target: path.resolve(rootDir),
    filesScanned: files.length,
    durationMs: Date.now() - t0,
    score: score,
    summary: {
      critical: findings.filter(f => f.severity === 'critical').length,
      high: findings.filter(f => f.severity === 'high').length,
      medium: findings.filter(f => f.severity === 'medium').length,
      low: findings.filter(f => f.severity === 'low').length
    },
    findings: findings
  };
}

module.exports = { scanTarget, computeScore, VERSION };
