// 终端表格化报告渲染（不引第三方库，控制台配色用 ANSI）
'use strict';

const C = {
  reset: '\x1b[0m', dim: '\x1b[2m', bold: '\x1b[1m',
  red: '\x1b[31m', yellow: '\x1b[33m', green: '\x1b[32m', cyan: '\x1b[36m', magenta: '\x1b[35m'
};
const sevColor = { critical: C.red, high: C.red, medium: C.yellow, low: C.dim };

function renderTable(report) {
  const { score, summary, findings, filesScanned, durationMs, target } = report;
  const gradeColor = score.grade === 'A' || score.grade === 'B' ? C.green : score.grade === 'C' ? C.yellow : C.red;

  console.log('');
  console.log(`${C.bold}  mcpscan${C.reset} ${C.dim}v${report.version}${C.reset}  ${C.dim}${target}${C.reset}`);
  console.log(`  ${C.dim}scanned ${filesScanned} files in ${durationMs}ms${C.reset}`);
  console.log('  ' + '─'.repeat(62));
  console.log(`  Risk score: ${gradeColor}${C.bold}${score.total}/100 (${score.grade})${C.reset}   ` +
    `${summary.critical ? C.red : C.dim}critical ${summary.critical}${C.reset}  ` +
    `${summary.high ? C.red : C.dim}high ${summary.high}${C.reset}  ` +
    `${C.yellow}medium ${summary.medium}${C.reset}  ${C.dim}low ${summary.low}${C.reset}`);
  console.log('  ' + '─'.repeat(62));

  if (findings.length === 0) {
    console.log(`  ${C.green}✓ 未发现高风险模式${C.reset}（静态规则覆盖五类：注入/执行/外传/供应链/密钥）`);
    console.log('');
    return;
  }

  for (const f of findings) {
    const col = sevColor[f.severity] || C.reset;
    console.log(`${col}${C.bold}  [${f.severity.toUpperCase()}]${C.reset} ${C.bold}${f.rule}${C.reset} ${f.title}`);
    console.log(`        ${C.cyan}${f.file}:${f.line}${C.reset} ${C.dim}(×${f.count})${C.reset}`);
    if (f.samples[0]) console.log(`        ${C.dim}> ${f.samples[0]}${C.reset}`);
    console.log(`        ${C.magenta}why:${C.reset} ${f.why}`);
    console.log(`        ${C.green}fix:${C.reset} ${f.fix}`);
    console.log('');
  }
}

module.exports = { renderTable };
