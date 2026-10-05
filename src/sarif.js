// SARIF 2.1.0 输出：上传 GitHub Security tab（code-scanning）用的标准格式
'use strict';

const LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note' };

function toSarif(report) {
  // 汇总所有出现过的规则作为 rules 元数据
  const seenRules = new Map();
  for (const f of report.findings) {
    if (!seenRules.has(f.rule)) {
      seenRules.set(f.rule, {
        id: f.rule,
        shortDescription: { text: f.title },
        fullDescription: { text: f.why },
        help: { text: f.fix }
      });
    }
  }

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'mcpscan',
          version: report.version,
          informationUri: 'https://github.com/shaoshi20/mcpscan',
          rules: Array.from(seenRules.values())
        }
      },
      results: report.findings.map(f => ({
        ruleId: f.rule,
        level: LEVEL[f.severity] || 'note',
        message: { text: `${f.title} — ${f.why} 修复建议: ${f.fix}` },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: f.file.replace(/\\/g, '/') },
            region: { startLine: f.line }
          }
        }],
        partialFingerprints: { mcpscanRule: `${f.rule}:${f.file}` }
      }))
    }]
  };
}

module.exports = { toSarif };
