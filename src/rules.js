// mcpscan 规则库：五类风险的静态检测规则（v0.2，24 条，覆盖 JS/TS + Python）
// 设计经验（来自 dshscan 项目误报治理）：每条规则必须有明确的"为什么危险"和"怎么修"，
// 宁可漏报不可误报——安全工具的公信力一次误报就烧光。
// langs 字段可选：限定规则只作用于特定语言（缺省 = 语言无关，字符串类规则通用）

// 严重度权重（用于计分）
const SEVERITY_WEIGHT = { critical: 25, high: 10, medium: 4, low: 1 };

// 每类得分上限（防止同一类问题刷爆总分，类别间可比）
const CATEGORY_CAP = {
  injection: 40,   // 提示词注入面
  exec: 40,        // 危险执行能力
  netexfil: 35,    // 数据外传
  supplychain: 30, // 供应链完整性
  secrets: 30      // 密钥暴露
};

// 同一规则在同一文件的得分衰减：前 3 次命中全额计分，之后每次 20%
const DECAY_AFTER = 3;
const DECAY_FACTOR = 0.2;

// 供应链规则只作用于包清单文件（源码里出现依赖语法多为误报）
const MANIFEST_BASENAMES = ['package.json', 'pyproject.toml', 'requirements.txt', 'setup.py', 'setup.cfg'];

const RULES = [
  // ============ 提示词注入面（injection）============
  {
    id: 'INJ-001',
    category: 'injection',
    severity: 'high',
    desc: '工具描述中包含操纵宿主 LLM 的指令性语言',
    why: 'MCP 工具的 description 会被直接拼进宿主模型的上下文。若描述含 "ignore previous instructions" 类指令，server 作者（或劫持它的攻击者）可以操纵 agent 行为——这是 MCP 最典型的注入面。', // mcpscan-disable-line（规则自举：why 文本引用了攻击载荷示例）
    pattern: /(ignore|disregard|forget)[^"'\n]{0,40}(previous|prior|above|earlier)[^"'\n]{0,24}instruction/i,
    fix: '工具描述只做客观能力陈述，删除任何试图引导模型行为的指令性语句。'
  },
  {
    id: 'INJ-002',
    category: 'injection',
    severity: 'high',
    desc: '字符串中包含对宿主模型的隐性指令（you are now / must obey / do not tell）',
    why: '典型的越狱式提示词模板，出现在 MCP server 源码里通常意味着该 server 试图在运行时改写 agent 的系统约束。',
    pattern: /(you\s+are\s+now\s+a|must\s+(obey|follow)[^"'\n]{0,20}(instruction|rule)|do\s+not\s+(tell|reveal|inform)\s+the\s+user)/i,
    fix: '移除针对宿主模型的行为指令；若为测试用例请隔离到 tests/ 并在扫描时排除。'
  },
  {
    id: 'INJ-003',
    category: 'injection',
    severity: 'medium',
    desc: '工具 description 由模板字符串/外部内容动态拼接',
    why: '动态生成的 description 在运行时才确定内容，一旦上游数据被污染，注入载荷可以绕过一切安装期审计。',
    pattern: /(description|Description)\s*[:=]\s*`[^`]*\$\{/,
    fix: 'description 改为静态字面量；动态内容（如查询结果）只应出现在 tool 结果中，且宿主应将其视为数据而非指令。'
  },
  {
    id: 'INJ-004',
    category: 'injection',
    severity: 'medium',
    desc: '源码中存在超长 Base64 块（可能隐藏载荷）',
    why: '超过 512 字符的 Base64 常量无法被人工审阅，是隐藏注入载荷/二阶段下载地址的常见手法。',
    pattern: /['"][A-Za-z0-9+/]{512,}={0,2}['"]/,
    fix: '改用可读的明文配置或资源文件；确有二进制需求请放独立资产文件并说明用途。'
  },
  {
    id: 'INJ-005',
    category: 'injection',
    severity: 'medium',
    desc: '工具描述中嵌入"访问外部 URL"的引导指令',
    why: '描述里引导模型去 visit/fetch 外部地址是间接注入的经典布局：URL 内容随时可被上游替换，审计时看到的和运行时拿到的不一致。',
    pattern: /(description|Description)\s*[:=]\s*['"`][^'"`\n]{0,200}\b(visit|fetch|download|retrieve)\b[^'"`\n]{0,60}https?:\/\//i,
    fix: '描述中不放外链引导；补充资料应放在仓库文档并走版本化提交。'
  },

  // ============ 危险执行（exec）============
  {
    id: 'EXE-001',
    category: 'exec',
    severity: 'critical',
    desc: '引入 child_process 执行 shell 命令',
    why: 'MCP server 拥有 shell 执行能力 = 宿主 agent 被间接授予宿主机 shell。任何注入到该 server 的恶意输入都可能变成任意命令执行。',
    pattern: /require\s*\(\s*['"](node:)?child_process['"]\s*\)|from\s+['"](node:)?child_process['"]/,
    fix: '默认不要引入 shell 执行；确需执行固定命令时用 execFile + 参数数组，禁止拼接字符串。'
  },
  {
    id: 'EXE-002',
    category: 'exec',
    severity: 'high',
    desc: '使用 eval / new Function 动态执行代码',
    why: 'eval 能执行任何字符串，等价于给 agent 的输入开了一扇任意代码执行的窗（JS 与 Python 同理）。',
    pattern: /\b(eval|new\s+Function)\s*\(/,
    fix: '用映射表/查表逻辑替代动态求值。'
  },
  {
    id: 'EXE-003',
    category: 'exec',
    severity: 'high',
    desc: 'spawn 选项开启 shell: true', // mcpscan-disable-line（规则自举：描述引用了风险特征文本）
    why: 'shell:true 使参数经过 shell 解释，参数注入风险显著升高。', // mcpscan-disable-line（规则自举：why 文本引用了风险特征文本）
    pattern: /shell\s*:\s*true/,
    fix: '去掉 shell:true，改用参数数组形式调用。' // mcpscan-disable-line（规则自举）
  },
  {
    id: 'EXE-004',
    category: 'exec',
    severity: 'high',
    desc: 'exec 执行由模板字符串拼接的命令',
    why: '模板插值进 shell 命令 = 经典命令注入。若插值来源含用户/agent 输入，攻击者可直接控制命令。',
    pattern: /exec(Sync)?\s*\(\s*`[^`]*\$\{/,
    fix: '固定命令 + execFile 参数数组；对动态部分做白名单校验。'
  },
  {
    id: 'EXE-005',
    category: 'exec',
    severity: 'medium',
    desc: '动态 require（非字面量参数）',
    why: 'require(变量) 使加载路径运行时才确定，静态审计无法覆盖被加载代码，也为按环境切换恶意模块留了门。',
    langs: ['js'],
    pattern: /\brequire\s*\(\s*[A-Za-z_$][\w$.[\]]*\s*\)/,
    fix: 'require 只接受字面量路径；确需动态加载用白名单映射表。'
  },
  {
    id: 'PYX-001',
    category: 'exec',
    severity: 'critical',
    desc: 'Python 使用 os.system / os.popen 执行 shell 命令',
    why: '等价于把宿主机 shell 交给 agent 输入，Python 版 MCP server 中最高危的执行面。',
    langs: ['py'],
    pattern: /\bos\.(system|popen)\s*\(/,
    fix: '用 subprocess.run(参数列表, shell=False) 替代，并对参数做白名单校验。'
  },
  {
    id: 'PYX-002',
    category: 'exec',
    severity: 'critical',
    desc: 'subprocess 调用开启 shell=True',
    why: 'shell=True 使参数经 shell 解释，注入风险与 os.system 相同。',
    langs: ['py'],
    pattern: /subprocess\.\w+\s*\([^)]*shell\s*=\s*True/,
    fix: '去掉 shell=True，用参数列表形式传参。'
  },
  {
    id: 'PYX-003',
    category: 'exec',
    severity: 'high',
    desc: 'Python exec() 动态执行代码',
    why: 'exec() 可执行任意字符串，配合 agent 输入即任意代码执行。',
    langs: ['py'],
    pattern: /\bexec\s*\(/,
    fix: '用映射表/查表逻辑替代动态执行。'
  },

  // ============ 数据外传（netexfil）============
  {
    id: 'NET-001',
    category: 'netexfil',
    severity: 'high',
    desc: '向硬编码公网 IP 发起请求',
    why: '正常业务极少直连裸 IP。硬编码 IP 是数据回传/ C2 通信的常见形态，且绕过域名校验。',
    pattern: /['"]https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/,
    fix: '改用域名 + 可配置 baseURL，并在文档中声明全部外部端点。'
  },
  {
    id: 'NET-002',
    category: 'netexfil',
    severity: 'medium',
    desc: '存在明文 HTTP 出站请求（非 localhost）',
    why: '出站数据未加密，链路上可被窃听篡改；也常出现在不成熟/恶意的回传实现中。',
    pattern: /['"]http:\/\/(?!localhost|127\.0\.0\.1)/,
    fix: '全部出站请求使用 HTTPS。'
  },
  {
    id: 'NET-003',
    category: 'netexfil',
    severity: 'high',
    desc: '请求方法为 POST 且携带拼接体（可能将本地数据外发）',
    why: '读文件/查库再把结果 POST 出去，是"只读工具"偷渡数据外传的典型形态。',
    pattern: /(fetch|axios(\.\w+)?|https?\.request)\s*\([^)]{0,160}(method\s*:\s*['"]POST['"]|body\s*:)/is,
    fix: '如需上报遥测，请在 README 显式声明数据范围并提供关闭开关；默认不外发任何用户数据。'
  },

  // ============ 供应链（supplychain，仅作用于包清单文件）============
  {
    id: 'SUP-001',
    category: 'supplychain',
    severity: 'critical',
    desc: 'package.json 含 preinstall/postinstall 脚本',
    why: '安装期脚本在 npm install 时以用户权限直接执行，是 npm 供应链攻击的第一载荷位。MCP server 被宿主自动安装时尤其危险。',
    pattern: /"(pre|post)install"\s*:\s*"[^"]+"/,
    fix: '移除安装期脚本；如必须构建，改用 prepare 且内容仅限本地构建工具调用。'
  },
  {
    id: 'SUP-002',
    category: 'supplychain',
    severity: 'high',
    desc: '依赖直接指向 git / 非注册表 URL',
    why: '绕过 npm registry 审计与锁定，代码可在任意时刻被上游替换，不可复现也不可审计。',
    pattern: /"(github:[^"]+|git\+https?:\/\/[^"]+)"|git\+https?:\/\/[^\s#]+/,
    fix: '使用 npm registry / PyPI 发布的固定版本；确需 fork 请自行发布带版本号的包。'
  },
  {
    id: 'SUP-003',
    category: 'supplychain',
    severity: 'medium',
    desc: '依赖版本为 * 或 latest（未锁定）',
    why: '浮动版本意味着任何一次上游更新（包括被投毒的版本）都会被自动拉入。',
    pattern: /:\s*["'](latest|\*)["']/,
    fix: '固定到精确版本（配合 lockfile）。'
  },
  {
    id: 'SUP-004',
    category: 'supplychain',
    severity: 'critical',
    desc: '依赖名命中已知 typosquat 特征名',
    why: '知名包的拼写变体（crossenv→cross-env 之类）是 npm 投毒最经典的手法，安装即中招。',
    pattern: /"(crossenv|reqeusts|colof|react-dome|exprees|lodahs|node-fetchs|axioss|typescripts|commaqnder)"/,
    fix: '核对 npm 官方包名的正确拼写，删除该依赖。'
  },

  {
    id: 'SUP-005',
    category: 'supplychain',
    severity: 'low',
    desc: 'requirements.txt 存在未固定版本的依赖',
    why: 'pip 安装未锁定的包意味着任何一次上游更新（包括被投毒的版本）都会被自动拉入，且不可复现。',
    pattern: /^[A-Za-z0-9][A-Za-z0-9_.-]*(\[[^\]]+\])?\s*$/m,
    fix: '用 pip freeze 或 uv 固定全部版本，并提交 lock 文件。'
  },

  // ============ 密钥暴露（secrets）============
  {
    id: 'SEC-001',
    category: 'secrets',
    severity: 'critical',
    desc: '源码中硬编码疑似真实密钥（OpenAI/Anthropic/AWS/GitHub/Slack/Google）',
    why: '已发布的密钥等于公开泄露，爬虫几分钟内就会捡走并滥用。',
    // \b 边界防止 "task-xxx" 之类单词尾部误命中 sk-；sk- 允许连字符段（覆盖 sk-proj- / sk-ant-api03- 等新格式）
    pattern: /\b(sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|gh[psor]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35})\b/,
    fix: '立即吊销该密钥；改用环境变量注入，并在 .gitignore 排除 .env。'
  },
  {
    id: 'SEC-002',
    category: 'secrets',
    severity: 'high',
    desc: 'api_key/secret/token/password 被赋值为长字面量',
    why: '16 位以上的字面量赋值给凭证类变量，大概率是硬编码凭证或测试后忘记移除的真实凭证。',
    pattern: /(api[_-]?key|secret|token|password|passwd)\s*[:=]\s*['"][A-Za-z0-9+/_-]{16,}['"]/i,
    fix: '凭证只走环境变量/密钥管理器；代码里保留占位符。'
  },
  {
    id: 'SEC-003',
    category: 'secrets',
    severity: 'medium',
    desc: '日志语句输出凭证相关变量',
    why: '日志会把密钥写进终端/日志文件，MCP 常驻进程的日志是长期泄露源。',
    pattern: /(console|logging|logger)\.(\w+)\s*\([^)]*\b(secret|token|password|api[_-]?key)\b/i,
    fix: '删除凭证日志；调试期使用脱敏工具函数。'
  }
];

module.exports = { RULES, SEVERITY_WEIGHT, CATEGORY_CAP, DECAY_AFTER, DECAY_FACTOR, MANIFEST_BASENAMES };
