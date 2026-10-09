# SearchFishingNet —— 基于搜索引擎的钓鱼网络威胁情报系统设计

> 对应安全建设思路：《【安全建设】企业安全下的银狐互联网下载投毒防护》
> 方案一：基于搜索引擎 SEO 排名筛选的 DNS 封堵策略 → 本文将其升级为"AI 严判 + 情报闭环"的完整系统。

---

## 1. 背景与目标

银狐组织通过伪造钉钉、向日葵、ToDesk、Chrome、WPS 等热门办公软件的官网/下载站，利用 SEO
把恶意站点顶到搜索结果前列，投毒目标多为甄别能力有限的企业普通员工。原始方案为：

```
搜索关键词列表 → 搜索引擎爬虫(前3-4页) → 域名提取 → 域名置信度评分
    → 低/中置信度：自动封堵；高置信度：人工评判
```

本系统在此基础上补齐两块能力：

1. **AI 严判**：规则评分只能回答"像不像钓鱼站"，AI 多模态裁决回答"是不是钓鱼站"，
   以截图 + 页面正文 + 结构化特征做最终定性，压缩人工介入。
2. **威胁情报闭环**：把封堵从"一次性动作"升级为可运营的情报生产——每个域名一份带证据链
   的情报记录（IoC + 评分依据 + AI 裁决理由 + 截图），支持下发、复核、反馈、过期。

### 设计原则

- **采集不重写**：现有四引擎爬虫（百度/必应/360/搜狗）保持不动，系统直接消费其 JSON 输出。
- **分级研判漏斗**：便宜的规则先跑，贵的 AI 只看漏下来的可疑目标，控制成本。
- **白名单优先级最高**：品牌官方域名硬编码在本地词库，优先级高于 AI 判断（对抗 GEO 投毒污染白名单的问题）。
- **所有封堵动作必须留证据**：截图 + 正文摘录 + AI 裁决理由落库，支持事后审计与误报回滚。

---

## 2. 总体架构

```
┌─────────────────────────────────────────────────────────────────┐
│                          采集层                                  │
│  Browser Web Crawler（现有）          AI 关键词扩展（可选）        │
│  baidu / bing / 360 / sogou           词库: 银狐高频软件词        │
└──────────────┬──────────────────────────────────────────────────┘
               │ unified_search_results_*.json / domains_*.txt
┌──────────────▼──────────────────────────────────────────────────┐
│                        预处理层                                  │
│  重定向还原 → 域名提取 → 去重合并 → 白名单放行 → 官方域名放行      │
└──────────────┬──────────────────────────────────────────────────┘
┌──────────────▼──────────────────────────────────────────────────┐
│                        研判层（三级漏斗）                          │
│  L1 规则评分  置信度0-100: 相似度/SSL/RDAP注册年龄/TLD/URL特征      │
│              ├─ ≥70 可信          → 放行，记录白名单依据           │
│              └─ <70 可疑/高危      ↓ 进入 L2                       │
│  L2 动态取证  Playwright 无害化访问: 截图/正文/表单/外链/favicon    │
│  L3 AI 严判  多模态裁决(截图+正文+特征) 两通道一致性 → 最终定性     │
└──────────────┬──────────────────────────────────────────────────┘
┌──────────────▼──────────────────────────────────────────────────┐
│                        情报层                                    │
│  SQLite 情报库: 域名档案 / 裁决记录 / 证据链 / 情报记录(STIX风格)   │
│  状态机: active → monitored / auto_blocked / pending_review       │
│         → expired / false_positive(反馈)                         │
└──────────────┬──────────────────────────────────────────────────┘
┌──────────────▼──────────────────────────────────────────────────┐
│                        处置层                                    │
│  封堵产物: hosts / dnsmasq / BIND RPZ / ACL CSV / 封堵工单JSON     │
│  通知: Webhook(飞书/钉钉/企微)   未来: 安全设备 MCP/API 下发        │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. 研判层详细设计

### 3.1 L1 规则评分（域名置信度，0-100）

从 100 起评，各因子加权修正。返回分数 + 逐因子依据（用于审计与 AI 输入）。

| 因子 | 数据源 | 分值 | 说明 |
|---|---|---|---|
| 白名单命中 | 本地词库 | 直接置 100 | 主流正规站，永不封堵 |
| 品牌官方域名 | 本地词库 `BRAND_OFFICIALS` | 直接置 100 | 品牌→官方域名硬映射（最长后缀匹配消歧），对抗 GEO 投毒 |
| 威胁情报命中 | VirusTotal / OpenPhish（可选 API） | 直接置 0 | 已知恶意，跳过 AI 直接封堵候选 |
| 域名相似度 | 同形字归一 + 编辑距离 vs 品牌库 | -40 ~ 0 | 假冒核心信号：`dingtalk-download.top`、`向日葵远程-cn.xyz` |
| **分发渠道** | 已知下载站名单 + 域名标签特征 | **封顶 69** | 第三方软件下载站（ZOL/太平洋/华军/pc6 等）与 soft*/down*/xiazai* 标签域名是银狐投毒链主要分发环节，**一律待观察，绝不 trusted** |
| 注册年龄 | RDAP（rdap.org，免费无 Key） | -15 ~ +20 | <90 天强恶意信号 |
| ICP 备案 | 备案查询 API（可选，需 Key） | +25 | 国内合规企业站强可信信号 |
| SSL 证书 | 站点证书解析 | -10 ~ +10 | 有效证书 +10；无 TLS -10 |
| TLD 风险 | 本地高危 TLD 表 | -10 | `.top/.xyz/.icu/.cyou/.zip` 等 |
| URL 特征 | 正则 | -5 ~ -15 | 路径含 download/setup/破解/绿色版、punycode、@ 绕转、品牌词出现在非官方子域 |

**分发渠道管控（严格下载管控，默认开启）**：企业场景只放行品牌官方下载渠道——
- **已知第三方下载站**（ZOL/太平洋/华军/mydown/pc6/duote 等）：策略封堵（`policy_blocked`），直接进 DNS 黑名单，不做研判（政策决定，非威胁定性），可复核回滚；
- **模式命中下载渠道**（`soft*/down*/xiazai*` 标签）：封顶 39 分（可疑）进 AI 严判漏斗；
- 评分模型升级或策略变更后，CLI `python run_pipeline.py rescore` / 平台「存量重评分」任务重算分数并执行策略（不覆盖 AI 裁决处置与人工误报回滚）。
- 设置页可关闭（宽松模式：下载渠道封顶 69 待观察，不策略封堵）；环境变量 `SFN_STRICT_DOWNLOAD=0`。

评分模型升级后可对存量记录重算：CLI `python run_pipeline.py rescore` 或平台任务"存量重评分"。
重评分只刷新分数展示，**不改变处置**——处置变化必须经研判流程或人工复核。

分级与路由：

| 置信度 | 分级 | 路由 |
|---|---|---|
| ≥ 70 | 可信 | 放行，不消耗取证/AI 资源 |
| 40 ~ 69 | 待观察 | L2 取证 + L3 AI 严判；AI 不能定论 → `pending_review`（人工） |
| 15 ~ 39 | 可疑 | L2 取证 + L3 AI 严判；AI 判恶意 → 自动封堵 |
| < 15 | 高危 | 同上，AI 确认后置顶封堵；威胁情报已命中则跳过 AI 直接封堵候选 |

### 3.2 L2 动态取证（无害化访问）

Playwright 无头访问，专抓"站点实际长什么样"：

- 截图（1280×800 视口 PNG）、`<title>`、正文文本（截断 4000 字）、表单数量与字段名、
  外链、favicon（算 hash 供同类聚类）、最终落地 URL、HTTP 状态。
- 安全护栏：禁用下载、禁用推送通知、导航仅允许 http/https、单页超时熔断、
  访问记录只做取证不上传任何企业信息。

### 3.3 L3 AI 严判（核心新增）

**模型接入**：OpenAI 兼容协议，默认指向智谱 BigModel（`glm-4.5v` 多模态），
`SFN_AI_API_KEY / SFN_AI_BASE_URL / SFN_AI_MODEL` 环境变量可切换任意厂商。

**输入（裁决材料包）**：
1. 截图（base64）
2. 页面正文摘录 + title
3. 结构化特征：L1 评分明细、RDAP 注册年龄、SSL 结论、相似度报告
4. 搜索语境：命中关键词、来源引擎、搜索结果标题与摘要

**裁决类别**（六分类，比二分类更贴近运营）：

| verdict | 含义 | 处置 |
|---|---|---|
| `phishing` | 假冒官网/登录钓鱼 | 自动封堵 |
| `malware_distribution` | 投毒下载站（捆绑木马/假安装包） | 自动封堵 |
| `brand_abuse` | 擦边蹭品牌但暂无直接危害 | 监控 |
| `suspicious` | 证据不足，倾向可疑 | 人工复核 |
| `benign` | 正版官网/正常站 | 放行 |
| `unrelated` | 与关键词无关的无关结果 | 放行 |

**"严判"机制（对抗误报与提示词注入）**：

1. **本地官方映射一票通过**：域名 ∈ 品牌官方映射 → 不送 AI，直接放行。AI 只裁非官方站。
2. **双通道一致性**：通道 A（仅文本+特征）与通道 B（截图+全文）独立裁决，
   结论一致且置信度差 < 25 → 采信；不一致 → 强制降级 `suspicious` 交人工。
   裁决理由必须引用页面原文（证据强制引用），引用为空视为无效裁决。
3. **提示词注入防护**：页面正文先剥离控制字符与疑似指令模式
   （"忽略以上指令/ignore previous instructions"等），正文在 prompt 中以不可信数据段包裹。
4. **温度 0 + JSON 强约束输出**：`verdict/confidence/impersonated_brand/evidence[]/risk_points[]/recommendation`。

### 3.3.1 严格放行策略（默认开启）

只有**品牌官方域名**（及人工审定的白名单）自动放行；其余域名——包括没有任何负面信号的
长尾站——一律封顶 69 分，强制进入取证与 AI 研判漏斗（评分明细记为"放行策略"因子）。
设置页可关闭；环境变量 `SFN_STRICT_OFFICIAL_ONLY=0`。

### 3.3.2 取证精度与下载链路一致性

L2 取证在截图/正文之外额外提取两类高价值信号：

- **下载链路**：页面所有下载入口（安装包后缀链接或"下载"按钮）指向的主机，并标记
  `网盘/短链`（lanzou/ctfile/百度网盘等 NETDISK_PATTERNS）、`站外主机`、`本站托管`；
- **页面品牌宣称**：title/正文中出现的品牌词，用于 AI 核对"宣称品牌 vs 域名归属"。

L3 严判 prompt 对应规则：官方站安装包托管在官方域名/CDN；下载入口指向网盘/短链/站外
主机是投毒下载站（malware_distribution）的强信号；无下载入口的资讯页按 brand_abuse/
benign/unrelated 处理。

### 3.3.3 多模型接入（常规推理模型 + 视觉模型 + Jev 结构化仲裁）

AI 严判支持任意 OpenAI 兼容模型组合 + Jev 结构化评估模型，三类模型各司其职：

| 角色 | 通道 | 配置 | 说明 |
|---|---|---|---|
| 主判模型（文本推理） | 通道A：材料推理裁决 | `ai_model` | GLM-4.6 / DeepSeek-R1 等常规推理模型即可胜任 |
| 视觉模型（可选） | 通道B：截图+全文核验 | `ai_vision_model`，留空主模型兼任 | GLM-4.5V 等多模态模型 |
| Jev 结构化仲裁（可选） | 通道C：概率型定性 | `ai_jev_model`，留空不启用 | bocha-jev-v1 等 TypeSafe SystemOne 协议模型，输出真假概率/定性概率分布/置信度，不生成自然语言 |

适配器能力：推理模型思考输出自动解析（`reasoning_content` 回退、`<think>` 剥离）；
拒绝 `temperature` 参数自动去参重试；模型不支持图片自动探测并降级单通道（裁决标注"单通道·文本"）；
三模型独立连通性测试。合并规则：

- 通道A/B 一致且置信度差 ≤ `ai_consistency_gap` → 采信；不一致强制人工；
- 任一通道置信度为 0 → 视为无效信号（如非视觉模型被误配为视觉通道），按另一有效通道定性；
- 通道C 与主裁决一致 → 取均值置信度；分歧 → 取更严重定性、置信度压至 min(≤60) 并转人工
  （Jev 概率型模型不输出证据引用，仅作仲裁不单独触发自动封堵）；
- 主推理通道调用失败/无效时，通道C 可单独兜底定性（标注"Jev单通道"）。

**Jev 结构化评估协议**（TypeSafe SystemOne）：`POST {base}/typesafe/v1/systemone`，请求体
`{model, state(任务上下文), questions}`；问题类型 `noul`（真假概率）/`choice`（`criteria`
为 选项→说明 字典）/`score`（`criteria` 为评分依据列表）；响应含各候选概率分布、argmax 与
校准置信度。端点留空时按 chat 基址推导（`…/gateway/v1` → `…/gateway/typesafe/v1/systemone`），
可用 `ai_jev_url` 显式覆盖。评估延迟约 25ms/次，适合海量记录的独立仲裁与兜底。

**重判待复核任务**：复用已存取证证据（不重新访问站点）对 `pending_review` 记录重新裁决，
用于"先跑采集、后配 AI Key"场景——配置后一键定性存量；词库更新后新命中官方映射的
记录直接放行，不消耗 AI 调用。4 线程并行，主通道连续不可用进入 60s 冷却窗；
裁决前补采 RDAP 注册年龄硬事实（免费、进程内缓存）并持久化 `payload.facts`。

### 3.3.4 硬事实核验与映射自增长

**硬事实**（`fishingnet/facts.py`）：对客观事实源的一手查询，独立于规则评分与 AI——
RDAP 注册年龄（免费无 Key，随 judge/rescore/rejudge 采集并入库 `payload.facts`）、
ICP 备案（配置 ICP_API_URL 后启用，对比备案主体与页面宣称品牌方）、VirusTotal
（配置 VT_API_KEY 后启用，多引擎报恶意可直接定性）。事实作为【硬事实核验】小节
进入 AI 材料包，带研判解读提示（新注册坐床期 / 老域名需更强证据）。

**映射自增长**：词库管理页展示"官方映射候选"——从 AI 放行/复核记录提取"页面宣称
品牌（以页面标题命中的品牌词根为准）但不在映射表"的域名；安全闸排除 AI 恶意嫌疑、
坐床期新注册（<90 天）、网盘/下载渠道分发页；人工一键确认后并入 BRAND_OFFICIALS
（`data/config/brand_officials.json` 持久化，成为最高优先级事实源），对应记录即时
重评分自动放行。误报回滚 → 补映射 → 不再误报的闭环由此收敛。

**复核效率**：`GET /api/records?sort=priority` 按复核优先级排序（AI 有恶意定性但置信
度不足 40 分 / 品牌词 30 / 注册<90 天 30 / 网盘入口与高风险 TLD 12/10，老域名 -15）；
人工复核页支持多选批量处置（`POST /api/records/batch-feedback`，放行/误报自动加白）。

### 3.5 样本分析（AI 样本猎取与行为推断）

对**已确认封堵**（auto_blocked，或显式指定的封堵记录）的站点，从 L2 取证捕获的下载入口
直接拉取载荷做**静态分析 + AI 行为推断**：

- **安全护栏**：样本绝不在本机执行；64MB 大小上限；HTML 响应自动拒绝；样本按 SHA256
  隔离存放 `data/samples/`；网盘/短链入口不可直连自动跳过；存证无直链时自动重访站点刷新下载入口。
- **人工上传**：样本分析页可直接上传本地可疑文件（≤64MB，`POST /api/samples/upload`）——
  哈希落盘隔离 + 静态分析即时完成，随后自动触发 `sample_analyze` 任务做 AI 行为/C2 分析；
  重复上传（同 SHA256）去重且不覆盖已有分析状态；来源线索可随附备注（如"XX 群流传"）。
- **静态提取护栏**：IP 正则带前后向断言，OID/版本号等长点分串（1.3.6.1.4.1…）不会碎片化
  成虚假 C2 候选；C2 候选逐条强制字符串证据并标注置信度，供分析师复核。
- **静态分析**（纯标准库，fishingnet/static_analysis.py）：文件类型识别（PE/MSI/LNK/脚本等）、
  MD5/SHA1/SHA256、整体与分节熵（加壳指标）、PE 头解析（架构/编译时间/子系统/节表/导入表）、
  导入 API 能力信号归类（进程创建/网络下载/持久化/键盘监听/注入/反调试等）、
  ASCII+UTF-16 字符串提取、IOC 提取（URL/IP/域名/注册表/命令行）、安装器识别（Inno/NSIS）。
- **AI 行为分析**（fishingnet/ai_sample_analysis.py）：复用共享 AI 客户端（常规推理模型即可），
  基于静态报告推断行为链、能力、持久化方式、释放文件与 **C2 恶意外连地址候选**——
  每条 C2 必须给出样本字符串级证据与置信度，无证据不列入（严判防编造）。
- **入口**：任务 `sample_hunt`（指定域名或全部 auto_blocked）；封堵记录详情抽屉"样本分析"按钮；
  「重判待复核」任务会顺带补分析已入库未分析的样本。
- **页面**：样本分析（样本库列表 + 详情抽屉：文件信息/AI 行为链/C2 表格/静态报告/隔离区样本取回）。

### 3.6 防 GEO 投毒

笔记中指出的难点——黑灰产污染 AI 联网搜索结果、连带污染白名单判断——在本设计中的对策：

- 白名单判断只依赖**本地硬编码的官方域名映射**，AI 联网搜索结论仅作参考输入，无处置权；
- AI 裁决基于**站点实际渲染内容与截图**，而非搜索摘要（摘要才是 SEO/GEO 投毒的主战场）；
- 官方域名映射变更走人工词库维护流程（PR / 配置变更），AI 不得修改词库。

---

## 4. 情报层设计

### 4.1 情报记录（JSON，STIX 风格简化）

```json
{
  "id": "sfn--<uuid>",
  "created": "2026-09-23T20:00:00+08:00",
  "type": "phishing-site",
  "domain": "dingtalk-download.top",
  "urls": ["https://dingtalk-download.top/setup"],
  "ips": [],
  "favicon_hash": "sha1:...",
  "keyword_context": ["钉钉下载"],
  "engine_sources": {"baidu": {"rank": 2, "title": "..."}},
  "score": {
    "rule_score": 28,
    "rule_breakdown": [{"factor": "similarity", "delta": -40, "detail": "..."}],
    "ai_verdict": "phishing",
    "ai_confidence": 93,
    "ai_evidence": ["页面标题宣称『钉钉官方下载』但域名非官方映射"],
    "final": "malicious"
  },
  "evidence": {"screenshot": "data/evidence/xxx.png", "page_title": "..."},
  "ttl_days": 30,
  "disposition": "auto_blocked",
  "status": "active"
}
```

### 4.2 状态机

```
new → scored → (evidenced) → judged ─┬→ auto_blocked (active, TTL 30d)
                                     ├→ monitored   (brand_abuse)
                                     ├→ pending_review (低置信 AI 结论)
                                     └→ allowed
auto_blocked → false_positive  (人工反馈, 从封堵产物移除并回写词库)
任意 → expired (TTL 到期, 复跑研判)
```

---

## 5. 处置层设计

| 产物 | 用途 |
|---|---|
| `hosts` | 终端 Hosts 黑名单（最简落地） |
| `dnsmasq.conf` | 内网 DNS（`address=/domain/`） |
| `rpz.zone` | BIND Response Policy Zone |
| `acl_domain.csv` | 防火墙/上网行为管理导入 |
| `block_orders.json` | 封堵工单：含证据链，供安全设备 API/MCP 下发（远期） |
| `report.md` | 本轮运营报告：新增/封堵/复核/放行统计 |

**误报回滚**：`run_pipeline.py feedback <domain> false_positive` 一条命令完成
"移出封堵产物 + 情记录状态改写 + 白名单候选标记"。

---

## 6. 目录结构

```
SearchFishingNet/
├── Browser Web Crawler/        # 现有四引擎爬虫（不改动）
├── fishingnet/                 # 核心包
│   ├── config.py               # 配置与阈值
│   ├── models.py               # 数据模型（dataclass）
│   ├── keywords.py             # 银狐高频词库 + 品牌官方域名映射 + 白名单
│   ├── browser.py              # Playwright 浏览器自动发现
│   ├── scoring.py              # L1 规则评分引擎
│   ├── evidence.py             # L2 动态取证
│   ├── ai_judge.py             # L3 AI 严判（多模态双通道）
│   ├── intel.py                # 情报库（SQLite）
│   ├── blocklist.py            # 封堵产物生成
│   └── pipeline.py             # 编排（支持进度回调，供平台任务流复用）
├── backend/                    # FastAPI 平台后端
│   ├── app/main.py             # 应用装配：路由/CORS/统一鉴权/前端静态托管
│   ├── app/auth.py             # 登录会话：默认 admin/admin（加盐哈希存 data/config/auth.json），
│   │                           #   会话 Cookie sfn_session 7 天（data/config/sessions.json 跨重启有效），
│   │                           #   机器调用可 SFN_API_TOKEN Bearer 旁路；/api 全拦截，登录接口豁免
│   ├── app/store.py            # 运行时配置存储（关键词/白名单增补/设置，data/config/*.json）
│   ├── app/jobs.py             # 进程内任务管理器（进度行缓冲 + SSE）
│   ├── app/tasks.py            # 任务执行体（crawl/ingest/pipeline/judge，线程池运行）
│   └── app/routers_*.py        # 记录/任务/看板/封堵/词库/设置 API
├── frontend/                   # Vue 3 + TypeScript + Element Plus 运营台
│   └── src/{api,views,components,layout,lib}
├── run_pipeline.py             # CLI 入口（与平台共用核心包）
├── docs/DESIGN.md              # 本文档
├── samples/                    # 测试样例
└── data/                       # 运行时数据（库/截图/封堵产物/config/上传）
```

### 6.1 平台架构补充

```
Vue3 SPA (TS, Element Plus, ECharts)
   │  /api/*（开发期 Vite 代理 → 8765；生产期同端口由 FastAPI 托管 dist）
FastAPI
   ├─ 任务 API   POST /api/jobs → 线程池执行 tasks.py → SSE /api/jobs/{id}/events 实时回传
   ├─ 记录 API   列表/详情/截图/复核处置(feedback: confirm_block·false_positive·allow)
   ├─ 看板 API   统计/14天趋势/裁决分布/高频关键词
   ├─ 封堵 API   生效列表/产物预览下载/重新生成
   ├─ 词库 API   关键词与白名单增补 CRUD、品牌映射只读
   └─ 设置 API   AI 接入与阈值，热生效（写入 data/config/settings.json 并应用）
fishingnet 核心包（与 CLI 完全共用，单一事实源）
```

任务在进程内线程池执行（playwright/RDAP 等阻塞调用均在线程中跑），
进度经 pipeline 的回调进入 Job 环形缓冲，前端 EventSource 增量消费。
pipeline 任务支持**断点续跑**（resume）：跳过 24 小时内已产出结果文件的关键词，
仅补采剩余关键词，最后对全部结果文件统一研判——任务中断后重启不丢采集进度。
安全降级策略不变：无 AI Key → `pending_review`，绝不自动封堵；`false_positive` 状态跨轮次持久。

## 7. 使用方式

```bash
# 使用现有爬虫 venv
source "Browser Web Crawler/.venv/bin/activate"

# 1) 采集：直接跑现有爬虫，或用系统代跑
python "Browser Web Crawler/Search_Crawler.py" "钉钉下载"
# 或: python run_pipeline.py crawl "钉钉下载" --engines baidu,bing --max-pages 3

# 2) 研判：消费爬虫 JSON → 评分 → 取证 → AI 严判 → 情报
export SFN_AI_API_KEY=<你的BigModel API Key>
python run_pipeline.py ingest "Browser Web Crawler/unified_search_results_钉钉下载.json"

# 3) 产物
#    data/blocklist/{hosts,dnsmasq.conf,rpz.zone,acl_domain.csv,block_orders.json}
#    data/report.md

# 4) 误报反馈
python run_pipeline.py feedback <domain> false_positive --note "官网换域名了"
```

无 `SFN_AI_API_KEY` 时系统以 `pending_review` 落库不封堵（降级安全）；
`--mock-ai` 提供离线测试通道。

## 8. 路线图（对齐笔记"后续发展"）

| 阶段 | 内容 | 状态 |
|---|---|---|
| P0 | 爬虫接入 + L1 规则评分 + L2 取证 + L3 AI 严判 + 封堵产物 | ✅ 已落地（全量跑批验证） |
| P1 | 联网 Agent 扩展采集 + ICP/VT 正式接入 | ✅ 已落地：`agent_discover` 任务（AI 关键词变体扩展 + 免费引擎必应中国/DDG 双回退，产出进既有研判漏斗）；RDAP 已入库进 AI 材料包，ICP/VT 填 Key 即启用 |
| P2 | 安全专家模型调优（笔记 SecGPT） | ✅ 已落地：专家范例库（人工复核判例 few-shot 注入裁决 prompt，误报范例优先）、训练对 JSONL 导出（`/api/dict/training/export`）、人机一致率度量（看板展示） |
| P3 | 设备 MCP/API 全流程接管（笔记 AISecOps） | ✅ 已落地：封堵工单下发任务（`dispatch_block`）——通用 webhook + AdGuard Home 订阅适配器，设置页配置并可测试连通 |
| P4 | Web 运营台：复核工作流、误报回流、趋势看板 | ✅ 已落地：复核工作流（优先级排序+批量处置）、误报回流（反馈白名单+映射自增长）、30 天趋势看板（发现/封堵/人工复核三线 + 人机一致率） |
