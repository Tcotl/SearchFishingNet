// 研判记录 / AI 裁决的展示辅助函数与映射

export const verdictTag: Record<string, { label: string; type: 'danger' | 'warning' | 'success' | 'info' | 'primary' }> = {
  phishing: { label: '假冒钓鱼', type: 'danger' },
  malware_distribution: { label: '投毒下载', type: 'danger' },
  brand_abuse: { label: '蹭品牌', type: 'warning' },
  suspicious: { label: '可疑待定', type: 'warning' },
  benign: { label: '正常', type: 'success' },
  unrelated: { label: '无关', type: 'info' },
}

export const finalTag: Record<string, { label: string; type: 'danger' | 'warning' | 'success' | 'info' }> = {
  malicious: { label: '恶意', type: 'danger' },
  policy: { label: '策略封堵', type: 'danger' },
  benign: { label: '正常', type: 'success' },
  monitor: { label: '监控', type: 'warning' },
  review: { label: '待复核', type: 'warning' },
}

export const dispositionTag: Record<string, { label: string; type: 'danger' | 'warning' | 'success' | 'info' }> = {
  auto_blocked: { label: '已封堵', type: 'danger' },
  policy_blocked: { label: '策略封堵', type: 'danger' },
  monitored: { label: '监控中', type: 'warning' },
  pending_review: { label: '待复核', type: 'warning' },
  allowed: { label: '已放行', type: 'success' },
}

export const statusTag: Record<string, { label: string; type: 'danger' | 'warning' | 'success' | 'info' }> = {
  active: { label: '生效中', type: 'info' },
  false_positive: { label: '误报', type: 'info' },
  allowed: { label: '已放行', type: 'success' },
  expired: { label: '已过期', type: 'info' },
}

export const factorNames: Record<string, string> = {
  official: '官方域名映射',
  whitelist: '白名单',
  threat_intel: '威胁情报',
  icp: 'ICP 备案',
  similarity: '域名相似度',
  domain_age: '注册年龄',
  ssl: 'SSL 证书',
  tld: 'TLD 风险',
  url_feature: 'URL 特征',
  channel: '分发渠道',
  strict_pass: '放行策略',
}

export function jobTypeLabel(t: string): string {
  return { pipeline: '采集+研判', crawl: '仅采集', ingest: '研判文件', judge: '单域研判', rescore: '重评分', rejudge_pending: '重判待复核', sample_hunt: '样本猎取', sample_analyze: '样本分析', agent_discover: 'Agent扩展采集', dispatch_block: '封堵下发' }[t] ?? t
}

const JOB_STATUS: Record<string, 'info' | 'primary' | 'success' | 'danger'> = {
  pending: 'info', running: 'primary', success: 'success', failed: 'danger',
}

export function jobStatusTag(s: string): 'info' | 'primary' | 'success' | 'danger' {
  return JOB_STATUS[s] ?? 'info'
}

export function fmtTime(ts: number | null): string {
  if (!ts) return '-'
  return new Date(ts * 1000).toLocaleString('zh-CN', { hour12: false })
}

export function fmtIso(v: string | undefined | null): string {
  if (!v) return '-'
  return v.replace('T', ' ').slice(0, 16)
}
