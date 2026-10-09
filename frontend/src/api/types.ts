// 与后端 Pydantic/JSON 结构对齐的 TS 类型定义

export type Verdict = 'phishing' | 'malware_distribution' | 'brand_abuse' | 'suspicious' | 'benign' | 'unrelated' | ''
export type Final = 'malicious' | 'benign' | 'monitor' | 'review' | ''
export type Disposition = 'auto_blocked' | 'policy_blocked' | 'monitored' | 'pending_review' | 'allowed' | ''
export type RecordStatus = 'active' | 'false_positive' | 'allowed' | 'expired'
export type JobStatus = 'pending' | 'running' | 'success' | 'failed'
export type JobType = 'pipeline' | 'crawl' | 'ingest' | 'judge' | 'rescore' | 'rejudge_pending' | 'sample_hunt' | 'sample_analyze' | 'agent_discover' | 'dispatch_block'

export interface ScoreFactor {
  factor: string
  delta: number
  detail: string
}

export interface RuleScore {
  domain: string
  score: number
  tier: string
  threat_intel_hit: boolean
  breakdown: ScoreFactor[]
}

export interface SearchHit {
  keyword: string
  engine: string
  rank: number
  title: string
  url: string
  domain: string
  description: string
  display_url: string
}

export interface DownloadLink {
  url: string
  text: string
  host: string
  netdisk: boolean
  offsite: boolean
}

export interface Evidence {
  domain: string
  ok: boolean
  final_url: string
  http_status: number | null
  page_title: string
  text_excerpt: string
  form_fields: { type: string; name: string; placeholder: string }[]
  external_links: string[]
  download_links: DownloadLink[]
  brand_mentions: string[]
  favicon_sha1: string
  screenshot_path: string
  error: string
}

export interface AiVerdict {
  verdict: Verdict
  confidence: number
  impersonated_brand: string
  evidence: string[]
  risk_points: string[]
  recommendation: string
  channel: string
}

export interface BrandCandidate {
  domain: string
  brand: string
  source: 'ai_benign' | 'brand_mention'
  ai_verdict: string
  page_title: string
  age_days: number | null
  priority: number
}

export interface ThreatRecord {
  id: string
  created: string
  domain: string
  hits: SearchHit[]
  score: RuleScore | null
  evidence: Evidence | null
  ai_verdict: AiVerdict | null
  final: Final
  disposition: Disposition
  status: RecordStatus
  note?: string
  ttl_days: number
  priority?: number
  priority_tier?: 'high' | 'medium' | 'low'
  priority_reasons?: string[]
  facts?: {
    rdap?: { registered?: string | null; age_days?: number | null }
    icp?: { beian?: string; owner?: string; error?: string }
    vt?: { malicious?: number; suspicious?: number; reputation?: number; error?: string }
  }
}

export interface Job {
  id: string
  type: JobType
  params: Record<string, unknown>
  status: JobStatus
  created_at: number
  started_at: number | null
  finished_at: number | null
  progress_lines: number
  progress_tail: string[]
  result: Record<string, unknown> | null
  error: string
}

export interface DashboardSummary {
  total: number
  blocked_active: number
  pending_review: number
  false_positives: number
  malicious: number
  monitored: number
  allowed: number
  by_status: Record<string, number>
  by_final: Record<string, number>
  verdicts: Record<string, number>
  trend: { date: string; new: number; blocked: number }[]
  top_keywords: [string, number][]
  recent: {
    domain: string
    final: Final
    disposition: Disposition
    status: RecordStatus
    score: number | null
    ai_verdict: Verdict
    ai_confidence: number
    created: string
  }[]
}

export interface Settings {
  ai_base_url: string
  ai_model: string
  ai_vision_model: string
  ai_jev_model: string
  ai_jev_url: string
  ai_api_key_set: boolean
  vt_api_key_set: boolean
  icp_api_url: string
  icp_api_key_set: boolean
  ai_block_confidence: number
  ai_consistency_gap: number
  strict_download_policy: boolean
  strict_official_only: boolean
  skip_evidence_default: boolean
  block_webhook_url: string
  adguard_url: string
  adguard_user: string
  adguard_pass_set: boolean
  adguard_blocklist_url: string
  data_dir: string
  project_root: string
}

export interface RecordsPage {
  total: number
  page: number
  page_size: number
  items: ThreatRecord[]
}

export interface BlocklistInfo {
  count: number
  domains: string[]
  artifacts: string[]
  dir: string
}

// ---------------- 样本分析 ----------------

export interface SampleListItem {
  sha256: string
  source_domain: string
  source_url: string
  file_name: string
  size: number
  md5: string
  sha1: string
  ftype: string
  status: string
  risk_level: string
  c2_count: number
  created_at: number
  analyzed_at: number | null
}

export interface SampleC2 {
  indicator: string
  type: string
  confidence: number
  evidence: string
}

export interface SampleDetail extends SampleListItem {
  static_report: {
    file: { name: string; size: number; md5: string; sha1: string; sha256: string; entropy: number; type: string }
    pe: {
      machine: string
      compiled: string
      subsystem: string
      sections: { name: string; va: string; size: number; entropy: number; packed: boolean }[]
      imports: Record<string, string[]>
      import_signals: Record<string, string[]>
    } | null
    installer: string | null
    packed?: boolean
    iocs: {
      urls: string[]
      ips: string[]
      domains: string[]
      registry: string[]
      commands: string[]
      suspicious_strings: string[]
    }
    string_count: number
  }
  ai_report: {
    family_guess?: string
    risk_level?: string
    behavior_chain?: string[]
    capabilities?: string[]
    c2_addresses?: SampleC2[]
    dropped_files?: string[]
    persistence?: string
    summary?: string
    error?: string
    raw?: string
  } | null
}
