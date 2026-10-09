import { ElMessage } from 'element-plus'
import type {
  BlocklistInfo, BrandCandidate, DashboardSummary, Job, RecordsPage, SampleDetail, SampleListItem,
  Settings, ThreatRecord,
} from './types'

const BASE = '/api'

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let resp: Response
  try {
    resp = await fetch(BASE + path, {
      headers: { 'Content-Type': 'application/json' },
      ...init,
    })
  } catch (e) {
    ElMessage.error('后端服务不可达，请确认平台服务已启动')
    throw e
  }
  if (!resp.ok) {
    if (resp.status === 401 && !path.startsWith('/auth/')) {
      // 会话失效 → 回登录页（登录接口自身的 401 属业务错误，不跳转）
      window.location.href = '/login'
      throw new Error('未登录或会话已过期')
    }
    let detail = `HTTP ${resp.status}`
    try {
      const body = await resp.json()
      detail = body.detail || detail
    } catch { /* keep default */ }
    ElMessage.error(String(detail))
    throw new Error(detail)
  }
  return resp.json() as Promise<T>
}

export const api = {
  // 认证
  login: (username: string, password: string) =>
    request<{ ok: boolean; username: string }>('/auth/login', {
      method: 'POST', body: JSON.stringify({ username, password }),
    }),
  logout: () => request<{ ok: boolean }>('/auth/logout', { method: 'POST' }),
  changePassword: (old_password: string, new_password: string, confirm_password: string) =>
    request<{ ok: boolean }>('/auth/change-password', {
      method: 'POST', body: JSON.stringify({ old_password, new_password, confirm_password }),
    }),
  // 看板
  dashboard: () => request<DashboardSummary>('/dashboard/summary'),
  dashboardTrends: (days = 30) =>
    request<{ series: { date: string; discovered: number; blocked: number; human_review: number }[]; agreement: { rate: number | null; total: number; ai_too_strict: number; ai_too_lenient: number } }>(`/dashboard/trends?days=${days}`),
  dashboardOverview: () =>
    request<{ kpi: { new_today: number; new_yesterday: number; blocked_today: number; blocked_total: number; total: number }; brand_top: { brand: string; count: number }[]; funnel: { stage: string; count: number }[]; health: { ai_configured: boolean; ai_model: string; ai_vision_model: string | null; ai_jev_model: string | null; samples: number; samples_analyzed: number; keywords_total: number; whitelist?: number; data_freshness: number | null } }>('/dashboard/overview'),
  // 记录
  records: (query: Record<string, string | number | undefined>) => {
    const qs = new URLSearchParams()
    Object.entries(query).forEach(([k, v]) => {
      if (v !== undefined && v !== '') qs.set(k, String(v))
    })
    return request<RecordsPage>(`/records?${qs}`)
  },
  record: (domain: string) => request<ThreatRecord>(`/records/${domain}`),
  feedback: (domain: string, body: { kind: string; note?: string; add_whitelist?: boolean }) =>
    request<{ ok: boolean; blocked_count: number }>(`/records/${domain}/feedback`, {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  batchFeedback: (domains: string[], kind: string, note?: string) =>
    request<{ ok: boolean; processed: number; missing: string[]; blocked_count: number }>(
      '/records/batch-feedback', { method: 'POST', body: JSON.stringify({ domains, kind, note }) }),
  // 任务
  createJob: (type: string, params: Record<string, unknown>) =>
    request<Job>('/jobs', { method: 'POST', body: JSON.stringify({ type, params }) }),
  jobs: () => request<Job[]>('/jobs'),
  job: (id: string) => request<Job>(`/jobs/${id}`),
  uploads: () => request<{ filename: string; size: number; mtime: number }[]>('/jobs/uploads/list'),
  upload: async (file: File) => {
    const form = new FormData()
    form.append('file', file)
    const resp = await fetch(`${BASE}/jobs/uploads`, { method: 'POST', body: form })
    if (!resp.ok) throw new Error(`上传失败: HTTP ${resp.status}`)
    return resp.json() as Promise<{ filename: string; size: number }>
  },
  trainingStats: () =>
    request<{ total: number; agree: number; rate: number | null; ai_too_strict: number; ai_too_lenient: number; exemplars: number }>('/dict/training/stats'),
  trainingExport: () => `${BASE}/dict/training/export`,
  // 设备接管
  testDispatch: () =>
    request<{ ok: boolean; message: string }>('/settings/test-dispatch', { method: 'POST' }),
  // 封堵
  blocklist: () => request<BlocklistInfo>('/blocklist'),
  artifact: async (name: string) => {
    const resp = await fetch(`${BASE}/blocklist/files/${name}`)
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
    return resp.text()
  },
  regenerate: () => request<{ count: number }>('/blocklist/regenerate', { method: 'POST' }),
  // 词库
  keywords: () => request<{ keywords: string[] }>('/dict/keywords'),
  keywordGroups: () =>
    request<{ groups: { category: string; keywords: string[] }[]; total: number }>('/dict/keywords/groups'),
  addKeyword: (keyword: string) =>
    request<{ ok: boolean }>('/dict/keywords', { method: 'POST', body: JSON.stringify({ keyword }) }),
  removeKeyword: (keyword: string) =>
    request<{ ok: boolean }>(`/dict/keywords/${encodeURIComponent(keyword)}`, { method: 'DELETE' }),
  whitelistEntries: () =>
    request<{ entries: { domain: string; note: string; source: string; enabled: boolean; added_at: number }[]; enabled_count: number }>('/dict/whitelist'),
  addWhitelistBulk: (domains: string, note: string) =>
    request<{ ok: boolean; added: number; duplicates: number }>('/dict/whitelist', {
      method: 'POST',
      body: JSON.stringify({ domains, note }),
    }),
  updateWhitelist: (domain: string, patch: { enabled?: boolean; note?: string }) =>
    request<{ ok: boolean }>(`/dict/whitelist/${encodeURIComponent(domain)}`, {
      method: 'PUT',
      body: JSON.stringify(patch),
    }),
  removeWhitelist: (domain: string) =>
    request<{ ok: boolean }>(`/dict/whitelist/${encodeURIComponent(domain)}`, { method: 'DELETE' }),
  brands: () => request<{ brands: { brand: string; officials: string[]; custom?: boolean }[] }>('/dict/brands'),
  brandCandidates: () =>
    request<{ items: BrandCandidate[]; total: number }>('/dict/brand-candidates'),
  confirmBrandCandidate: (brand: string, domains: string[]) =>
    request<{ ok: boolean; added: number; auto_allowed: string[]; blocked_count: number }>(
      '/dict/brand-candidates/confirm', { method: 'POST', body: JSON.stringify({ brand, domains }) }),
  removeBrandOfficial: (brand: string, domain: string) =>
    request<{ ok: boolean }>(`/dict/brands/${encodeURIComponent(brand)}/${encodeURIComponent(domain)}`, { method: 'DELETE' }),
  // 样本分析
  samples: () =>
    request<{ items: SampleListItem[] }>('/samples'),
  sample: (sha256: string) =>
    request<SampleDetail>(`/samples/${sha256}`),
  uploadSample: async (file: File, note: string) => {
    const form = new FormData()
    form.append('file', file)
    if (note) form.append('note', note)
    const resp = await fetch(`${BASE}/samples/upload`, { method: 'POST', body: form })
    if (!resp.ok) {
      let detail = `HTTP ${resp.status}`
      try {
        const body = await resp.json()
        detail = body.detail || detail
      } catch { /* keep default */ }
      ElMessage.error(String(detail))
      throw new Error(detail)
    }
    return resp.json() as Promise<{
      sha256: string; sha1: string; md5: string; file_name: string
      size: number; ftype: string; duplicate: boolean; static_report: unknown
    }>
  },

  // 设置
  settings: () => request<Settings>('/settings'),
  saveSettings: (patch: Record<string, unknown>) =>
    request<Settings>('/settings', { method: 'PUT', body: JSON.stringify(patch) }),
  testAi: () => request<{ ok: boolean; message: string }>('/settings/test-ai', { method: 'POST' }),
}
