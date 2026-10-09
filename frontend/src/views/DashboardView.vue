<template>
  <div v-loading="loading">
    <!-- 态势头部：标题 + 时间范围 + 数据新鲜度 + 主操作 -->
    <el-card shadow="never" class="block" :body-style="{ padding: '14px 18px' }">
      <div class="saas-head">
        <div class="saas-title">
          <span class="pulse" :class="ov?.health.ai_configured ? 'on' : 'off'"></span>
          <div>
            <div class="h1">威胁态势总览</div>
            <div class="dim">
              数据新鲜度 {{ freshness }}
              <template v-if="ov?.health.ai_configured">
                · AI 研判链路就绪（{{ [ov.health.ai_model, ov.health.ai_vision_model, ov.health.ai_jev_model].filter(Boolean).join(' / ') }}）
              </template>
              <template v-else>· <b class="miss">未配置 AI</b>，全量降级人工复核</template>
            </div>
          </div>
        </div>
        <div class="head-actions">
          <el-radio-group v-model="range" size="small" @change="reloadTrend">
            <el-radio-button :value="7">近 7 天</el-radio-button>
            <el-radio-button :value="30">近 30 天</el-radio-button>
            <el-radio-button :value="90">近 90 天</el-radio-button>
          </el-radio-group>
          <el-button type="danger" :loading="starting" @click="oneKeyScan">
            <el-icon class="btn-ico"><VideoPlay /></el-icon>
            一键采集研判
          </el-button>
        </div>
      </div>
    </el-card>

    <!-- KPI 指标行（含环比） -->
    <el-row :gutter="12" class="block">
      <el-col v-for="card in cards" :key="card.label" :span="4">
        <el-card shadow="never" class="stat" :body-style="{ padding: '14px 16px' }">
          <div class="stat-row">
            <el-icon class="stat-ico" :style="{ background: card.bg, color: card.color }">
              <component :is="card.icon" />
            </el-icon>
            <div class="stat-main">
              <div class="stat-num" :style="{ color: card.color }">{{ card.value }}</div>
              <div class="stat-label">{{ card.label }}</div>
              <div class="stat-delta" :class="card.deltaClass">{{ card.delta ?? '&nbsp;' }}</div>
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <el-alert v-if="summary?.pending_review" type="warning" :closable="false" class="block">
      <div class="alert-row">
        <span>
          有 <b>{{ summary.pending_review }}</b> 条记录待人工终审
          <template v-if="trends?.agreement?.ai_too_lenient">
            ，另检测到 <b class="miss">{{ trends.agreement.ai_too_lenient }}</b> 条 AI 漏判（人工确认恶意而 AI 未判出），建议优先复盘
          </template>
        </span>
        <el-button size="small" type="warning" @click="$router.push('/review')">进入复核工作台</el-button>
      </div>
    </el-alert>

    <!-- 态势图组 -->
    <el-row :gutter="12" class="block equal">
      <el-col :span="16">
        <el-card shadow="never">
          <template #header>
            研判趋势（{{ range }} 天）
            <el-tag v-if="trends?.agreement?.rate != null" size="small"
                    :type="(trends.agreement.rate ?? 0) >= 85 ? 'success' : 'warning'" class="ml">
              人机一致率 {{ trends.agreement.rate }}%
            </el-tag>
            <el-tag v-if="trends?.agreement?.ai_too_lenient" size="small" type="danger" class="ml">
              AI 漏判 {{ trends.agreement.ai_too_lenient }}
            </el-tag>
          </template>
          <div ref="trendEl" class="chart" />
        </el-card>
      </el-col>
      <el-col :span="8">
        <el-card shadow="never" header="AI 裁决分布">
          <div ref="pieEl" class="chart" />
        </el-card>
      </el-col>
    </el-row>

    <!-- 品牌仿冒 Top + 研判漏斗 -->
    <el-row :gutter="12" class="block equal">
      <el-col :span="12">
        <el-card shadow="never" header="品牌被仿冒 Top 10（AI 判恶意）">
          <div ref="brandEl" class="chart" />
        </el-card>
      </el-col>
      <el-col :span="12">
        <el-card shadow="never" header="研判漏斗">
          <div class="funnel" :style="{ height: '260px' }">
            <div v-for="(s, i) in ov?.funnel ?? []" :key="s.stage" class="funnel-row">
              <div class="funnel-stage">{{ s.stage }}</div>
              <div class="funnel-bar-area">
                <div class="funnel-bar" :style="funnelStyle(i, s.count)"></div>
              </div>
              <div class="funnel-num">{{ s.count }}</div>
            </div>
          </div>
          <div class="dim funnel-hint">封堵率 {{ funnelRate }} · 存疑转人工占比 {{ reviewRate }}</div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 最近记录 + 系统健康 -->
    <el-row :gutter="12" class="equal">
      <el-col :span="16">
        <el-card shadow="never" header="最近研判记录">
          <el-table :data="summary?.recent ?? []" size="small"
                    @row-click="() => $router.push('/records')">
            <el-table-column prop="domain" label="域名" min-width="200" />
            <el-table-column label="规则分" width="80">
              <template #default="{ row }">{{ row.score ?? '-' }}</template>
            </el-table-column>
            <el-table-column label="AI 裁决" width="110">
              <template #default="{ row }">
                <el-tag v-if="row.ai_verdict" :type="verdictTag[row.ai_verdict]?.type ?? 'info'" size="small">
                  {{ verdictTag[row.ai_verdict]?.label ?? row.ai_verdict }}
                </el-tag>
                <span v-else>-</span>
              </template>
            </el-table-column>
            <el-table-column label="处置" width="90">
              <template #default="{ row }">
                <el-tag :type="dispositionTag[row.disposition]?.type ?? 'info'" size="small">
                  {{ dispositionTag[row.disposition]?.label ?? (row.disposition || '-') }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column label="时间" width="125">
              <template #default="{ row }">{{ fmtIso(row.created) }}</template>
            </el-table-column>
          </el-table>
        </el-card>
      </el-col>
      <el-col :span="8">
        <el-card shadow="never" header="系统健康" class="health-fill">
          <el-descriptions :column="1" size="small" border class="block">
            <el-descriptions-item label="AI 严判链路">
              <el-tag :type="ov?.health.ai_configured ? 'success' : 'danger'" size="small">
                {{ ov?.health.ai_configured ? '就绪' : '未配置' }}
              </el-tag>
              <span class="dim ml">{{ ov?.health.ai_model }}</span>
            </el-descriptions-item>
            <el-descriptions-item label="视觉 / Jev 通道">
              <span class="mono">{{ ov?.health.ai_vision_model || '—' }} / {{ ov?.health.ai_jev_model || '—' }}</span>
            </el-descriptions-item>
            <el-descriptions-item label="采集词库">
              {{ ov?.health.keywords_total ?? '-' }} 词 · 白名单 {{ ov?.health.whitelist ?? '-' }} 域
            </el-descriptions-item>
            <el-descriptions-item label="样本隔离库">
              {{ ov?.health.samples ?? 0 }} 个 · 已分析 {{ ov?.health.samples_analyzed ?? 0 }}
            </el-descriptions-item>
            <el-descriptions-item label="人机一致率">
              <el-tag v-if="trends?.agreement?.rate != null" size="small"
                      :type="(trends.agreement.rate ?? 0) >= 85 ? 'success' : 'warning'">
                {{ trends.agreement.rate }}%（n={{ trends.agreement.total }}）
              </el-tag>
              <span v-else class="dim">待人工反馈样本</span>
            </el-descriptions-item>
          </el-descriptions>
          <el-card shadow="never" header="高频命中关键词" :body-style="{ padding: '10px 14px' }">
            <div class="kw-wrap">
              <el-tag v-for="[kw, n] in summary?.top_keywords ?? []" :key="kw" class="kw" type="info" disable-transitions>
                {{ kw }} · {{ n }}
              </el-tag>
              <el-empty v-if="!summary?.top_keywords?.length" description="暂无数据" :image-size="40" />
            </div>
          </el-card>
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<script setup lang="ts">
import * as echarts from 'echarts'
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api } from '../api/client'
import type { DashboardSummary } from '../api/types'
import { dispositionTag, fmtIso, verdictTag } from '../lib/display'

interface Overview {
  kpi: { new_today: number; new_yesterday: number; blocked_today: number; blocked_total: number; total: number }
  brand_top: { brand: string; count: number }[]
  funnel: { stage: string; count: number }[]
  health: {
    ai_configured: boolean; ai_model: string; ai_vision_model: string | null; ai_jev_model: string | null
    samples: number; samples_analyzed: number; keywords_total: number; whitelist?: number
    data_freshness: number | null
  }
}

const router = useRouter()
const loading = ref(true)
const starting = ref(false)
const keywordCount = ref(0)
const range = ref(30)
const summary = ref<DashboardSummary | null>(null)
const ov = ref<Overview | null>(null)
const trends = ref<{ series: { date: string; discovered: number; blocked: number; human_review: number }[]; agreement: { rate: number | null; total: number; ai_too_strict: number; ai_too_lenient: number } } | null>(null)
const trendEl = ref<HTMLDivElement>()
const pieEl = ref<HTMLDivElement>()
const brandEl = ref<HTMLDivElement>()
let chart1: echarts.ECharts | null = null
let chart2: echarts.ECharts | null = null
let chart3: echarts.ECharts | null = null

const freshness = computed(() => {
  const s = ov.value?.health.data_freshness
  if (s == null) return '暂无数据'
  if (s < 3600) return `${Math.max(1, Math.round(s / 60))} 分钟前`
  if (s < 86400) return `${Math.round(s / 3600)} 小时前`
  return `${Math.round(s / 86400)} 天前`
})

async function oneKeyScan() {
  try {
    await ElMessageBox.confirm(
      `将对词库全部 ${keywordCount.value} 个关键词执行四引擎搜索采集与完整研判（约 ${Math.max(5, keywordCount.value * 2)} 分钟），` +
      '期间请勿关闭平台。确认启动？',
      '一键采集研判', { type: 'warning', confirmButtonText: '启动', cancelButtonText: '取消' })
  } catch {
    return
  }
  starting.value = true
  try {
    await api.createJob('pipeline', { max_pages: 1, max_results: 15, resume: true })
    ElMessage.success('一键任务已启动')
    router.push('/jobs')
  } finally {
    starting.value = false
  }
}

const cards = computed(() => {
  const kpi = ov.value?.kpi
  const today = kpi?.new_today ?? 0
  const yesterday = kpi?.new_yesterday ?? 0
  const delta = yesterday > 0 ? Math.round((today - yesterday) / yesterday * 100)
    : (today > 0 ? 100 : null)
  const deltaText = delta === null ? undefined
    : `${delta >= 0 ? '↑' : '↓'} ${Math.abs(delta)}% 较昨日`
  return [
    { label: '累计研判域名', value: summary.value?.total ?? 0, color: '#2563eb', bg: '#eff6ff', icon: 'Search',
      delta: `今日 +${today}`, deltaClass: 'up' },
    { label: '生效封堵', value: summary.value?.blocked_active ?? 0, color: '#dc2626', bg: '#fef2f2', icon: 'Lock',
      delta: `今日 +${kpi?.blocked_today ?? 0}`, deltaClass: 'up-bad' },
    { label: '待人工复核', value: summary.value?.pending_review ?? 0, color: '#d97706', bg: '#fffbeb', icon: 'Checked' },
    { label: '确认恶意', value: summary.value?.malicious ?? 0, color: '#b91c1c', bg: '#fef2f2', icon: 'WarningFilled' },
    { label: '误报回滚', value: summary.value?.false_positives ?? 0, color: '#64748b', bg: '#f8fafc', icon: 'RefreshLeft' },
    { label: '正常/放行', value: summary.value?.allowed ?? 0, color: '#16a34a', bg: '#f0fdf4', icon: 'CircleCheck' },
  ].map(c => ({ ...c, delta: c.delta === `今日 +0` && c.label === '累计研判域名' ? deltaText : c.delta }))
})

const funnelMax = computed(() => Math.max(1, ...(ov.value?.funnel ?? []).map(s => s.count)))
const funnelRate = computed(() => {
  const f = ov.value?.funnel ?? []
  if (f.length < 4 || !f[0].count) return '-'
  return Math.round(f[3].count / f[0].count * 100) + '%'
})
const reviewRate = computed(() => {
  const f = ov.value?.funnel ?? []
  if (f.length < 5 || !f[0].count) return '-'
  return Math.round(f[4].count / f[0].count * 100) + '%'
})

function funnelStyle(i: number, count: number) {
  const colors = ['#2563eb', '#0891b2', '#7c3aed', '#dc2626', '#d97706']
  const pct = Math.max(6, Math.round(count / funnelMax.value * 100))
  return { width: pct + '%', background: colors[i % colors.length] }
}

function renderTrend() {
  if (!trendEl.value) return
  chart1 = chart1 ?? echarts.init(trendEl.value)
  const s = trends.value?.series
  if (!s?.length) return
  chart1.setOption({
    tooltip: { trigger: 'axis' },
    legend: { data: ['新增发现', '封堵动作', '人工复核'], top: 0 },
    grid: { left: 40, right: 16, top: 34, bottom: 24 },
    xAxis: { type: 'category', data: s.map(d => d.date) },
    yAxis: { type: 'value', minInterval: 1 },
    series: [
      { name: '新增发现', type: 'line', smooth: true, data: s.map(d => d.discovered),
        areaStyle: { opacity: 0.12 }, itemStyle: { color: '#2563eb' } },
      { name: '封堵动作', type: 'line', smooth: true, data: s.map(d => d.blocked),
        itemStyle: { color: '#dc2626' } },
      { name: '人工复核', type: 'line', smooth: true, data: s.map(d => d.human_review),
        itemStyle: { color: '#d97706' } },
    ],
  })
}

function renderPie() {
  if (!pieEl.value || !summary.value) return
  chart2 = chart2 ?? echarts.init(pieEl.value)
  const colorMap: Record<string, string> = {
    phishing: '#dc2626', malware_distribution: '#b91c1c', brand_abuse: '#d97706',
    suspicious: '#eab308', benign: '#16a34a', unrelated: '#94a3b8', 未裁决: '#cbd5e1',
  }
  const data = Object.entries(summary.value.verdicts).map(([k, v]) => ({
    name: verdictTag[k]?.label ?? k, value: v,
    itemStyle: { color: colorMap[k] ?? '#94a3b8' },
  }))
  chart2.setOption({
    tooltip: { trigger: 'item' },
    legend: { bottom: 0, itemWidth: 12, itemHeight: 12, textStyle: { fontSize: 11 } },
    series: [{ type: 'pie', radius: ['42%', '68%'], center: ['50%', '44%'], data,
               label: { formatter: '{b}: {c}' } }],
  })
}

function renderBrand() {
  if (!brandEl.value) return
  chart3 = chart3 ?? echarts.init(brandEl.value)
  const top = (ov.value?.brand_top ?? []).slice().reverse()
  chart3.setOption({
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
    grid: { left: 90, right: 40, top: 10, bottom: 24 },
    xAxis: { type: 'value', minInterval: 1 },
    yAxis: { type: 'category', data: top.map(t => t.brand),
             axisLabel: { fontSize: 12, color: '#334155' } },
    series: [{
      type: 'bar', data: top.map(t => t.count), barWidth: 14,
      itemStyle: { color: '#dc2626', borderRadius: [0, 4, 4, 0] },
      label: { show: true, position: 'right', fontSize: 11, color: '#64748b' },
    }],
  })
}

async function reloadTrend() {
  trends.value = await api.dashboardTrends(range.value)
  renderTrend()
}

function onResize() {
  chart1?.resize()
  chart2?.resize()
  chart3?.resize()
}

onMounted(async () => {
  try {
    summary.value = await api.dashboard()
    keywordCount.value = (await api.keywords()).keywords.length
    trends.value = await api.dashboardTrends(range.value)
    ov.value = await api.dashboardOverview()
  } finally {
    loading.value = false
  }
  renderTrend()
  renderPie()
  renderBrand()
  window.addEventListener('resize', onResize)
})

onBeforeUnmount(() => {
  window.removeEventListener('resize', onResize)
  chart1?.dispose()
  chart2?.dispose()
  chart3?.dispose()
})
</script>

<style scoped>
.saas-head { display: flex; align-items: center; justify-content: space-between; gap: 16px; flex-wrap: wrap; }
.saas-title { display: flex; align-items: center; gap: 12px; }
.h1 { font-size: 17px; font-weight: 700; color: #1e293b; }
.head-actions { display: flex; align-items: center; gap: 12px; }
.pulse {
  width: 10px; height: 10px; border-radius: 50%; flex: none;
  animation: pulse 2s infinite;
}
.pulse.on { background: #16a34a; box-shadow: 0 0 0 rgba(22, 163, 74, .5); }
.pulse.off { background: #dc2626; }
@keyframes pulse {
  0% { box-shadow: 0 0 0 0 rgba(22, 163, 74, .45); }
  70% { box-shadow: 0 0 0 9px rgba(22, 163, 74, 0); }
  100% { box-shadow: 0 0 0 0 rgba(22, 163, 74, 0); }
}
.dim { font-size: 12px; color: #64748b; }
.btn-ico { margin-right: 4px; }
.miss { color: #dc2626; }
.ml { margin-left: 8px; }
.mono { font-family: Menlo, Consolas, monospace; font-size: 12px; }
.stat :deep(.el-card__body) { display: block; }
.stat-row { display: flex; align-items: center; gap: 12px; }
.stat-ico {
  font-size: 20px; width: 40px; height: 40px; border-radius: 8px;
  display: inline-flex; align-items: center; justify-content: center; flex: none;
}
.stat-main { min-width: 0; }
.stat-num { font-size: 24px; font-weight: 700; line-height: 1.1; }
.stat-label { font-size: 12px; color: #64748b; margin-top: 3px; }
.stat-delta { font-size: 11px; margin-top: 3px; }
.stat-delta.up { color: #2563eb; }
.stat-delta.up-bad { color: #dc2626; }
.alert-row { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
.block { margin-top: 12px; }
.chart { height: 260px; }
.funnel { padding: 4px 4px 0; display: flex; flex-direction: column; justify-content: space-around; }
.funnel-row { display: flex; align-items: center; gap: 10px; margin-bottom: 14px; }
.funnel-stage { width: 68px; font-size: 12px; color: #475569; text-align: right; flex: none; }
.funnel-bar-area { flex: 1; min-width: 0; }
.funnel-bar { height: 18px; border-radius: 3px; min-width: 22px; transition: width .4s ease; }
.funnel-num { width: 44px; font-size: 13px; font-weight: 600; color: #1e293b; flex: none; }
.funnel-hint { margin-top: 6px; }
.equal { display: flex; flex-wrap: wrap; }
.equal > .el-col { display: flex; flex-direction: column; }
.equal > .el-col > .el-card { flex: 1; display: flex; flex-direction: column; width: 100%; }
.equal > .el-col > .el-card > :deep(.el-card__body) { flex: 1; display: flex; flex-direction: column; }
.health-fill { flex: 1; display: flex; flex-direction: column; }
.health-fill > :deep(.el-card__body) { flex: 1; }
.kw-wrap { display: flex; flex-wrap: wrap; gap: 8px; }
.kw { margin: 0; }
</style>
