<template>
  <div v-loading="loading">
    <el-card shadow="never" class="block" :body-style="{ padding: '14px 18px' }">
      <div class="onekey">
        <div>
          <div class="onekey-title">一键获取钓鱼站点列表</div>
          <div class="dim">对词库全部 <b>{{ keywordCount }}</b> 个关键词执行四引擎采集 → 评分 → 取证 → AI 严判，
            恶意站点自动进入封堵列表，可在「封堵管理」导出。</div>
        </div>
        <el-button type="danger" size="large" :loading="starting" @click="oneKeyScan">
          <el-icon class="btn-ico"><VideoPlay /></el-icon>
          一键采集研判
        </el-button>
      </div>
    </el-card>

    <el-row :gutter="12">
      <el-col v-for="card in cards" :key="card.label" :span="4">
        <el-card shadow="never" class="stat" :body-style="{ padding: '14px 16px' }">
          <div class="stat-row">
            <el-icon class="stat-ico" :style="{ background: card.bg, color: card.color }">
              <component :is="card.icon" />
            </el-icon>
            <div>
              <div class="stat-num" :style="{ color: card.color }">{{ card.value }}</div>
              <div class="stat-label">{{ card.label }}</div>
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

    <el-row :gutter="12" class="block">
      <el-col :span="14">
        <el-card shadow="never">
          <template #header>
            近 30 天研判趋势
            <el-tag v-if="trends?.agreement?.rate != null" size="small"
                    :type="(trends.agreement.rate ?? 0) >= 85 ? 'success' : 'warning'" class="ml">
              人机一致率 {{ trends.agreement.rate }}%
            </el-tag>
            <el-tag v-if="trends?.agreement?.ai_too_lenient" size="small" type="danger" class="ml">
              AI 漏判 {{ trends.agreement.ai_too_lenient }}（人工确认恶意而 AI 未判出）
            </el-tag>
          </template>
          <div ref="trendEl" class="chart" />
        </el-card>
      </el-col>
      <el-col :span="10">
        <el-card shadow="never" header="AI 裁决分布">
          <div ref="pieEl" class="chart" />
        </el-card>
      </el-col>
    </el-row>

    <el-row :gutter="12">
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
        <el-card shadow="never" header="高频命中关键词" class="block">
          <div class="kw-wrap">
            <el-tag v-for="[kw, n] in summary?.top_keywords ?? []" :key="kw" class="kw" type="info">
              {{ kw }} · {{ n }}
            </el-tag>
            <el-empty v-if="!summary?.top_keywords?.length" description="暂无数据" :image-size="50" />
          </div>
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

const router = useRouter()
const loading = ref(true)
const starting = ref(false)
const keywordCount = ref(0)
const summary = ref<DashboardSummary | null>(null)
const trends = ref<{ series: { date: string; discovered: number; blocked: number; human_review: number }[]; agreement: { rate: number | null; total: number; ai_too_strict: number; ai_too_lenient: number } } | null>(null)
const trendEl = ref<HTMLDivElement>()
const pieEl = ref<HTMLDivElement>()
let chart1: echarts.ECharts | null = null
let chart2: echarts.ECharts | null = null

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

const cards = computed(() => [
  { label: '累计研判域名', value: summary.value?.total ?? 0, color: '#2563eb', bg: '#eff6ff', icon: 'Search' },
  { label: '生效封堵', value: summary.value?.blocked_active ?? 0, color: '#dc2626', bg: '#fef2f2', icon: 'Lock' },
  { label: '待人工复核', value: summary.value?.pending_review ?? 0, color: '#d97706', bg: '#fffbeb', icon: 'Checked' },
  { label: '确认恶意', value: summary.value?.malicious ?? 0, color: '#b91c1c', bg: '#fef2f2', icon: 'WarningFilled' },
  { label: '误报回滚', value: summary.value?.false_positives ?? 0, color: '#64748b', bg: '#f8fafc', icon: 'RefreshLeft' },
  { label: '正常/放行', value: summary.value?.allowed ?? 0, color: '#16a34a', bg: '#f0fdf4', icon: 'CircleCheck' },
])

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
function onResize() {
  chart1?.resize()
  chart2?.resize()
}

onMounted(async () => {
  try {
    summary.value = await api.dashboard()
    keywordCount.value = (await api.keywords()).keywords.length
    trends.value = await api.dashboardTrends()
  } finally {
    loading.value = false
  }
  renderTrend()
  renderPie()
  window.addEventListener('resize', onResize)
})

onBeforeUnmount(() => {
  window.removeEventListener('resize', onResize)
  chart1?.dispose()
  chart2?.dispose()
})
</script>

<style scoped>
.onekey { display: flex; align-items: center; justify-content: space-between; gap: 20px; }
.onekey-title { font-size: 16px; font-weight: 700; margin-bottom: 4px; }
.dim { font-size: 12px; color: #64748b; }
.btn-ico { margin-right: 4px; }
.stat :deep(.el-card__body) { display: block; }
.stat-row { display: flex; align-items: center; gap: 12px; }
.stat-ico {
  font-size: 20px;
  width: 40px;
  height: 40px;
  border-radius: 8px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex: none;
}
.stat-num { font-size: 24px; font-weight: 700; line-height: 1.1; }
.stat-label { font-size: 12px; color: #64748b; margin-top: 3px; }
.alert-row { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
.miss { color: #dc2626; }
.block { margin-top: 12px; }
.chart { height: 260px; }
.kw-wrap { display: flex; flex-wrap: wrap; gap: 8px; }
.kw { margin: 0; }
</style>
