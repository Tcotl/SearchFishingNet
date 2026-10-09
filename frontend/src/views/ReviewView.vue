<template>
  <div>
    <el-alert type="warning" :closable="false" class="block"
              title="以下域名经规则评分与 AI 严判后仍无法定论。已按复核优先级排序：AI 有恶意定性但置信度不足、含品牌词、新注册坐床期的置顶。" />

    <el-card shadow="never" class="block" :body-style="{ padding: '12px 18px' }" v-if="selected.length">
      <div class="batch-bar">
        <span>已选 <b>{{ selected.length }}</b> 条</span>
        <el-button size="small" type="danger" @click="batch('confirm_block')">批量确认恶意·封堵</el-button>
        <el-button size="small" type="warning" @click="batch('false_positive')">批量标记误报</el-button>
        <el-button size="small" type="success" @click="batch('allow')">批量放行</el-button>
        <el-button size="small" text @click="selected = []">取消选择</el-button>
        <span class="dim">放行/误报会自动加入白名单，后续轮次不再告警。</span>
      </div>
    </el-card>

    <el-table :data="items" v-loading="loading" size="small" @selection-change="(v: ThreatRecord[]) => selected = v">
      <el-table-column type="selection" width="42" />
      <el-table-column label="优先级" width="86" sortable :sort-by="'priority'" :sort-order="'descending'">
        <template #default="{ row }">
          <el-tooltip :content="(row.priority_reasons ?? []).join('；') || '无'" placement="top">
            <el-tag :type="prioTag[row.priority_tier ?? 'low']" size="small">
              {{ row.priority ?? 0 }}
            </el-tag>
          </el-tooltip>
        </template>
      </el-table-column>
      <el-table-column prop="domain" label="域名" min-width="190" />
      <el-table-column label="注册年龄" width="110">
        <template #default="{ row }">
          <span v-if="row.facts?.rdap?.age_days != null"
                :class="{ 'young': row.facts.rdap.age_days < 90 }">
            {{ row.facts.rdap.age_days < 365 ? row.facts.rdap.age_days + ' 天' : Math.floor(row.facts.rdap.age_days / 365) + ' 年' }}
          </span>
          <span v-else class="dim">未知</span>
        </template>
      </el-table-column>
      <el-table-column label="规则分" width="76">
        <template #default="{ row }">{{ row.score?.score ?? '-' }}</template>
      </el-table-column>
      <el-table-column label="AI 参考" min-width="230">
        <template #default="{ row }">
          <template v-if="row.ai_verdict">
            <el-tag :type="verdictTag[row.ai_verdict.verdict]?.type ?? 'info'" size="small" class="mr">
              {{ verdictTag[row.ai_verdict.verdict]?.label ?? row.ai_verdict.verdict }} · {{ row.ai_verdict.confidence }}
            </el-tag>
            <span class="dim">{{ row.ai_verdict.evidence?.[0] ?? '' }}</span>
          </template>
          <span v-else class="dim">未裁决（未配置 AI）</span>
        </template>
      </el-table-column>
      <el-table-column label="发现时间" width="120">
          <template #default="{ row }">{{ fmtIso(row.created) }}</template>
        </el-table-column>
      <el-table-column label="复核处置" width="250">
        <template #default="{ row }">
          <el-button size="small" type="danger" plain @click.stop="decide(row, 'confirm_block')">确认恶意·封堵</el-button>
          <el-button size="small" type="info" plain @click.stop="decide(row, 'false_positive')">误报</el-button>
          <el-button size="small" type="success" plain @click.stop="decide(row, 'allow')">放行</el-button>
        </template>
      </el-table-column>
    </el-table>

    <el-drawer v-model="drawer" :title="active?.domain" size="68%">
      <RecordDetail :record="active" @changed="load" />
    </el-drawer>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api } from '../api/client'
import type { ThreatRecord } from '../api/types'
import { fmtIso, verdictTag } from '../lib/display'
import RecordDetail from '../components/RecordDetail.vue'

const items = ref<ThreatRecord[]>([])
const selected = ref<ThreatRecord[]>([])
const loading = ref(false)
const drawer = ref(false)
const active = ref<ThreatRecord | null>(null)

const prioTag: Record<string, 'danger' | 'warning' | 'info'> = {
  high: 'danger', medium: 'warning', low: 'info',
}

async function load() {
  loading.value = true
  selected.value = []
  try {
    const resp = await api.records({ disposition: 'pending_review', status: 'active', page_size: 100, sort: 'priority' })
    items.value = resp.items
  } finally {
    loading.value = false
  }
}

async function decide(row: ThreatRecord, kind: 'confirm_block' | 'false_positive' | 'allow') {
  const labels = { confirm_block: '确认为恶意并加入封堵', false_positive: '标记为误报（移出封堵并加入白名单候选）', allow: '直接放行' }
  try {
    await ElMessageBox.confirm(`确定对 ${row.domain} 执行「${labels[kind]}」？`, '人工复核', { type: 'warning' })
  } catch {
    return
  }
  await api.feedback(row.domain, { kind, add_whitelist: kind === 'allow' || kind === 'false_positive' })
  ElMessage.success('处置完成，封堵产物已更新')
  await load()
}

async function batch(kind: 'confirm_block' | 'false_positive' | 'allow') {
  const domains = selected.value.map(r => r.domain)
  const labels = { confirm_block: `确认为恶意并封堵 ${domains.length} 个域名`, false_positive: `标记 ${domains.length} 个域名为误报`, allow: `放行 ${domains.length} 个域名` }
  try {
    await ElMessageBox.confirm(`确定${labels[kind]}？该操作会更新封堵产物。`, '批量复核', { type: 'warning' })
  } catch {
    return
  }
  const r = await api.batchFeedback(domains, kind)
  ElMessage.success(`批量处置完成：${r.processed} 条${r.missing.length ? `，${r.missing.length} 条不存在` : ''}`)
  await load()
}

onMounted(load)
</script>

<style scoped>
.block { margin-bottom: 12px; }
.mr { margin-right: 6px; }
.dim { color: #94a3b8; font-size: 12px; }
.batch-bar { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.young { color: #dc2626; font-weight: 600; }
</style>
