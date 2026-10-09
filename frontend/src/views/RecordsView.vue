<template>
  <div>
    <el-card shadow="never" class="block" :body-style="{ padding: '10px 18px' }">
      <div class="tabs-row">
        <el-radio-group v-model="quick" size="small" @change="onQuick">
          <el-radio-button value="">全部</el-radio-button>
          <el-radio-button value="pending_review">待复核</el-radio-button>
          <el-radio-button value="blocked">已封堵</el-radio-button>
          <el-radio-button value="monitored">监控中</el-radio-button>
          <el-radio-button value="allowed">已放行</el-radio-button>
          <el-radio-button value="false_positive">误报</el-radio-button>
        </el-radio-group>
        <div class="filters">
          <el-input v-model="filters.q" placeholder="域名 / 关键词 / 标题" clearable style="width: 200px"
                    @keyup.enter="search" @clear="search" />
          <el-button type="primary" plain @click="search">查询</el-button>
        </div>
      </div>
    </el-card>

    <el-card shadow="never">
      <el-table :data="items" v-loading="loading" size="small"
                @row-click="(row: ThreatRecord) => showDetail(row)" style="cursor: pointer">
        <el-table-column prop="domain" label="域名" min-width="210" />
        <el-table-column label="规则分" width="80">
          <template #default="{ row }">{{ row.score?.score ?? '-' }}</template>
        </el-table-column>
        <el-table-column label="AI 裁决" width="110">
          <template #default="{ row }">
            <el-tag v-if="row.ai_verdict" :type="verdictTag[row.ai_verdict.verdict]?.type ?? 'info'" size="small">
              {{ verdictTag[row.ai_verdict.verdict]?.label ?? row.ai_verdict.verdict }}
            </el-tag>
            <span v-else class="dim">未裁决</span>
          </template>
        </el-table-column>
        <el-table-column label="置信度" width="90">
          <template #default="{ row }">{{ row.ai_verdict?.confidence ?? '-' }}</template>
        </el-table-column>
        <el-table-column label="处置" width="95">
          <template #default="{ row }">
            <el-tag :type="dispositionTag[row.disposition]?.type ?? 'info'" size="small">
              {{ dispositionTag[row.disposition]?.label ?? (row.disposition || '-') }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="90">
          <template #default="{ row }">
            <el-tag :type="statusTag[row.status]?.type ?? 'info'" size="small" effect="plain">
              {{ statusTag[row.status]?.label ?? row.status }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="首次发现" width="130">
          <template #default="{ row }">{{ fmtIso(row.created) }}</template>
        </el-table-column>
      </el-table>
      <el-pagination
        v-model:current-page="page" :page-size="pageSize" :total="total"
        layout="total, prev, pager, next" class="pager" @current-change="load" />
    </el-card>

    <el-drawer v-model="drawer" :title="active?.domain" size="68%">
      <RecordDetail :record="active" @changed="load" />
    </el-drawer>
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { api } from '../api/client'
import type { ThreatRecord } from '../api/types'
import { dispositionTag, fmtIso, statusTag, verdictTag } from '../lib/display'
import RecordDetail from '../components/RecordDetail.vue'

const filters = reactive({ q: '', status: '', disposition: '' })
const quick = ref('')
const items = ref<ThreatRecord[]>([])
const total = ref(0)
const page = ref(1)
const pageSize = 20
const loading = ref(false)
const drawer = ref(false)
const active = ref<ThreatRecord | null>(null)

function onQuick(v: string) {
  if (v === 'blocked') {
    // 已封堵 = AI 自动封堵 + 策略封堵：页面级并集过滤
    filters.disposition = ''
    filters.status = 'active'
    quickBlocked.value = true
  } else {
    quickBlocked.value = false
    filters.disposition = v
    filters.status = ''
  }
  page.value = 1
  load()
}
const quickBlocked = ref(false)

function search() {
  page.value = 1
  load()
}

async function load() {
  loading.value = true
  try {
    if (quickBlocked.value) {
      // 拉两类封堵合并展示
      const [a, b] = await Promise.all([
        api.records({ ...filters, disposition: 'auto_blocked', page: 1, page_size: 100 }),
        api.records({ ...filters, disposition: 'policy_blocked', page: 1, page_size: 100 }),
      ])
      items.value = [...a.items, ...b.items]
      total.value = a.total + b.total
      return
    }
    const resp = await api.records({ ...filters, page: page.value, page_size: pageSize })
    items.value = resp.items
    total.value = resp.total
  } finally {
    loading.value = false
  }
}

function showDetail(row: ThreatRecord) {
  active.value = row
  drawer.value = true
}

onMounted(load)
</script>

<style scoped>
.block { margin-bottom: 12px; }
.dim { color: #94a3b8; font-size: 12px; }
.pager { margin-top: 10px; justify-content: flex-end; }
.tabs-row { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
.filters { display: flex; align-items: center; gap: 8px; }
</style>

