<template>
  <div>
    <el-card shadow="never" header="批量添加白名单域名" class="block">
      <el-form label-width="80px">
        <el-form-item label="域名列表">
          <el-input v-model="bulkInput" type="textarea" :rows="4"
                    placeholder="每行一个域名，也支持逗号/分号分隔，自动去除协议和 www&#10;例如：&#10;example.com&#10;download.vendor-cdn.com" />
        </el-form-item>
        <el-form-item label="备注">
          <el-input v-model="noteInput" placeholder="选填，例如：研发部指定下载源 / 官网换域名" style="max-width: 420px" />
        </el-form-item>
        <el-form-item label="">
          <el-button type="primary" :loading="adding" @click="add">加入白名单</el-button>
          <span class="dim ml">
            白名单域名与品牌官方映射同效：命中即 100 分直接放行，不进研判漏斗；
            「人工复核」的误报回滚/放行操作会自动以"误报回流"来源加入。
          </span>
        </el-form-item>
      </el-form>
    </el-card>

    <el-card shadow="never" class="block">
      <template #header>
        <div class="head">
          <span>白名单列表（{{ entries.length }} 条，启用 {{ enabledCount }}）</span>
          <el-input v-model="q" placeholder="搜索域名/备注" clearable style="width: 220px" size="small" />
        </div>
      </template>
      <el-table :data="filtered" v-loading="loading" size="small">
        <el-table-column prop="domain" label="域名" min-width="240" show-overflow-tooltip />
        <el-table-column label="来源" width="100">
          <template #default="{ row }">
            <el-tag :type="row.source === 'feedback' ? 'warning' : 'primary'" size="small">
              {{ row.source === 'feedback' ? '误报回流' : '人工添加' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="note" label="备注" min-width="180" show-overflow-tooltip>
          <template #default="{ row }">{{ row.note || '-' }}</template>
        </el-table-column>
        <el-table-column label="添加时间" width="165">
          <template #default="{ row }">{{ row.added_at ? fmtTime(row.added_at) : '-' }}</template>
        </el-table-column>
        <el-table-column label="启用" width="80">
          <template #default="{ row }">
            <el-switch :model-value="row.enabled" @change="(v: any) => toggle(row, v)" />
          </template>
        </el-table-column>
        <el-table-column label="操作" width="80">
          <template #default="{ row }">
            <el-button size="small" type="danger" text @click="del(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
      <el-empty v-if="!filtered.length && !loading" description="暂无白名单域名" :image-size="60" />
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api/client'

interface Entry {
  domain: string
  note: string
  source: string
  enabled: boolean
  added_at: number
}

const entries = ref<Entry[]>([])
const q = ref('')
const bulkInput = ref('')
const noteInput = ref('')
const adding = ref(false)
const loading = ref(true)

const filtered = computed(() => {
  const needle = q.value.trim().toLowerCase()
  if (!needle) return entries.value
  return entries.value.filter(e => e.domain.includes(needle) || (e.note || '').toLowerCase().includes(needle))
})
const enabledCount = computed(() => entries.value.filter(e => e.enabled).length)

function fmtTime(ts: number): string {
  return new Date(ts * 1000).toLocaleString('zh-CN', { hour12: false })
}

async function load() {
  loading.value = true
  try {
    entries.value = (await api.whitelistEntries()).entries
  } finally {
    loading.value = false
  }
}

async function add() {
  if (!bulkInput.value.trim()) return ElMessage.warning('请输入域名')
  adding.value = true
  try {
    const r = await api.addWhitelistBulk(bulkInput.value, noteInput.value)
    if (r.added) ElMessage.success(`已添加 ${r.added} 条` + (r.duplicates ? `，跳过重复 ${r.duplicates} 条` : ''))
    else ElMessage.warning('没有新增（全部已存在）')
    bulkInput.value = ''
    noteInput.value = ''
    await load()
  } finally {
    adding.value = false
  }
}

async function toggle(row: Entry, enabled: boolean) {
  await api.updateWhitelist(row.domain, { enabled })
  row.enabled = enabled
  ElMessage.success(`${row.domain} 已${enabled ? '启用' : '停用'}`)
}

async function del(row: Entry) {
  await api.removeWhitelist(row.domain)
  ElMessage.success('已删除')
  await load()
}

onMounted(load)
</script>

<style scoped>
.block { margin-bottom: 12px; }
.ml { margin-left: 10px; }
.dim { font-size: 12px; color: #94a3b8; }
.head { display: flex; align-items: center; justify-content: space-between; }
</style>
