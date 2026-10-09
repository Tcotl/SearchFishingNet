<template>
  <div>
    <el-card shadow="never" header="采集关键词（银狐高频软件词库）" class="block">
      <div class="add-bar">
        <el-input v-model="newKw" placeholder="新增关键词，如：钉钉下载" style="width: 240px" @keyup.enter="add" />
        <el-button type="primary" class="ml" @click="add">添加</el-button>
        <el-input v-model="q" placeholder="搜索关键词/分类" clearable style="width: 200px" size="small" />
        <span class="dim">共 {{ rows.length }} 个</span>
        <span class="dim ml">白名单域名请前往「白名单管理」页面维护。</span>
      </div>

      <el-table :data="filtered" v-loading="loading" size="small" height="430">
        <el-table-column type="index" label="#" width="55" />
        <el-table-column prop="keyword" label="关键词" min-width="200" />
        <el-table-column prop="category" label="分类" width="140">
          <template #default="{ row }">
            <el-tag size="small" :type="row.category === '其他' ? 'info' : 'primary'">{{ row.category }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="80">
          <template #default="{ row }">
            <el-button size="small" type="danger" text @click="del(row.keyword)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-card shadow="never" header="品牌官方域名映射（全系统最高优先级事实源 · 标「自定义」的为平台确认增补）" class="block">
      <el-table :data="brands" size="small" height="360">
        <el-table-column prop="brand" label="品牌" width="130">
          <template #default="{ row }">
            {{ row.brand }}
            <el-tag v-if="row.custom" size="small" type="success" class="ml4">自定义</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="官方域名">
          <template #default="{ row }">
            <el-tag v-for="d in row.officials" :key="d" size="small" type="info" class="od">{{ d }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="90">
          <template #default="{ row }">
            <el-button v-if="row.custom" size="small" type="danger" text
                       @click="delMapping(row.brand, row.officials[0])">移除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-card shadow="never" class="block" :body-style="{ padding: '12px 18px' }">
      <template #header>
        <span>官方映射候选（自增长）</span>
        <span class="dim ml4">AI 放行/复核记录里"页面宣称品牌但不在映射表"的域名——人工核实后一键确认，确认即成为最高优先级事实源并自动放行对应记录</span>
      </template>
      <el-table :data="candidates" v-loading="candLoading" size="small" max-height="380">
        <el-table-column prop="domain" label="域名" min-width="180" />
        <el-table-column prop="brand" label="宣称品牌" width="130" />
        <el-table-column label="来源" width="110">
          <template #default="{ row }">
            <el-tag size="small" :type="row.source === 'ai_benign' ? 'success' : 'warning'">
              {{ row.source === 'ai_benign' ? 'AI 判放行' : '品牌宣称' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="注册年龄" width="90">
          <template #default="{ row }">
            <span v-if="row.age_days != null" :class="{ 'young': row.age_days < 90 }">
              {{ row.age_days < 365 ? row.age_days + ' 天' : Math.floor(row.age_days / 365) + ' 年' }}
            </span>
            <span v-else class="dim">未知</span>
          </template>
        </el-table-column>
        <el-table-column prop="page_title" label="页面标题" min-width="200" show-overflow-tooltip />
        <el-table-column label="操作" width="120">
          <template #default="{ row }">
            <el-button size="small" type="primary" @click="confirmMapping(row)">确认映射</el-button>
          </template>
        </el-table-column>
        <template #empty>
          <el-empty description="暂无候选：AI 放行记录的品牌都已覆盖映射表" :image-size="60" />
        </template>
      </el-table>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api } from '../api/client'
import type { BrandCandidate } from '../api/types'

interface KwRow { keyword: string; category: string }

const rows = ref<KwRow[]>([])
const brands = ref<{ brand: string; officials: string[]; custom?: boolean }[]>([])
const candidates = ref<BrandCandidate[]>([])
const candLoading = ref(false)
const newKw = ref('')
const q = ref('')
const loading = ref(true)

const filtered = computed(() => {
  const needle = q.value.trim().toLowerCase()
  if (!needle) return rows.value
  return rows.value.filter(r => r.keyword.toLowerCase().includes(needle) || r.category.includes(needle))
})

async function load() {
  loading.value = true
  try {
    const g = await api.keywordGroups()
    rows.value = g.groups.flatMap(grp => grp.keywords.map(kw => ({ keyword: kw, category: grp.category })))
    brands.value = (await api.brands()).brands
    candLoading.value = true
    try {
      candidates.value = (await api.brandCandidates()).items
    } finally {
      candLoading.value = false
    }
  } finally {
    loading.value = false
  }
}

async function confirmMapping(row: BrandCandidate) {
  try {
    await ElMessageBox.confirm(
      `确认「${row.domain}」为品牌「${row.brand}」的官方域名？确认后该域名及其子域自动放行。`,
      '官方映射确认', { type: 'warning' })
  } catch { return }
  const r = await api.confirmBrandCandidate(row.brand, [row.domain])
  ElMessage.success(`映射已确认${r.auto_allowed.length ? `，${r.auto_allowed.length} 条记录自动放行` : ''}`)
  await load()
}

async function delMapping(brand: string, domain: string) {
  try {
    await ElMessageBox.confirm(`移除自定义映射「${brand} → ${domain}」？下次重评分该域名将回归研判漏斗。`, '移除映射', { type: 'warning' })
  } catch { return }
  await api.removeBrandOfficial(brand, domain)
  ElMessage.success('映射已移除')
  await load()
}

async function add() {
  const kw = newKw.value.trim()
  if (!kw) return
  await api.addKeyword(kw)
  newKw.value = ''
  ElMessage.success('已添加')
  await load()
}

async function del(kw: string) {
  await api.removeKeyword(kw)
  ElMessage.success('已删除')
  await load()
}

onMounted(load)
</script>

<style scoped>
.block { margin-bottom: 12px; }
.add-bar { display: flex; align-items: center; gap: 10px; margin-bottom: 12px; flex-wrap: wrap; }
.ml { margin-left: 6px; }
.dim { color: #94a3b8; font-size: 13px; }
.od { margin: 2px 4px 2px 0; }
.ml4 { margin-left: 8px; font-weight: 400; }
.young { color: #dc2626; font-weight: 600; }
</style>
