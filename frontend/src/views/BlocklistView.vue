<template>
  <div v-loading="loading">
    <el-row :gutter="12" class="block">
      <el-col :span="8">
        <el-card shadow="never">
          <div class="big-num danger">{{ info?.count ?? 0 }}</div>
          <div class="dim">当前生效封堵域名</div>
        </el-card>
      </el-col>
      <el-col :span="8">
        <el-card shadow="never">
          <div class="path">{{ info?.dir ?? '-' }}</div>
          <div class="dim">封堵产物目录</div>
        </el-card>
      </el-col>
      <el-col :span="8">
        <el-card shadow="never">
          <el-button type="primary" plain @click="regen">重新生成产物</el-button>
          <span class="dim ml">供 hosts / dnsmasq / RPZ / ACL 与设备接口消费</span>
        </el-card>
      </el-col>
    </el-row>

    <el-card shadow="never" class="block" :body-style="{ padding: '12px 18px' }">
      <div class="export-bar">
        <span class="export-title">导出钓鱼站点列表</span>
        <el-button size="small" type="danger" plain @click="downloadExport('csv')">CSV（含证据链）</el-button>
        <el-button size="small" type="warning" plain @click="downloadExport('txt')">域名 TXT</el-button>
        <el-button size="small" plain @click="downloadExport('json')">JSON（完整情报）</el-button>
        <span class="dim">默认导出确认恶意（生效封堵）域名；CSV/JSON 可选附带监控域名。</span>
      </div>
    </el-card>

    <el-row :gutter="12">
      <el-col :span="10">
        <el-card shadow="never" header="封堵域名列表">
          <el-table :data="info?.domains ?? []" size="small" height="420">
            <el-table-column type="index" width="50" />
            <el-table-column label="域名" prop="" >
              <template #default="{ $index }">{{ info?.domains?.[$index] }}</template>
            </el-table-column>
          </el-table>
        </el-card>
      </el-col>
      <el-col :span="14">
        <el-card shadow="never" header="封堵产物预览">
          <el-tabs v-model="tab">
            <el-tab-pane v-for="a in info?.artifacts ?? []" :key="a" :label="a" :name="a" />
          </el-tabs>
          <pre class="artifact">{{ artifactText }}</pre>
          <el-button size="small" class="mt" @click="download">下载当前产物</el-button>
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api/client'
import type { BlocklistInfo } from '../api/types'

const loading = ref(true)
const info = ref<BlocklistInfo | null>(null)
const tab = ref('hosts')
const artifactText = ref('')

async function load() {
  loading.value = true
  try {
    info.value = await api.blocklist()
    await loadArtifact()
  } finally {
    loading.value = false
  }
}

async function loadArtifact() {
  if (!tab.value) return
  artifactText.value = await api.artifact(tab.value)
}

async function regen() {
  const r = await api.regenerate()
  ElMessage.success(`已重新生成，封堵 ${r.count} 个域名`)
  await load()
}

function download() {
  window.open(`/api/blocklist/files/${tab.value}`)
}

function downloadExport(fmt: 'csv' | 'txt' | 'json') {
  window.open(`/api/blocklist/export/phishing.${fmt}`)
}

watch(tab, loadArtifact)
onMounted(load)
</script>

<style scoped>
.block { margin-bottom: 12px; }
.export-bar { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.export-title { font-weight: 600; margin-right: 4px; }
.big-num { font-size: 34px; font-weight: 700; }
.danger { color: #dc2626; }
.dim { font-size: 12px; color: #64748b; }
.path { font-size: 13px; word-break: break-all; }
.artifact {
  background: #0f172a; color: #bbf7d0; border-radius: 6px; padding: 12px;
  font-size: 12px; line-height: 1.7; max-height: 380px; overflow-y: auto; margin: 0;
  white-space: pre-wrap; word-break: break-all;
}
.mt { margin-top: 10px; }
.ml { margin-left: 10px; }
</style>
