<template>
  <div>
    <el-alert type="warning" :closable="false" class="block"
              title="样本仅做静态分析（哈希/文件结构/字符串/IOC 提取），不会在本机执行；样本按 SHA256 隔离存放于 data/samples/。猎取范围默认为 AI 确认恶意（已封堵）站点。" />

    <el-card shadow="never" class="block" :body-style="{ padding: '12px 18px' }">
      <div class="hunt-bar" style="margin-bottom: 10px">
        <span class="hunt-title">样本猎取</span>
        <el-input v-model="domain" placeholder="指定已封堵域名（留空=全部 AI 确认恶意站点）"
                  style="width: 320px" size="small" clearable />
        <el-button type="danger" size="small" :loading="hunting" @click="hunt">开始猎取分析</el-button>
        <span class="dim">从取证数据中已记录的下载入口直接拉取载荷（网盘链接不可直连的会跳过）。</span>
      </div>
      <div class="hunt-bar">
        <span class="hunt-title">人工上传</span>
        <el-upload :show-file-list="false" :http-request="doUpload">
          <el-button type="warning" size="small" :loading="uploading">选择文件上传分析</el-button>
        </el-upload>
        <el-input v-model="uploadNote" placeholder="来源线索（可选）：如 XX 群流传 / 某站下载"
                  style="width: 280px" size="small" clearable />
        <span class="dim">上传即哈希落盘隔离（≤64MB）+ 静态分析，随后自动启动 AI 行为分析；样本不会被本机执行。</span>
      </div>
    </el-card>

    <el-card shadow="never" header="样本库">
      <el-table :data="items" v-loading="loading" size="small"
                @row-click="(row: SampleListItem) => showDetail(row.sha256)" style="cursor: pointer">
        <el-table-column label="SHA256" width="130">
          <template #default="{ row }">{{ row.sha256.slice(0, 14) }}…</template>
        </el-table-column>
        <el-table-column prop="source_domain" label="来源站点" min-width="150" show-overflow-tooltip>
          <template #default="{ row }">{{ row.source_domain === 'manual' ? '人工上传' : row.source_domain }}</template>
        </el-table-column>
        <el-table-column prop="file_name" label="文件名" min-width="160" show-overflow-tooltip />
        <el-table-column prop="ftype" label="类型" width="140" show-overflow-tooltip />
        <el-table-column label="大小" width="90">
          <template #default="{ row }">{{ (row.size / 1024 / 1024).toFixed(1) }} MB</template>
        </el-table-column>
        <el-table-column label="风险" width="80">
          <template #default="{ row }">
            <el-tag v-if="row.risk_level" :type="riskTag(row.risk_level)" size="small">{{ row.risk_level }}</el-tag>
            <span v-else class="dim">{{ row.status }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="c2_count" label="C2候选" width="80" />
        <el-table-column label="入库时间" width="165">
          <template #default="{ row }">{{ fmtTime(row.created_at) }}</template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-drawer v-model="drawer" :title="active?.file_name ?? '样本详情'" size="72%">
      <template v-if="active">
        <el-descriptions :column="2" border size="small" class="block">
          <el-descriptions-item label="SHA256"><span class="mono">{{ active.sha256 }}</span></el-descriptions-item>
          <el-descriptions-item label="MD5"><span class="mono">{{ active.md5 }}</span></el-descriptions-item>
          <el-descriptions-item label="类型">{{ active.ftype }}</el-descriptions-item>
          <el-descriptions-item label="大小">{{ (active.size / 1024 / 1024).toFixed(2) }} MB</el-descriptions-item>
          <el-descriptions-item label="来源站点">{{ active.source_domain }}</el-descriptions-item>
          <el-descriptions-item label="下载自"><span class="mono break">{{ active.source_url }}</span></el-descriptions-item>
        </el-descriptions>

        <el-row :gutter="12">
          <el-col :span="14">
            <el-card shadow="never" header="AI 行为分析" class="block">
              <template v-if="active.ai_report && !active.ai_report.error">
                <div class="ai-head">
                  <el-tag :type="riskTag(active.ai_report.risk_level ?? '')" size="large">
                    风险: {{ active.ai_report.risk_level }}
                  </el-tag>
                  <span class="family">{{ active.ai_report.family_guess }}</span>
                </div>
                <div class="sub">行为链</div>
                <ol class="chain">
                  <li v-for="(b, i) in active.ai_report.behavior_chain ?? []" :key="i">{{ b }}</li>
                </ol>
                <div class="sub">能力</div>
                <el-tag v-for="c in active.ai_report.capabilities ?? []" :key="c" size="small"
                        type="warning" class="cap">{{ c }}</el-tag>
                <div class="sub">持久化</div>
                <p class="mini">{{ active.ai_report.persistence || '-' }}</p>
                <template v-if="active.ai_report.dropped_files?.length">
                  <div class="sub">释放文件</div>
                  <ul class="evi"><li v-for="(f, i) in active.ai_report.dropped_files" :key="i">{{ f }}</li></ul>
                </template>
                <p class="mini">{{ active.ai_report.summary }}</p>
              </template>
              <el-alert v-else-if="active.ai_report?.error" type="error" :title="active.ai_report.error" :closable="false" />
              <el-empty v-else description="尚未进行 AI 分析（配置 AI Key 后可通过「重判待复核」式重分析或重新猎取）" :image-size="60" />
            </el-card>

            <el-card shadow="never" header="恶意外连地址（C2 候选）" class="block">
              <el-table :data="active.ai_report?.c2_addresses ?? []" size="small">
                <el-table-column prop="indicator" label="指标" min-width="160" />
                <el-table-column prop="type" label="类型" width="70" />
                <el-table-column label="置信度" width="80">
                  <template #default="{ row }">{{ row.confidence }}</template>
                </el-table-column>
                <el-table-column prop="evidence" label="证据（样本字符串）" min-width="240" show-overflow-tooltip />
              </el-table>
              <el-empty v-if="!active.ai_report?.c2_addresses?.length" description="暂无 C2 候选" :image-size="50" />
            </el-card>
          </el-col>

          <el-col :span="10">
            <el-card shadow="never" header="静态分析" class="block">
              <template v-if="active.static_report">
                <el-descriptions :column="1" size="small" border>
                  <el-descriptions-item label="编译时间">{{ active.static_report.pe?.compiled || '-' }}</el-descriptions-item>
                  <el-descriptions-item label="架构/子系统">{{ active.static_report.pe?.machine || '-' }} / {{ active.static_report.pe?.subsystem || '-' }}</el-descriptions-item>
                  <el-descriptions-item label="熵">{{ active.static_report.file.entropy }} {{ active.static_report.packed ? '（疑似加壳）' : '' }}</el-descriptions-item>
                  <el-descriptions-item label="安装器">{{ active.static_report.installer || '-' }}</el-descriptions-item>
                </el-descriptions>
                <template v-if="importSignals.length">
                  <div class="sub">导入表能力信号</div>
                  <div v-for="s in importSignals" :key="s.cap" class="dl-row">
                    <el-tag type="danger" size="small">{{ s.cap }}</el-tag>
                    <span class="dl-host">{{ s.apis.join(', ') }}</span>
                  </div>
                </template>
                <template v-if="active.static_report.iocs">
                  <div class="sub">字符串 IOC（{{ active.static_report.string_count }} 条字符串中提取）</div>
                  <div v-if="active.static_report.iocs.urls.length" class="ioc">
                    <b>URL:</b> <span v-for="u in active.static_report.iocs.urls.slice(0, 8)" :key="u" class="mono break">{{ u }} </span>
                  </div>
                  <div v-if="active.static_report.iocs.ips.length" class="ioc">
                    <b>IP:</b> <span v-for="u in active.static_report.iocs.ips.slice(0, 10)" :key="u" class="mono">{{ u }} </span>
                  </div>
                  <div v-if="active.static_report.iocs.domains.length" class="ioc">
                    <b>域名:</b> <span v-for="u in active.static_report.iocs.domains.slice(0, 10)" :key="u" class="mono">{{ u }} </span>
                  </div>
                  <div v-if="active.static_report.iocs.commands.length" class="ioc">
                    <b>命令行:</b> <span v-for="u in active.static_report.iocs.commands.slice(0, 5)" :key="u" class="mono break">{{ u }}；</span>
                  </div>
                </template>
              </template>
            </el-card>
            <el-button size="small" class="block" @click="fetchSample">下载隔离区样本（分析师取回）</el-button>
          </el-col>
        </el-row>
      </template>
    </el-drawer>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import type { UploadRequestOptions } from 'element-plus'
import { api } from '../api/client'
import type { SampleDetail, SampleListItem } from '../api/types'

const items = ref<SampleListItem[]>([])
const loading = ref(true)
const hunting = ref(false)
const uploading = ref(false)
const uploadNote = ref('')
const domain = ref('')
const drawer = ref(false)
const active = ref<SampleDetail | null>(null)

function riskTag(level: string): 'danger' | 'warning' | 'success' | 'info' {
  const map: Record<string, 'danger' | 'warning' | 'success' | 'info'> = {
    high: 'danger', medium: 'warning', low: 'success',
  }
  return map[level] ?? 'info'
}
function fmtTime(ts: number): string {
  return new Date(ts * 1000).toLocaleString('zh-CN', { hour12: false })
}

const importSignals = computed(() =>
  Object.entries(active.value?.static_report?.pe?.import_signals ?? {})
    .map(([cap, apis]) => ({ cap, apis })))

async function load() {
  loading.value = true
  try {
    items.value = (await api.samples()).items
  } finally {
    loading.value = false
  }
}

function hunt() {
  hunting.value = true
  api.createJob('sample_hunt', domain.value.trim() ? { domain: domain.value.trim() } : {})
    .then(() => {
      ElMessage.success('样本猎取任务已启动')
      domain.value = ''
    })
    .finally(() => { hunting.value = false })
}

async function doUpload(opts: UploadRequestOptions) {
  uploading.value = true
  try {
    const r = await api.uploadSample(opts.file as File, uploadNote.value.trim())
    uploadNote.value = ''
    ElMessage.success(r.duplicate
      ? `样本已存在库中（${r.sha256.slice(0, 16)}…），已重新触发 AI 行为分析`
      : `样本已隔离入库：${r.sha256.slice(0, 16)}…（${r.ftype}），AI 行为分析已启动`)
    await load()
    await showDetail(r.sha256)
    // 轮询 AI 分析任务，完成后自动刷新详情与列表
    const job = await api.createJob('sample_analyze', { sha256: r.sha256 })
    const deadline = Date.now() + 5 * 60_000
    while (Date.now() < deadline && drawer.value) {
      await new Promise(res => setTimeout(res, 5000))
      const j = await api.job(job.id)
      if (j.status === 'success' || j.status === 'failed') break
    }
    if (drawer.value && active.value?.sha256 === r.sha256) {
      active.value = await api.sample(r.sha256)
      ElMessage.success('AI 行为分析已完成')
    }
    await load()
  } catch { /* 上传/任务错误已在 api 层提示 */ }
  finally { uploading.value = false }
}

async function showDetail(sha256: string) {
  active.value = await api.sample(sha256)
  drawer.value = true
}

function fetchSample() {
  if (active.value) window.open(`/api/samples/${active.value.sha256}/download`)
}

onMounted(load)
</script>

<style scoped>
.block { margin-bottom: 12px; }
.hunt-bar { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.hunt-title { font-weight: 600; }
.dim { font-size: 12px; color: #94a3b8; }
.mono { font-family: Menlo, Consolas, monospace; font-size: 11.5px; }
.break { word-break: break-all; }
.ai-head { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
.family { font-weight: 600; }
.sub { font-size: 12px; color: #64748b; margin: 10px 0 4px; font-weight: 600; }
.chain { margin: 0; padding-left: 18px; font-size: 12.5px; line-height: 1.9; }
.cap { margin: 0 4px 4px 0; }
.mini { font-size: 13px; }
.evi { margin: 0; padding-left: 18px; font-size: 12px; }
.dl-row { display: flex; align-items: flex-start; gap: 6px; margin: 4px 0; }
.dl-host { font-size: 11.5px; color: #64748b; word-break: break-all; }
.ioc { font-size: 12px; margin: 4px 0; line-height: 1.7; }
</style>
