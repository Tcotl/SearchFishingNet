<template>
  <div>
    <el-card shadow="never" header="发起任务" class="block">
      <el-form :model="form" label-width="90px" inline>
        <el-form-item label="任务类型">
          <el-radio-group v-model="form.type">
            <el-radio-button value="pipeline">采集 + 研判</el-radio-button>
            <el-radio-button value="crawl">仅采集</el-radio-button>
            <el-radio-button value="agent_discover">Agent 扩展采集</el-radio-button>
            <el-radio-button value="ingest">研判已有文件</el-radio-button>
            <el-radio-button value="judge">单域研判</el-radio-button>
            <el-radio-button value="rescore">存量重评分</el-radio-button>
            <el-radio-button value="rejudge_pending">重判待复核</el-radio-button>
            <el-radio-button value="dispatch_block">封堵下发</el-radio-button>
          </el-radio-group>
        </el-form-item>

        <template v-if="form.type === 'agent_discover'">
          <el-form-item label="种子词">
            <KeywordSelect v-model="form.keywords" />
            <span class="dim ml">留空则从词库随机抽 5 个；AI 自动扩展搜索变体并用 DuckDuckGo 免费引擎检索</span>
          </el-form-item>
          <el-form-item label="入库上限">
            <el-input-number v-model="form.max_new_domains" :min="5" :max="100" /> 个新域名
          </el-form-item>
        </template>

        <template v-if="form.type === 'dispatch_block'">
          <el-form-item label="">
            <span class="dim">把当前全部封堵域名下发到已配置渠道（设置页 → 设备接管：webhook / AdGuard Home）。未配置渠道会提示失败。</span>
          </el-form-item>
        </template>

        <el-form-item v-if="form.type === 'judge'" label="域名">
          <el-input v-model="form.domain" placeholder="例如 dingtalk-app.top" style="width: 260px" />
        </el-form-item>

        <template v-if="form.type === 'ingest'">
          <el-form-item label="数据来源">
            <el-select v-model="form.file" style="width: 300px" placeholder="选择爬虫结果文件">
              <el-option label="最新一次采集结果" value="latest" />
              <el-option v-for="u in uploads" :key="u.filename" :value="u.filename"
                         :label="`${u.filename}（${Math.ceil(u.size / 1024)} KB）`" />
            </el-select>
          </el-form-item>
          <el-form-item label="">
            <el-upload :show-file-list="false" :http-request="doUpload" accept=".json">
              <el-button>上传爬虫 JSON</el-button>
            </el-upload>
          </el-form-item>
        </template>

        <template v-if="form.type === 'pipeline' || form.type === 'crawl'">
          <el-form-item label="关键词范围">
            <KeywordSelect v-model="form.keywords" />
          </el-form-item>
        </template>

        <el-form-item v-if="form.type === 'pipeline' || form.type === 'crawl'" label="采集深度">
          <el-input-number v-model="form.max_pages" :min="1" :max="10" /> 页
          <el-input-number v-model="form.max_results" :min="5" :max="100" class="ml" /> 条/引擎
        </el-form-item>

        <el-form-item v-if="form.type === 'pipeline'" label="断点续跑">
          <el-switch v-model="form.resume" active-text="跳过 24h 内已采集关键词" />
        </el-form-item>

        <el-form-item v-if="form.type === 'pipeline' || form.type === 'ingest' || form.type === 'judge'" label="AI 接入">
          <el-switch v-model="form.mock_ai" active-text="Mock（离线测试）" />
          <el-switch v-model="form.skip_evidence" active-text="跳过取证" class="ml" />
        </el-form-item>

        <el-form-item label="">
          <el-button type="primary" :loading="submitting" @click="submit">启动任务</el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <el-card shadow="never" header="任务历史">
      <el-table :data="jobs" size="small" @row-click="openJob">
        <el-table-column label="类型" width="110">
          <template #default="{ row }">{{ jobTypeLabel(row.type) }}</template>
        </el-table-column>
        <el-table-column label="参数" min-width="220" show-overflow-tooltip>
          <template #default="{ row }">{{ JSON.stringify(row.params) }}</template>
        </el-table-column>
        <el-table-column label="状态" width="90">
          <template #default="{ row }">
            <el-tag :type="jobStatusTag(row.status)" size="small">{{ row.status }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="创建时间" width="160">
          <template #default="{ row }">{{ fmtTime(row.created_at) }}</template>
        </el-table-column>
        <el-table-column label="完成时间" width="160">
          <template #default="{ row }">{{ fmtTime(row.finished_at) }}</template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-drawer v-model="drawer" :title="`任务进度 · ${active?.id ?? ''}`" size="55%">
      <template v-if="active">
        <div class="job-head">
          <el-tag :type="jobStatusTag(liveStatus)">{{ liveStatus }}</el-tag>
          <span class="job-params">{{ JSON.stringify(active.params) }}</span>
        </div>
        <pre ref="logEl" class="log">{{ logText }}</pre>
        <el-alert v-if="liveStatus === 'failed'" type="error" :title="active.error" :closable="false" />
        <el-descriptions v-if="liveStatus === 'success' && active.result" :column="2" border size="small">
          <el-descriptions-item v-for="(v, k) in flatResult" :key="k" :label="String(k)">
            {{ v }}
          </el-descriptions-item>
        </el-descriptions>
      </template>
    </el-drawer>
  </div>
</template>

<script setup lang="ts">
import { nextTick, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api/client'
import type { Job } from '../api/types'
import { fmtTime, jobStatusTag, jobTypeLabel } from '../lib/display'
import KeywordSelect from '../components/KeywordSelect.vue'

const form = reactive({
  type: 'pipeline',
  domain: '',
  file: 'latest',
  keywords: [] as string[],
  max_pages: 2,
  max_results: 15,
  mock_ai: false,
  skip_evidence: false,
  resume: true,
  max_new_domains: 30,
})
const jobs = ref<Job[]>([])
const uploads = ref<{ filename: string; size: number }[]>([])
const submitting = ref(false)
const drawer = ref(false)
const active = ref<Job | null>(null)
const liveStatus = ref('')
const logText = ref('')
const logEl = ref<HTMLElement>()
let es: EventSource | null = null
let pollTimer: number | null = null

const flatResult = ref<Record<string, unknown>>({})

function submit() {
  if (form.type === 'rescore' || form.type === 'rejudge_pending') {
    submitting.value = true
    api.createJob(form.type, {})
      .then(job => {
        ElMessage.success('任务已启动')
        openJob(job)
        refresh()
      })
      .finally(() => { submitting.value = false })
    return
  }
  const params: Record<string, unknown> = {
    mock_ai: form.mock_ai,
    skip_evidence: form.skip_evidence,
  }
  if (form.type === 'judge') {
    if (!form.domain.trim()) return ElMessage.warning('请输入域名')
    params.domain = form.domain.trim()
  }
  if (form.type === 'ingest') params.file = form.file
  if (form.type === 'agent_discover') {
    if (form.keywords.length) params.keywords = form.keywords
    params.max_new_domains = form.max_new_domains
    delete params.mock_ai
    delete params.skip_evidence
  }
  if (form.type === 'dispatch_block') {
    delete params.mock_ai
    delete params.skip_evidence
  }
  if (form.type === 'pipeline' || form.type === 'crawl') {
    if (form.keywords.length) params.keywords = form.keywords
    params.max_pages = form.max_pages
    params.max_results = form.max_results
    if (form.type === 'pipeline') params.resume = form.resume
  }
  submitting.value = true
  api.createJob(form.type, params)
    .then(job => {
      ElMessage.success('任务已启动')
      openJob(job)
      refresh()
    })
    .finally(() => { submitting.value = false })
}

function openJob(job: Job) {
  active.value = job
  liveStatus.value = job.status
  logText.value = ''
  flatResult.value = {}
  drawer.value = true
  startStream(job.id)
}

function startStream(jobId: string) {
  es?.close()
  es = new EventSource(`/api/jobs/${jobId}/events`)
  es.onmessage = (ev) => {
    const data = JSON.parse(ev.data)
    if (data.line) {
      logText.value += data.line + '\n'
      nextTick(() => logEl.value?.scrollTo({ top: logEl.value.scrollHeight }))
    }
    if (data.done) {
      liveStatus.value = data.status
      es?.close()
      if (data.status === 'failed') nextTick(() => { if (active.value) active.value.error = data.error })
      refresh()
      // 拉取最终 result
      api.job(jobId).then(j => {
        active.value = j
        if (j.status === 'success') flatten(j.result)
      })
    }
  }
  es.onerror = () => es?.close()
}

function flatten(result: Record<string, unknown> | null) {
  if (!result) return
  const flat: Record<string, unknown> = {}
  const stats = result.stats as Record<string, number> | undefined
  if (stats) {
    flat['输入域名'] = stats.total
    flat['白名单放行'] = stats.trusted
    flat['确认封堵'] = stats.blocked
    flat['待复核'] = stats.review
    flat['放行'] = stats.allowed
  }
  if (result.blocked_domains) flat['封堵域名'] = (result.blocked_domains as string[]).join(', ')
  if (result.outputs) flat['产出文件'] = (result.outputs as string[]).map(p => p.split('/').pop()).join(', ')
  flatResult.value = flat
}

async function refresh() {
  jobs.value = await api.jobs()
  uploads.value = await api.uploads()
}

async function doUpload(opt: { file: File }) {
  const r = await api.upload(opt.file)
  ElMessage.success(`上传成功：${r.filename}`)
  form.file = r.filename
  uploads.value = await api.uploads()
}

onMounted(refresh)
onBeforeUnmount(() => {
  es?.close()
  if (pollTimer) window.clearInterval(pollTimer)
})
</script>

<style scoped>
.block { margin-bottom: 12px; }
.ml { margin-left: 12px; }
.kw-input { display: flex; align-items: center; flex-wrap: wrap; gap: 6px; max-width: 640px; }
.kw-tag { margin: 0; }
.job-head { display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }
.job-params { font-size: 12px; color: #64748b; word-break: break-all; }
.log {
  background: #0f172a; color: #a5f3fc; font-size: 12px; line-height: 1.7;
  border-radius: 6px; padding: 12px; max-height: 46vh; overflow-y: auto;
  white-space: pre-wrap; word-break: break-all; margin: 0 0 12px;
}
</style>
