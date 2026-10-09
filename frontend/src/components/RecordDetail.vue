<template>
  <div v-if="record" class="detail">
    <el-descriptions :column="2" border size="small" class="block">
      <el-descriptions-item label="域名">{{ record.domain }}</el-descriptions-item>
      <el-descriptions-item label="记录ID">{{ record.id }}</el-descriptions-item>
      <el-descriptions-item label="规则评分">
        <el-tag :type="scoreTagType" size="small">{{ record.score?.score ?? '-' }} / 100（{{ tierLabel }}）</el-tag>
      </el-descriptions-item>
      <el-descriptions-item label="首次发现">{{ record.created }}</el-descriptions-item>
    </el-descriptions>

    <el-row :gutter="12">
      <el-col :span="14">
        <el-card shadow="never" header="L1 规则评分明细" class="block">
          <el-table :data="record.score?.breakdown ?? []" size="small">
            <el-table-column label="因子" width="110">
              <template #default="{ row }">{{ factorNames[row.factor] ?? row.factor }}</template>
            </el-table-column>
            <el-table-column label="分值" width="70">
              <template #default="{ row }">
                <span :class="row.delta < 0 ? 'delta-neg' : row.delta > 0 ? 'delta-pos' : ''">
                  {{ row.delta > 0 ? '+' + row.delta : row.delta }}
                </span>
              </template>
            </el-table-column>
            <el-table-column prop="detail" label="依据" show-overflow-tooltip />
          </el-table>
        </el-card>

        <el-card shadow="never" header="搜索语境（来源命中）" class="block">
          <el-table :data="record.hits ?? []" size="small">
            <el-table-column prop="engine" label="引擎" width="70" />
            <el-table-column prop="keyword" label="关键词" width="110" show-overflow-tooltip />
            <el-table-column prop="rank" label="排名" width="60" />
            <el-table-column prop="title" label="结果标题" show-overflow-tooltip />
          </el-table>
        </el-card>

        <el-card v-if="record.evidence" shadow="never" header="L2 动态取证" class="block">
          <el-descriptions :column="1" size="small" border>
            <el-descriptions-item label="状态">
              <el-tag :type="record.evidence.ok ? 'success' : 'danger'" size="small">
                {{ record.evidence.ok ? '取证成功' : '取证失败' }}
              </el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="落地URL">{{ record.evidence.final_url || '-' }}</el-descriptions-item>
            <el-descriptions-item label="页面标题">{{ record.evidence.page_title || '-' }}</el-descriptions-item>
            <el-descriptions-item v-if="record.evidence.form_fields.length" label="表单字段">
              {{ record.evidence.form_fields.map(f => f.type).join(', ') }}
            </el-descriptions-item>
            <el-descriptions-item v-if="record.evidence.error" label="错误">{{ record.evidence.error }}</el-descriptions-item>
          </el-descriptions>
          <template v-if="record.evidence.download_links?.length">
            <div class="sub">下载链路（安装包托管位置）</div>
            <div v-for="(d, i) in record.evidence.download_links.slice(0, 6)" :key="i" class="dl-row">
              <el-tag v-if="d.netdisk" type="danger" size="small">网盘/短链</el-tag>
              <el-tag v-else-if="d.offsite" type="warning" size="small">站外主机</el-tag>
              <el-tag v-else type="success" size="small">本站托管</el-tag>
              <span class="dl-text">{{ d.text || '下载' }}</span>
              <span class="dl-host">{{ d.host }}</span>
            </div>
          </template>
          <template v-if="record.evidence.brand_mentions?.length">
            <div class="sub">页面品牌宣称</div>
            <el-tag v-for="b in record.evidence.brand_mentions" :key="b" size="small" type="info" class="brand-tag">{{ b }}</el-tag>
          </template>
          <el-image
            v-if="record.evidence.screenshot_path"
            :src="`/api/records/${record.domain}/screenshot`"
            :preview-src-list="[`/api/records/${record.domain}/screenshot`]"
            fit="contain"
            style="margin-top: 10px; max-height: 300px; width: 100%"
            preview-teleported
          >
            <template #error><div class="img-err">截图加载失败</div></template>
          </el-image>
        </el-card>
      </el-col>

      <el-col :span="10">
        <el-card shadow="never" header="L3 AI 严判" class="block">
          <template v-if="record.ai_verdict">
            <div class="verdict-head">
              <el-tag :type="verdictTag[record.ai_verdict.verdict]?.type ?? 'info'" size="large">
                {{ verdictTag[record.ai_verdict.verdict]?.label ?? record.ai_verdict.verdict }}
              </el-tag>
              <span class="channel">{{ record.ai_verdict.channel }}</span>
            </div>
            <div class="conf-line">
              <span>置信度</span>
              <el-progress :percentage="record.ai_verdict.confidence" :stroke-width="14"
                           :status="record.ai_verdict.confidence >= 75 ? 'exception' : undefined" />
            </div>
            <p v-if="record.ai_verdict.impersonated_brand" class="mini">
              被假冒品牌：<b>{{ record.ai_verdict.impersonated_brand }}</b>
            </p>
            <div class="sub">裁决证据</div>
            <ul class="evi">
              <li v-for="(e, i) in record.ai_verdict.evidence" :key="i">{{ e }}</li>
            </ul>
            <template v-if="record.ai_verdict.risk_points.length">
              <div class="sub">风险点</div>
              <ul class="evi risk">
                <li v-for="(r, i) in record.ai_verdict.risk_points" :key="i">{{ r }}</li>
              </ul>
            </template>
          </template>
          <el-empty v-else description="尚未进行 AI 严判（未配置 API Key 或未触发研判）" :image-size="60" />
        </el-card>

        <el-card v-if="record.evidence?.text_excerpt" shadow="never" header="页面正文摘录" class="block">
          <div class="excerpt">{{ record.evidence.text_excerpt.slice(0, 1200) }}</div>
        </el-card>
      </el-col>
    </el-row>

    <div class="actions">
      <el-button size="small" type="danger" plain @click="decide('confirm_block')">确认恶意·封堵</el-button>
      <el-button size="small" type="info" plain @click="decide('false_positive')">误报回滚（移出封堵）</el-button>
      <el-button size="small" type="success" plain @click="decide('allow')">放行</el-button>
      <el-button v-if="record.disposition === 'auto_blocked' || record.disposition === 'policy_blocked'"
                 size="small" type="warning" plain :loading="hunting" @click="huntSample">
        样本分析（从该站下载载荷）
      </el-button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api } from '../api/client'
import type { ThreatRecord } from '../api/types'
import { factorNames, verdictTag } from '../lib/display'

const props = defineProps<{ record: ThreatRecord | null }>()
const emit = defineEmits<{ changed: [] }>()
const hunting = ref(false)

async function huntSample() {
  if (!props.record) return
  hunting.value = true
  try {
    await api.createJob('sample_hunt', { domain: props.record.domain })
    ElMessage.success('样本猎取任务已启动，可在「样本分析」页查看结果')
  } finally {
    hunting.value = false
  }
}

const tierLabel = computed(() =>
  ({ trusted: '可信', watch: '待观察', suspicious: '可疑', dangerous: '高危' })[props.record?.score?.tier ?? ''] ?? '-')

const scoreTagType = computed(() => {
  const s = props.record?.score?.score ?? 0
  return s >= 70 ? 'success' : s >= 40 ? 'warning' : 'danger'
})

async function decide(kind: 'confirm_block' | 'false_positive' | 'allow') {
  const rec = props.record
  if (!rec) return
  const labels = {
    confirm_block: '确认为恶意并加入封堵',
    false_positive: '标记为误报（移出封堵并加入白名单候选）',
    allow: '直接放行',
  }
  try {
    await ElMessageBox.confirm(`确定对 ${rec.domain} 执行「${labels[kind]}」？`, '复核处置', { type: 'warning' })
  } catch {
    return
  }
  await api.feedback(rec.domain, { kind, add_whitelist: kind === 'allow' || kind === 'false_positive' })
  ElMessage.success('处置完成，封堵产物已更新')
  emit('changed')
}
</script>

<style scoped>
.block { margin-bottom: 12px; }
.delta-neg { color: #dc2626; font-weight: 600; }
.delta-pos { color: #16a34a; font-weight: 600; }
.actions { margin-top: 4px; display: flex; gap: 8px; }
.verdict-head { display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }
.channel { font-size: 12px; color: #94a3b8; }
.conf-line { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
.conf-line .el-progress { flex: 1; }
.mini { font-size: 13px; margin: 6px 0; }
.sub { font-size: 12px; color: #64748b; margin: 10px 0 4px; font-weight: 600; }
.evi { margin: 0; padding-left: 18px; font-size: 12.5px; line-height: 1.8; }
.evi.risk { color: #b45309; }
.excerpt { font-size: 12px; color: #475569; line-height: 1.7; white-space: pre-wrap; max-height: 220px; overflow-y: auto; }
.dl-row { display: flex; align-items: center; gap: 6px; margin: 4px 0; font-size: 12px; }
.dl-text { color: #334155; }
.dl-host { color: #64748b; word-break: break-all; }
.brand-tag { margin: 0 4px 4px 0; }
.img-err { display: flex; align-items: center; justify-content: center; height: 120px; color: #94a3b8; font-size: 12px; }
</style>
