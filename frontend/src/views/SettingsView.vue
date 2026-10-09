<template>
  <div v-loading="loading" style="max-width: 760px">
    <el-card shadow="never" header="AI 严判接入（OpenAI 兼容协议）" class="block">
      <el-form label-width="150px">
        <el-form-item label="接口地址">
          <el-input v-model="form.ai_base_url" placeholder="https://open.bigmodel.cn/api/paas/v4" />
        </el-form-item>
        <el-form-item label="主判模型（文本推理）">
          <el-input v-model="form.ai_model" placeholder="glm-4.6 / deepseek-r1 / glm-4.5v" />
          <div class="hint">常规推理模型或多模态模型均可。推理模型的思考输出（reasoning_content / &lt;think&gt;）会自动解析；拒绝 temperature 参数时自动适配。</div>
        </el-form-item>
        <el-form-item label="视觉模型（可选）">
          <el-input v-model="form.ai_vision_model" placeholder="如 glm-4.5v，留空则主模型兼任" />
          <div class="hint">用于截图裁决通道（通道B）。与主模型构成"文本推理 + 截图核验"双通道一致性严判；视觉模型不可用时自动降级单通道。</div>
        </el-form-item>
        <el-form-item label="Jev 仲裁模型（可选）">
          <el-input v-model="form.ai_jev_model" placeholder="如 bocha-jev-v1，留空不启用" />
          <div class="hint">结构化评估模型（TypeSafe SystemOne 协议，通道C）：独立输出真假概率/定性概率分布/置信度，与主裁决一致性合并，分歧时保守降级人工；主推理通道不可用时可单独兜底定性。</div>
        </el-form-item>
        <el-form-item label="Jev 评估端点">
          <el-input v-model="form.ai_jev_url" placeholder="留空按接口地址推导（…/v1 → …/typesafe/v1/systemone）" />
        </el-form-item>
        <el-form-item label="API Key">
          <el-input v-model="keyInput" type="password" show-password
                    :placeholder="form.ai_api_key_set ? '已配置（输入新值可覆盖）' : '尚未配置'" />
        </el-form-item>
        <el-form-item label="">
          <el-button :loading="testing" @click="doTest">连通性测试（双模型）</el-button>
          <el-tag v-if="form.ai_api_key_set" type="success" size="small" class="ml">Key 已配置</el-tag>
          <el-tag v-else type="warning" size="small" class="ml">未配置（系统将全部转人工复核）</el-tag>
        </el-form-item>
      </el-form>
    </el-card>

    <el-card shadow="never" header="研判阈值" class="block">
      <el-form label-width="150px">
        <el-form-item label="严格下载管控">
          <el-switch v-model="form.strict_download_policy" active-text="仅放行官方下载渠道" />
          <div class="hint">开启后：已知第三方下载站直接策略封堵（进 DNS 黑名单），soft*/down* 等下载渠道域名降为可疑送 AI 严判；关闭后仅降为待观察。</div>
        </el-form-item>
        <el-form-item label="仅官方域名放行">
          <el-switch v-model="form.strict_official_only" active-text="严格放行策略" />
          <div class="hint">开启后：只有品牌官方域名与人工审定白名单自动放行，其余域名（含无负面信号的长尾站）一律封顶 69 分进入取证与 AI 研判漏斗。关闭则无负面信号的域名自动放行。</div>
        </el-form-item>
        <el-form-item label="自动封堵置信度 ≥">
          <el-slider v-model="form.ai_block_confidence" :min="50" :max="99" show-input style="width: 320px" />
        </el-form-item>
        <el-form-item label="双通道允许置信度差">
          <el-slider v-model="form.ai_consistency_gap" :min="5" :max="60" show-input style="width: 320px" />
        </el-form-item>
      </el-form>
    </el-card>

    <el-card shadow="never" header="可选威胁情报源" class="block">
      <el-form label-width="150px">
        <el-form-item label="VirusTotal Key">
          <el-input v-model="vtInput" type="password" show-password
                    :placeholder="form.vt_api_key_set ? '已配置（输入新值可覆盖）' : '未配置'" />
        </el-form-item>
        <el-form-item label="ICP 备案查询 API">
          <el-input v-model="form.icp_api_url" placeholder="POST 接口地址（可选）" />
        </el-form-item>
        <el-form-item label="ICP API Key">
          <el-input v-model="icpInput" type="password" show-password
                    :placeholder="form.icp_api_key_set ? '已配置（输入新值可覆盖）' : '未配置'" />
        </el-form-item>
      </el-form>
    </el-card>

    <el-button type="primary" size="large" :loading="saving" @click="save">保存设置</el-button>

    <el-card shadow="never" header="账号安全" class="block">
      <el-form label-width="150px" style="max-width: 520px">
        <el-form-item label="原口令">
          <el-input v-model="pw.old" type="password" show-password />
        </el-form-item>
        <el-form-item label="新口令">
          <el-input v-model="pw.new1" type="password" show-password placeholder="至少 5 位" />
        </el-form-item>
        <el-form-item label="确认新口令">
          <el-input v-model="pw.new2" type="password" show-password />
        </el-form-item>
        <el-form-item label="">
          <el-button :loading="changing" @click="doChangePassword">修改口令</el-button>
          <span class="hint" style="margin-left: 10px">默认口令 admin/admin，首次部署建议立即修改</span>
        </el-form-item>
      </el-form>
    </el-card>

    <el-card shadow="never" header="设备接管（P3：封堵工单自动下发）" class="block">
      <el-form label-width="150px">
        <el-form-item label="封堵 Webhook">
          <el-input v-model="form.block_webhook_url" placeholder="POST 接收 {action:'block', domains:[...]} 的 URL（防火墙/SOAR/DNS 网关）" />
        </el-form-item>
        <el-form-item label="AdGuard Home">
          <el-input v-model="form.adguard_url" placeholder="如 http://192.168.1.2（留空不启用）" style="margin-bottom: 6px" />
          <el-input v-model="form.adguard_user" placeholder="API 用户名" style="width: 240px; margin-right: 8px" />
          <el-input v-model="adguardPass" type="password" show-password
                    :placeholder="form.adguard_pass_set ? '已配置（输入新值可覆盖）' : 'API 密码'" style="width: 240px" />
        </el-form-item>
        <el-form-item label="封堵列表订阅 URL">
          <el-input v-model="form.adguard_blocklist_url" placeholder="AdGuard 可访问的封堵 TXT 地址（平台导出或反代 URL）" />
          <div class="hint">AdGuard 以订阅方式跟随平台封堵列表（||域名^ 规则自动维护）。保存后点「测试下发」验证连通；任务页可用「封堵下发」任务手动推送。</div>
        </el-form-item>
        <el-form-item label="">
          <el-button :loading="testingDispatch" @click="doTestDispatch">测试下发渠道</el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <el-card shadow="never" header="部署信息" class="block mt">
      <el-descriptions :column="1" size="small" border>
        <el-descriptions-item label="数据目录">{{ form.data_dir }}</el-descriptions-item>
        <el-descriptions-item label="项目根目录">{{ form.project_root }}</el-descriptions-item>
      </el-descriptions>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api/client'
import type { Settings } from '../api/types'

const loading = ref(true)
const saving = ref(false)
const testing = ref(false)
const form = reactive<Settings>({} as Settings)
const keyInput = ref('')
const vtInput = ref('')
const icpInput = ref('')
const pw = reactive({ old: '', new1: '', new2: '' })
const changing = ref(false)
const adguardPass = ref('')
const testingDispatch = ref(false)

async function doTestDispatch() {
  testingDispatch.value = true
  try {
    const r = await api.testDispatch()
    if (r.ok) ElMessage.success(r.message)
    else ElMessage.error(r.message)
  } finally { testingDispatch.value = false }
}

async function doChangePassword() {
  if (!pw.old || !pw.new1) { ElMessage.warning('请填写原口令和新口令'); return }
  if (pw.new1 !== pw.new2) { ElMessage.warning('两次输入的新口令不一致'); return }
  changing.value = true
  try {
    await api.changePassword(pw.old, pw.new1, pw.new2)
    pw.old = pw.new1 = pw.new2 = ''
    ElMessage.success('口令已修改，下次登录生效')
  } catch { /* 错误已在 api 层提示 */ }
  finally { changing.value = false }
}

async function load() {
  loading.value = true
  try {
    Object.assign(form, await api.settings())
  } finally {
    loading.value = false
  }
}

async function save() {
  saving.value = true
  try {
    const patch: Record<string, unknown> = {
      ai_base_url: form.ai_base_url,
      ai_model: form.ai_model,
      ai_vision_model: form.ai_vision_model,
      ai_jev_model: form.ai_jev_model,
      ai_jev_url: form.ai_jev_url,
      ai_block_confidence: form.ai_block_confidence,
      ai_consistency_gap: form.ai_consistency_gap,
      strict_download_policy: form.strict_download_policy,
      strict_official_only: form.strict_official_only,
      icp_api_url: form.icp_api_url,
      block_webhook_url: form.block_webhook_url,
      adguard_url: form.adguard_url,
      adguard_user: form.adguard_user,
      adguard_blocklist_url: form.adguard_blocklist_url,
    }
    if (keyInput.value) patch.ai_api_key = keyInput.value
    if (vtInput.value) patch.vt_api_key = vtInput.value
    if (icpInput.value) patch.icp_api_key = icpInput.value
    if (adguardPass.value) patch.adguard_pass = adguardPass.value
    Object.assign(form, await api.saveSettings(patch))
    keyInput.value = vtInput.value = icpInput.value = ''
    ElMessage.success('设置已保存并即时生效')
  } finally {
    saving.value = false
  }
}

async function doTest() {
  testing.value = true
  try {
    const r = await api.testAi()
    if (r.ok) ElMessage.success(r.message)
    else ElMessage.error(r.message)
  } finally {
    testing.value = false
  }
}

onMounted(load)
</script>

<style scoped>
.block { margin-bottom: 12px; }
.ml { margin-left: 10px; }
.mt { margin-top: 12px; }
.hint { font-size: 12px; color: #94a3b8; line-height: 1.6; max-width: 420px; }
</style>
