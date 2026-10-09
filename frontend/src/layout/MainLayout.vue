<template>
  <el-container style="height: 100vh">
    <el-aside width="220px" class="sidebar">
      <div class="brand">
        <span class="logo">🎣</span>
        <div>
          <div class="brand-name">SearchFishingNet</div>
          <div class="brand-sub">钓鱼威胁情报平台</div>
        </div>
      </div>
      <el-menu
        :default-active="route.path"
        router
        background-color="#1d2b36"
        text-color="#a7b6c2"
        active-text-color="#ffffff"
        class="menu"
      >
        <el-menu-item index="/dashboard">
          <el-icon><Odometer /></el-icon>
          <span>总览看板</span>
        </el-menu-item>

        <el-menu-item-group title="威胁运营">
          <el-menu-item index="/records">
            <el-icon><Document /></el-icon><span>研判记录</span>
          </el-menu-item>
          <el-menu-item index="/review">
            <el-icon><Checked /></el-icon><span>人工复核</span>
            <el-badge v-if="pendingCount" :value="pendingCount" :max="999" class="menu-badge" />
          </el-menu-item>
          <el-menu-item index="/samples">
            <el-icon><Box /></el-icon><span>样本分析</span>
          </el-menu-item>
        </el-menu-item-group>

        <el-menu-item-group title="防护处置">
          <el-menu-item index="/blocklist">
            <el-icon><Lock /></el-icon><span>封堵管理</span>
          </el-menu-item>
          <el-menu-item index="/jobs">
            <el-icon><VideoPlay /></el-icon><span>任务中心</span>
          </el-menu-item>
        </el-menu-item-group>

        <el-menu-item-group title="情报库">
          <el-menu-item index="/whitelist">
            <el-icon><CircleCheck /></el-icon><span>白名单</span>
          </el-menu-item>
          <el-menu-item index="/dict">
            <el-icon><Collection /></el-icon><span>词库管理</span>
          </el-menu-item>
        </el-menu-item-group>

        <el-menu-item-group title="系统">
          <el-menu-item index="/settings">
            <el-icon><Setting /></el-icon><span>系统设置</span>
          </el-menu-item>
        </el-menu-item-group>
      </el-menu>
      <div class="sidebar-foot">
        <div>Enterprise Edition</div>
        <div>{{ versionTag }}</div>
      </div>
    </el-aside>
    <el-main class="main">
      <div class="topbar">
        <div>
          <div class="crumb">{{ route.meta.title }}</div>
          <div class="crumb-sub">{{ pageDesc[route.path] ?? '' }}</div>
        </div>
        <span class="userbox">
          <el-icon><User /></el-icon>
          <span>{{ user || 'admin' }}</span>
          <el-divider direction="vertical" />
          <el-link type="danger" :underline="false" @click="logout">退出登录</el-link>
        </span>
      </div>
      <router-view />
    </el-main>
  </el-container>
</template>

<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import {
  Odometer, Document, Checked, Box, Lock, VideoPlay, CircleCheck, Collection, Setting, User,
} from '@element-plus/icons-vue'
import { api } from '../api/client'
import { currentUser, clearSession } from '../auth'

const route = useRoute()
const user = ref(currentUser())
const pendingCount = ref(0)
const versionTag = "v1.0.0"

const pageDesc: Record<string, string> = {
  '/dashboard': '威胁情报总览与运营指标',
  '/records': '全量研判记录检索与证据链查看',
  '/review': 'AI 无法定论记录的人工终审工作台',
  '/samples': '恶意载荷隔离库 · 静态分析 · AI 行为推断',
  '/blocklist': 'DNS 封堵产物管理与多格式导出',
  '/jobs': '采集、研判、样本与设备下发任务',
  '/whitelist': '可信域名白名单（人工审定与误报回流）',
  '/dict': '采集关键词与品牌官方域名映射（一票通过事实源）',
  '/settings': 'AI 接入 · 阈值 · 情报源 · 设备接管 · 账号安全',
}

let pollTimer: number | null = null

async function refreshBadge() {
  try {
    const s = await api.dashboard()
    pendingCount.value = s.pending_review ?? 0
  } catch { /* 后端不可达时静默 */ }
}

async function logout() {
  try { await api.logout() } catch { /* 会话可能已失效 */ }
  clearSession()
  window.location.href = '/login'  // 独立登录口（非 SPA 路由），整页跳转
}

onMounted(() => {
  refreshBadge()
  pollTimer = window.setInterval(refreshBadge, 60_000)
})
onBeforeUnmount(() => { if (pollTimer) window.clearInterval(pollTimer) })
</script>

<style scoped>
.sidebar {
  background: #1d2b36;
  display: flex;
  flex-direction: column;
}
.brand {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 18px 16px;
  color: #fff;
}
.logo { font-size: 26px; }
.brand-name { font-weight: 700; font-size: 15px; letter-spacing: 0.3px; }
.brand-sub { font-size: 11px; color: #7d8f9d; margin-top: 2px; }
.menu { border-right: none; flex: 1; }
.menu :deep(.el-menu-item.is-active) { background: #2563eb !important; }
.menu :deep(.el-menu-item-group__title) {
  padding: 12px 16px 4px;
  font-size: 11px;
  color: #5d7285;
  letter-spacing: 1px;
}
.menu-badge { margin-left: auto; margin-right: 8px; }
.sidebar-foot {
  padding: 14px 16px;
  font-size: 11px;
  color: #546b7d;
  border-top: 1px solid #16222c;
  line-height: 1.7;
}
.main { padding: 16px 20px; overflow-y: auto; background: #f5f7fa; }
.topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 14px;
}
.crumb { font-size: 17px; font-weight: 700; color: #1e293b; }
.crumb-sub { font-size: 12px; color: #94a3b8; margin-top: 2px; }
.userbox {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 13px;
  color: #475569;
}
</style>
