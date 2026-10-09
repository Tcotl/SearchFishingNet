import { createRouter, createWebHistory } from 'vue-router'
import { ensureAuthed } from './auth'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', redirect: '/dashboard' },
    { path: '/dashboard', component: () => import('./views/DashboardView.vue'), meta: { title: '总览看板', icon: 'Odometer' } },
    { path: '/jobs', component: () => import('./views/JobsView.vue'), meta: { title: '采集与研判任务', icon: 'VideoPlay' } },
    { path: '/records', component: () => import('./views/RecordsView.vue'), meta: { title: '研判记录', icon: 'Document' } },
    { path: '/review', component: () => import('./views/ReviewView.vue'), meta: { title: '人工复核', icon: 'Checked' } },
    { path: '/samples', component: () => import('./views/SamplesView.vue'), meta: { title: '样本分析', icon: 'Box' } },
    { path: '/blocklist', component: () => import('./views/BlocklistView.vue'), meta: { title: '封堵管理', icon: 'Lock' } },
    { path: '/whitelist', component: () => import('./views/WhitelistView.vue'), meta: { title: '白名单管理', icon: 'CircleCheck' } },
    { path: '/dict', component: () => import('./views/DictView.vue'), meta: { title: '词库管理', icon: 'Collection' } },
    { path: '/settings', component: () => import('./views/SettingsView.vue'), meta: { title: '系统设置', icon: 'Setting' } },
  ],
})

// 登录在独立的 /login 页面（后端直伺服，不属于本 SPA）。
// 会话失效时整页跳走，保证后台字节不下发给未登录浏览器。
router.beforeEach(async (to) => {
  const ok = await ensureAuthed()
  if (!ok) {
    const target = encodeURIComponent(to.fullPath)
    window.location.href = `/login?redirect=${target}`
    return false
  }
  return true
})

router.afterEach((to) => {
  document.title = `${to.meta.title ?? ''} · SearchFishingNet`
})

export default router
