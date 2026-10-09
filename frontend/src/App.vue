<template>
  <MainLayout />
</template>

<script setup lang="ts">
import MainLayout from './layout/MainLayout.vue'
</script>

<style>
html, body, #app {
  height: 100%;
  margin: 0;
  background: #f5f7fa;
  font-family: -apple-system, "PingFang SC", "Microsoft YaHei", "Helvetica Neue", sans-serif;
  -webkit-font-smoothing: antialiased;
}

/* ---- 企业级统一风格 ---- */
.el-card {
  border-radius: 8px;
  border-color: #e8edf2;
}
.el-card__header {
  font-weight: 600;
  font-size: 13.5px;
  color: #1e293b;
  border-bottom: 1px solid #f1f5f9;
  padding: 12px 18px;
}
.el-table th.el-table__cell {
  background: #f8fafc !important;
  color: #475569;
  font-weight: 600;
}
.el-table { --el-table-row-hover-bg-color: #f0f6ff; }
.el-drawer__title { font-weight: 600; color: #1e293b; }
</style>
