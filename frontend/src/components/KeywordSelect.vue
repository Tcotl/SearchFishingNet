<template>
  <div class="kw-select">
    <div class="toolbar">
      <el-checkbox :model-value="allVisibleSelected" :indeterminate="someVisibleSelected"
                   @change="toggleAllVisible">全选</el-checkbox>
      <el-button size="small" text @click="clearAll">清空</el-button>
      <el-input v-model="filter" size="small" clearable placeholder="搜索关键词" style="width: 180px" />
      <el-input v-model="customInput" size="small" style="width: 200px"
                placeholder="自定义关键词，回车加入词库" @keydown.enter.prevent="addCustom" />
      <span class="count">已选 {{ modelValue.length }} / {{ totalKw }}</span>
    </div>

    <div class="groups" v-loading="loading">
      <div v-for="g in visibleGroups" :key="g.category" class="kw-group">
        <div class="group-head">
          <el-checkbox :model-value="isGroupAll(g)" :indeterminate="isGroupSome(g)"
                       @change="(v: any) => toggleGroup(g, v)">
            <span class="group-name">{{ g.category }}</span>
            <span class="group-count">{{ g.keywords.length }}</span>
          </el-checkbox>
        </div>
        <el-checkbox v-for="kw in g.keywords" :key="kw" :value="kw" class="kw-item">
          {{ kw }}
        </el-checkbox>
      </div>
      <el-empty v-if="!visibleGroups.length && !loading" description="无匹配关键词" :image-size="50" />
    </div>

    <div class="hint">全不选 = 使用全部词库</div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api/client'

const props = defineProps<{ modelValue: string[] }>()
const emit = defineEmits<{ 'update:modelValue': [v: string[]] }>()

const loading = ref(true)
const filter = ref('')
const customInput = ref('')
const groups = ref<{ category: string; keywords: string[] }[]>([])
const totalKw = ref(0)

const visibleGroups = computed(() => {
  const needle = filter.value.trim().toLowerCase()
  if (!needle) return groups.value
  return groups.value
    .map(g => ({ ...g, keywords: g.keywords.filter(k => k.toLowerCase().includes(needle)) }))
    .filter(g => g.keywords.length)
})

const allVisible = computed(() => visibleGroups.value.flatMap(g => g.keywords))
const allVisibleSelected = computed(() =>
  allVisible.value.length > 0 && allVisible.value.every(k => props.modelValue.includes(k)))
const someVisibleSelected = computed(() =>
  !allVisibleSelected.value && allVisible.value.some(k => props.modelValue.includes(k)))

function setSelected(next: string[]) {
  emit('update:modelValue', [...new Set(next)])
}

function toggleAllVisible(checked: boolean) {
  if (checked) setSelected([...props.modelValue, ...allVisible.value])
  else setSelected(props.modelValue.filter(k => !allVisible.value.includes(k)))
}

function isGroupAll(g: { keywords: string[] }): boolean {
  return g.keywords.every(k => props.modelValue.includes(k))
}
function isGroupSome(g: { keywords: string[] }): boolean {
  return !isGroupAll(g) && g.keywords.some(k => props.modelValue.includes(k))
}
function toggleGroup(g: { keywords: string[] }, checked: boolean) {
  if (checked) setSelected([...props.modelValue, ...g.keywords])
  else setSelected(props.modelValue.filter(k => !g.keywords.includes(k)))
}
function clearAll() {
  setSelected([])
}

async function addCustom() {
  const kw = customInput.value.trim()
  if (!kw) return
  try {
    await api.addKeyword(kw)
    await load()
    setSelected([...props.modelValue, kw])
    ElMessage.success(`已加入词库并选中: ${kw}`)
    customInput.value = ''
  } catch { /* 错误已由 client 提示 */ }
}

async function load() {
  loading.value = true
  try {
    const r = await api.keywordGroups()
    groups.value = r.groups
    totalKw.value = r.total
  } finally {
    loading.value = false
  }
}

onMounted(async () => {
  await load()
  // 默认全选（典型场景为全量跑批；一键按钮同理）
  setSelected(allVisible.value)
})
</script>

<style scoped>
.kw-select {
  width: 100%;
  border: 1px solid #e2e8f0;
  border-radius: 6px;
  padding: 10px 12px;
  background: #f8fafc;
}
.toolbar { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; margin-bottom: 8px; }
.count { font-size: 12px; color: #2563eb; font-weight: 600; }
.groups { max-height: 260px; overflow-y: auto; }
.kw-group { margin-bottom: 6px; }
.group-head { margin-bottom: 2px; }
.group-name { font-weight: 600; }
.group-count { font-size: 11px; color: #94a3b8; margin-left: 4px; }
.kw-group .el-checkbox { margin-right: 6px; }
.kw-item { margin-right: 4px; }
.kw-item :deep(.el-checkbox__label) { font-size: 12.5px; padding-left: 4px; }
.hint { font-size: 11.5px; color: #94a3b8; margin-top: 6px; }
</style>
