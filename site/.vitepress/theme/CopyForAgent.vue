<script setup lang="ts">
import { computed, onUnmounted, ref } from 'vue'
import { useData } from 'vitepress'

type CopyState = 'idle' | 'done' | 'error'

const { page, theme, lang } = useData()

const isZh = computed(() => (lang.value || '').toLowerCase().startsWith('zh'))
const markdown = computed(
  () => (page.value as Record<string, unknown>).agentMarkdown as string | undefined
)

const labels = computed(() =>
  isZh.value
    ? {
        idle: '复制给 Agent',
        done: '已复制',
        error: '复制失败',
        title: '把本页 Markdown 复制到剪贴板，可直接粘贴给 Agent'
      }
    : {
        idle: 'Copy for Agent',
        done: 'Copied',
        error: 'Copy failed',
        title: 'Copy this page as Markdown for your agent'
      }
)

const state = ref<CopyState>('idle')
let timer: ReturnType<typeof setTimeout> | undefined

const repoUrl = computed(() => {
  const links = (theme.value.socialLinks || []) as Array<{ icon?: string; link?: string }>
  const social = links.find((link) => link.icon === 'github')?.link
  if (social) return social
  const edit = (theme.value.editLink as { pattern?: string } | undefined)?.pattern
  return edit?.match(/^(https:\/\/github\.com\/[^/]+\/[^/]+)\/edit\//)?.[1]
})

const payload = computed(() => {
  const repo = repoUrl.value
  const url = typeof window === 'undefined' ? '' : window.location.href.split('#')[0]
  const head = isZh.value
    ? `> 文档来源：${url}${repo ? ` · 代码仓库：${repo}` : ''}`
    : `> Source: ${url}${repo ? ` · Repository: ${repo}` : ''}`
  return `${head}\n\n${markdown.value?.trim() ?? ''}\n`
})

function copyWithTextarea(value: string) {
  const textarea = document.createElement('textarea')
  textarea.value = value
  textarea.setAttribute('readonly', '')
  textarea.style.position = 'fixed'
  textarea.style.opacity = '0'
  document.body.appendChild(textarea)
  textarea.select()
  const ok = document.execCommand('copy')
  textarea.remove()
  if (!ok) throw new Error('copy failed')
}

async function copy() {
  const value = payload.value
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(value)
    } else {
      copyWithTextarea(value)
    }
    state.value = 'done'
  } catch {
    try {
      copyWithTextarea(value)
      state.value = 'done'
    } catch {
      state.value = 'error'
    }
  }
  clearTimeout(timer)
  timer = setTimeout(() => {
    state.value = 'idle'
  }, 2000)
}

onUnmounted(() => clearTimeout(timer))
</script>

<template>
  <div v-if="markdown" class="copy-for-agent">
    <button
      type="button"
      class="copy-for-agent-button"
      :class="`is-${state}`"
      :title="labels.title"
      :aria-label="labels.title"
      @click="copy"
    >
      <svg
        v-if="state === 'done'"
        width="14"
        height="14"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        stroke-width="2"
        stroke-linecap="round"
        stroke-linejoin="round"
        aria-hidden="true"
      >
        <path d="M20 6 9 17l-5-5" />
      </svg>
      <svg
        v-else
        width="14"
        height="14"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        stroke-width="2"
        stroke-linecap="round"
        stroke-linejoin="round"
        aria-hidden="true"
      >
        <rect x="9" y="9" width="13" height="13" rx="2" />
        <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
      </svg>
      <span>{{ labels[state] }}</span>
    </button>
  </div>
</template>

<style scoped>
.copy-for-agent {
  display: flex;
  justify-content: flex-end;
  margin: 0 0 -12px;
}

.copy-for-agent-button {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 5px 12px;
  border: 1px solid var(--vp-c-divider);
  border-radius: 999px;
  background-color: var(--vp-c-bg);
  color: var(--vp-c-text-2);
  font-size: 13px;
  font-weight: 500;
  line-height: 1.4;
  cursor: pointer;
  transition:
    color 0.2s,
    border-color 0.2s,
    background-color 0.2s;
}

.copy-for-agent-button:hover {
  color: var(--vp-c-brand-1);
  border-color: var(--vp-c-brand-1);
  background-color: var(--vp-c-brand-soft);
}

.copy-for-agent-button.is-done,
.copy-for-agent-button.is-error {
  color: var(--vp-c-brand-1);
  border-color: var(--vp-c-brand-1);
}

.copy-for-agent-button svg {
  flex: none;
}

@media (max-width: 639px) {
  .copy-for-agent {
    justify-content: flex-start;
  }
}
</style>
