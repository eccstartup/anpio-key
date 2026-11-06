import { h } from 'vue'
import DefaultTheme from 'vitepress/theme'
import CopyForAgent from './CopyForAgent.vue'
import './custom.css'

export default {
  extends: DefaultTheme,
  Layout: () =>
    h(DefaultTheme.Layout, null, {
      'doc-before': () => h(CopyForAgent)
    })
}
