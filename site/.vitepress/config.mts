import { defineConfig } from 'vitepress'

// 中文按词切,而不是按字符切。VitePress 内置的本地搜索默认拿空白和标点分词,
// 中文整段会变成一个巨大的词条 —— 搜什么都搜不出来。
//
// 这里有个坑,踩过一次:miniSearch 把分词函数 `toString()` 存进索引,到浏览器
// 再 eval 回来 —— 闭包在那头是空的,引一个外面的 `segmenter` 就是 ReferenceError。
// 所以这个函数必须自给自足:只碰参数和 globalThis,分词器现取现建。
const tokenize = (text) => {
  const g = globalThis
  if (!g.__zhWordSegmenter) {
    g.__zhWordSegmenter = new Intl.Segmenter('zh', { granularity: 'word' })
  }
  return Array.from(g.__zhWordSegmenter.segment(text.toLowerCase()))
    .filter((s) => s.isWordLike)
    .map((s) => s.segment)
}

export default defineConfig({
  lang: 'zh-CN',
  title: 'Anpio Key',
  description:
    '跑在你自己机器上的守护进程,替 agent 保管 did:wba 的 Ed25519 私钥,并按 RFC 9421 签 HTTP 消息签名。',
  cleanUrls: true,
  head: [['meta', { name: 'theme-color', content: '#0f172a' }]],

  themeConfig: {
    nav: [
      { text: '开始', link: '/guide/what-is', activeMatch: '/guide/' },
      { text: '概念', link: '/concepts/envelope', activeMatch: '/concepts/' },
      { text: '参考', link: '/reference/commands', activeMatch: '/reference/' },
      { text: '深入', link: '/advanced/hardware-root', activeMatch: '/advanced/' },
      { text: '设计', link: '/design/', activeMatch: '/design/' },
    ],

    sidebar: [
      {
        text: '开始',
        items: [
          { text: '它是什么', link: '/guide/what-is' },
          { text: '安装', link: '/guide/install' },
          { text: '本机安全使用', link: '/guide/local-use' },
          { text: '五分钟跑通', link: '/guide/quickstart' },
        ],
      },
      {
        text: '概念',
        items: [
          { text: '信封与归档', link: '/concepts/envelope' },
          { text: '它能保护什么', link: '/concepts/trust-model' },
        ],
      },
      {
        text: '参考',
        items: [
          { text: '命令行', link: '/reference/commands' },
          { text: '默认行为', link: '/reference/defaults' },
          { text: '磁盘布局', link: '/reference/layout' },
        ],
      },
      {
        text: '深入',
        items: [
          { text: '硬件根', link: '/advanced/hardware-root' },
          { text: '接到 agent 上', link: '/advanced/agent' },
          { text: '出事的时候', link: '/advanced/recovery' },
          { text: '测试与向量', link: '/advanced/testing' },
        ],
      },
      {
        text: '设计',
        items: [{ text: '设计说明', link: '/design/' }],
      },
    ],

    outline: { level: [2, 3], label: '本页目录' },

    search: {
      provider: 'local',
      options: {
        miniSearch: {
          options: { tokenize },
          searchOptions: {
            fuzzy: 0.2,
            prefix: true,
            boost: { title: 4, text: 2, titles: 3 },
          },
        },
        locales: {
          root: {
            translations: {
              button: { buttonText: '搜索文档', buttonAriaLabel: '搜索文档' },
              modal: {
                noResultsText: '没有找到结果',
                resetButtonTitle: '清空',
                footer: {
                  selectText: '选择',
                  navigateText: '切换',
                  closeText: '关闭',
                },
              },
            },
          },
        },
      },
    },

    editLink: {
      pattern: 'https://github.com/eccstartup/anpio-key/edit/master/site/:path',
      text: '在 GitHub 上改这一页',
    },

    docFooter: { prev: '上一篇', next: '下一篇' },
    darkModeSwitchLabel: '主题',
    sidebarMenuLabel: '目录',
    returnToTopLabel: '回到顶部',
    lastUpdated: { text: '最后更新' },

    socialLinks: [{ icon: 'github', link: 'https://github.com/eccstartup/anpio-key' }],

    footer: {
      message: 'Apache-2.0 许可',
      copyright: 'Anpio Key',
    },
  },

  markdown: {
    // 文档里代码块多,行号会打断复制粘贴时的连续性,不开。
    lineNumbers: false,
  },
})
