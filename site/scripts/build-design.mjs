/*
 * 把仓库里的 deploy/LOCAL-USE.md 同步成站点页面。
 *
 * 操作指南只维护一份:仓库里那份给直接读 GitHub 的人,这里生成一份给站点读者。
 * 相对链接必须显式登记;没登记就让构建失败,不要发布一个 404 的页面。
 */

import { execFileSync } from 'node:child_process'
import { readFileSync, writeFileSync } from 'node:fs'

// 源码和别的仓库文档在站上没有对应页面,所以指向 GitHub。
// 分支名写死:仓库默认分支是 master,构建机上通常没有本地分支可问。
const REPO = (() => {
  try {
    const url = execFileSync('git', ['remote', 'get-url', 'origin'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim()
    const m = url.match(/github\.com[:/](.+?)(?:\.git)?$/)
    if (m) return `https://github.com/${m[1]}`
  } catch {
    // 没有 git(或没有 origin)就用兜底的那个。
  }
  return 'https://github.com/eccstartup/anpio-key'
})()

const BRANCH = 'master'
const blob = (path) => `${REPO}/blob/${BRANCH}/${path}`

const frontmatter = [
  '---',
  'editLink: false', // 这一页是生成的,仓库里没有对应的可编辑文件
  'lastUpdated: false', // 同上:它没有 git 历史
  '---',
  '',
].join('\n')

let localUse = readFileSync(new URL('../../deploy/LOCAL-USE.md', import.meta.url), 'utf8')
const operatorLinks = {
  'macos/README.md': blob('deploy/macos/README.md'),
  'linux/README.md': blob('deploy/linux/README.md'),
  'macos/SE-SESSION.md': '/advanced/hardware-root',
  '../README.md': '/guide/quickstart',
}
localUse = localUse.replace(/\]\(([^)]+)\)/g, (whole, link) => {
  if (operatorLinks[link]) return `](${operatorLinks[link]})`
  if (/^https?:/.test(link)) return whole
  throw new Error(`Unmapped local-use link: ${link}`)
})
writeFileSync(new URL('../guide/local-use.md', import.meta.url), frontmatter + localUse)
console.log('guide/local-use.md ← deploy/LOCAL-USE.md')
