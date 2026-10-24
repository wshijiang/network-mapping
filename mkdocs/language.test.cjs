const assert = require('node:assert/strict')
const { readFileSync } = require('node:fs')
const { join } = require('node:path')
const test = require('node:test')
const vm = require('node:vm')

function visit({ url, browser = 'zh-CN', cookie = '', blocked = false, home = true }) {
  const location = new URL(url)
  const redirects = []
  location.replace = href => redirects.push(href)
  const language = location.pathname.includes('/en/') ? 'en' : 'zh-CN'
  const base = 'https://example.test/project/'
  const links = ['zh-CN', 'en'].map(hreflang => ({ hreflang, href: base + (hreflang === 'en' ? 'en/' : '') + '?preview=1#intro' }))
  const handlers = {}
  const document = {
    documentElement: { lang: language },
    querySelectorAll: () => links,
    querySelector: selector => selector.includes('meta[') ? { content: String(home) } : links.find(link => selector.includes(`"${link.hreflang}"`)),
    addEventListener: (name, handler) => { handlers[name] = handler },
  }
  Object.defineProperty(document, 'cookie', {
    get: () => cookie,
    set: value => { if (blocked === 'throw') throw new Error('cookies disabled'); if (!blocked) cookie = value.split(';')[0] },
  })
  vm.runInNewContext(readFileSync(join(__dirname, '../docs/assets/language.js'), 'utf8'), {
    document, navigator: { languages: [browser] }, location, URL,
  })
  return { redirects, links, cookie: () => cookie, click: link => handlers.click({ target: { closest: () => link } }) }
}

test('first visits follow browser/cookie preferences and never automatically persist them', () => {
  const english = visit({ url: 'https://example.test/project/', browser: 'de-DE' })
  assert.equal(english.redirects.length, 1)
  assert.match(english.redirects[0], /\/project\/en\//)
  assert.equal(english.cookie(), '')
  assert.equal(visit({ url: 'https://example.test/project/', cookie: 'network_mapping_locale=zh-CN', browser: 'en' }).redirects.length, 0)
  assert.equal(visit({ url: 'https://example.test/project/TOPIC/', browser: 'en', home: false }).redirects.length, 0)
})

test('manual links reach and reload the selected home with silently rejected or throwing cookies', () => {
  for (const blocked of [true, 'throw']) for (const browser of ['zh-TW', 'en-GB']) {
    const chosen = browser.startsWith('zh') ? 'en' : 'zh-CN'
    const topic = visit({ url: 'https://example.test/project/TOPIC/', browser, blocked, home: false })
    const link = topic.links.find(link => link.hreflang === chosen)
    // Prepared hrefs also preserve intent for middle clicks, new tabs and copy-link.
    const target = new URL(link.href)
    assert.equal(target.searchParams.get('docs-lang'), chosen)
    assert.equal(target.searchParams.get('preview'), '1')
    assert.equal(target.hash, '#intro')
    topic.click(link)
    assert.equal(topic.cookie(), '')
    for (let reload = 0; reload < 2; reload++) {
      assert.equal(visit({ url: link.href, browser, blocked }).redirects.length, 0)
    }
  }
})

test('only supported explicit URL languages override cookies and browser detection', () => {
  const base = 'https://example.test/project/en/?docs-lang='
  assert.equal(visit({ url: base + 'en', cookie: 'network_mapping_locale=zh-CN' }).redirects.length, 0)
  for (const value of ['fr', '%3Cscript%3E', 'https%3A%2F%2Fevil.test', '']) {
    const page = visit({ url: base + value })
    assert.equal(page.redirects.length, 1)
    assert.equal(new URL(page.redirects[0]).origin, 'https://example.test')
  }
  const page = visit({ url: base + 'en', browser: 'zh-CN' })
  page.click(page.links.find(link => link.hreflang === 'zh-CN'))
  assert.equal(page.cookie(), 'network_mapping_locale=zh-CN')
})
