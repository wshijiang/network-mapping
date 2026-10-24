// A manual choice shares the console's host-only language preference.
;(() => {
  const cookieName = 'network_mapping_locale'
  const supported = value => value === 'en' || value === 'zh-CN'
  function preference() {
    // Menu URLs carry intent even when all browser storage is unavailable.
    const explicit = new URL(location.href).searchParams.get('docs-lang')
    if (supported(explicit)) return explicit
    try {
      for (const part of document.cookie.split(';')) {
        const [key, ...rest] = part.trim().split('=')
        if (key === cookieName) {
          const value = decodeURIComponent(rest.join('='))
          if (supported(value)) return value
        }
      }
    } catch { /* Browser restrictions do not prevent reading documentation. */ }
    return /^zh(?:-|$)/i.test(navigator.languages?.[0] || navigator.language || '') ? 'zh-CN' : 'en'
  }
  // Prepare actual hrefs so modified clicks, new tabs and copied links also work.
  for (const link of document.querySelectorAll('a[hreflang]')) {
    if (!supported(link.hreflang)) continue
    const target = new URL(link.href, location.href)
    target.searchParams.set('docs-lang', link.hreflang)
    link.href = target.href
  }
  document.addEventListener('click', event => {
    const link = event.target.closest('a[hreflang]')
    if (!link || !['en', 'zh-CN'].includes(link.hreflang)) return
    try {
      document.cookie = `${cookieName}=${link.hreflang}; Path=/; Max-Age=31536000; SameSite=Lax${location.protocol === 'https:' ? '; Secure' : ''}`
    } catch { /* Normal links still work when cookies are disabled. */ }
  })
  if (document.querySelector('meta[name="network-mapping-docs-home"]')?.content !== 'true') return
  const current = /^zh/i.test(document.documentElement.lang) ? 'zh-CN' : 'en'
  const chosen = preference()
  const alternate = document.querySelector(`link[rel="alternate"][hreflang="${chosen}"]`)
  if (alternate && chosen !== current) location.replace(alternate.href)
})()
