import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import helmet from 'helmet'
import jwt from 'jsonwebtoken'
import morgan from 'morgan'
import session from 'express-session'
import rateLimit from 'express-rate-limit'
import passport from 'passport'
import { Strategy as GoogleStrategy } from 'passport-google-oauth20'
import { randomBytes } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { readDb, writeDb, withoutPassword } from './db.js'

const app = express()
const PORT = globalThis.process?.env?.BACKEND_PORT || globalThis.process?.env?.PORT || 4000
const JWT_SECRET = globalThis.process?.env?.JWT_SECRET || 'citizen-connect-dev-secret'
const SESSION_SECRET = globalThis.process?.env?.SESSION_SECRET || 'citizen-connect-session-secret'
const FRONTEND_URL = globalThis.process?.env?.FRONTEND_URL || 'http://localhost:5173'
const CORS_ORIGINS = String(
  globalThis.process?.env?.CORS_ORIGINS ||
    globalThis.process?.env?.APP_CORS_ALLOWED_ORIGINS ||
    FRONTEND_URL,
)
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean)
const NODE_ENV = globalThis.process?.env?.NODE_ENV || 'development'
const IS_PRODUCTION = NODE_ENV === 'production'
const TRUST_PROXY = IS_PRODUCTION || globalThis.process?.env?.TRUST_PROXY === 'true'
const AUTH_RATE_LIMIT_WINDOW_MS = Number(globalThis.process?.env?.AUTH_RATE_LIMIT_WINDOW_MS || 15 * 60 * 1000)
const AUTH_RATE_LIMIT_MAX = Number(globalThis.process?.env?.AUTH_RATE_LIMIT_MAX || 20)
const ALLOW_DEV_GOOGLE_FALLBACK =
  !IS_PRODUCTION && globalThis.process?.env?.ALLOW_DEV_GOOGLE_FALLBACK !== 'false'
const GOOGLE_CLIENT_ID = globalThis.process?.env?.GOOGLE_CLIENT_ID || ''
const GOOGLE_CLIENT_SECRET = globalThis.process?.env?.GOOGLE_CLIENT_SECRET || ''
const GOOGLE_CALLBACK_URL = globalThis.process?.env?.GOOGLE_CALLBACK_URL || 'http://localhost:4000/api/auth/google/callback'
const GOOGLE_AUTH_ENABLED = Boolean(GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET)
const GOOGLE_DEV_FALLBACK_ENABLED = !GOOGLE_AUTH_ENABLED && ALLOW_DEV_GOOGLE_FALLBACK

const authLimiter = rateLimit({
  windowMs: AUTH_RATE_LIMIT_WINDOW_MS,
  max: AUTH_RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many authentication attempts. Please try again later.' },
})

if (TRUST_PROXY) {
  app.set('trust proxy', 1)
}

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || CORS_ORIGINS.includes(origin)) {
        callback(null, true)
        return
      }
      callback(new Error('CORS origin not allowed.'))
    },
    credentials: true,
  }),
)
app.use(
  helmet({
    crossOriginResourcePolicy: { policy: 'cross-origin' },
  }),
)
app.use(
  morgan('combined', {
    skip: (_req, res) => NODE_ENV === 'test' || res.statusCode < 400,
  }),
)
app.use(express.json())
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: IS_PRODUCTION ? 'none' : 'lax',
      secure: IS_PRODUCTION,
    },
  }),
)
app.use(passport.initialize())
app.use(passport.session())

passport.serializeUser((user, done) => {
  done(null, user.id)
})

passport.deserializeUser((id, done) => {
  const db = readDb()
  const user = db.users.find((item) => item.id === id)
  done(null, user ? withoutPassword(user) : false)
})

function upsertGoogleUser(profile, preferredRole = 'citizen') {
  const email = String(profile?.emails?.[0]?.value || '').trim().toLowerCase()
  if (!email) {
    throw new Error('Google account does not expose a valid email address.')
  }

  const name = String(profile?.displayName || email.split('@')[0] || 'Google User').trim()
  const avatar = String(profile?.photos?.[0]?.value || '')
  const googleId = String(profile?.id || '')
  const db = readDb()

  const idx = db.users.findIndex(
    (user) => user.googleId === googleId || user.email.toLowerCase() === email,
  )

  if (idx >= 0) {
    const existing = db.users[idx]
    db.users[idx] = {
      ...existing,
      name: existing.name || name,
      email,
      googleId,
      avatar: existing.avatar || avatar,
      authProvider: 'google',
    }
    writeDb(db)
    return withoutPassword(db.users[idx])
  }

  const newUser = {
    id: 'u' + Date.now(),
    name,
    email,
    password: '',
    role: preferredRole,
    avatar,
    joined: new Date().toISOString().slice(0, 10),
    googleId,
    authProvider: 'google',
  }

  db.users.push(newUser)
  writeDb(db)
  return withoutPassword(newUser)
}

if (GOOGLE_AUTH_ENABLED) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: GOOGLE_CLIENT_ID,
        clientSecret: GOOGLE_CLIENT_SECRET,
        callbackURL: GOOGLE_CALLBACK_URL,
        passReqToCallback: true,
      },
      (req, _accessToken, _refreshToken, profile, done) => {
        try {
          const allowedRoles = new Set(['citizen', 'politician', 'moderator'])
          const sessionRole = String(req?.session?.oauthRole || 'citizen').toLowerCase()
          const preferredRole = allowedRoles.has(sessionRole) ? sessionRole : 'citizen'
          const user = upsertGoogleUser(profile, preferredRole)
          if (req?.session) {
            delete req.session.oauthRole
          }
          done(null, user)
        } catch (error) {
          done(error)
        }
      },
    ),
  )
}

function auth(req, res, next) {
  const authHeader = req.headers.authorization || ''
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : ''
  if (!token) {
    req.user = { id: 'guest', role: 'guest', name: 'Guest User', email: '' }
    return next()
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET)
    req.user = decoded
    next()
  } catch {
    req.user = { id: 'guest', role: 'guest', name: 'Guest User', email: '' }
    return next()
  }
}

function issueToken(user) {
  return jwt.sign({ id: user.id, email: user.email, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '7d' })
}

function requireAuth(req, res, next) {
  if (!req.user || req.user.id === 'guest') {
    return res.status(401).json({ error: 'Authentication required.' })
  }
  return next()
}

function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ error: 'You do not have permission to perform this action.' })
    }
    return next()
  }
}

function todayIsoDate() {
  return new Date().toISOString().slice(0, 10)
}

function makeId(prefix) {
  return `${prefix}${Date.now()}${Math.floor(Math.random() * 1000)}`
}

function cleanText(value, maxLength = 2000) {
  return String(value || '').replace(/\s+/g, ' ').trim().slice(0, maxLength)
}

function pickAllowed(value, allowedValues, fallback) {
  const cleanValue = String(value || '').trim()
  return allowedValues.includes(cleanValue) ? cleanValue : fallback
}

function ensureMinLength(value, minLength, message) {
  if (value.length < minLength) {
    const error = new Error(message)
    error.statusCode = 400
    throw error
  }
}

function buildIssuePayload(body, user) {
  const title = cleanText(body?.title, 120)
  const description = cleanText(body?.description, 3000)
  const category = cleanText(body?.category, 64) || 'Community'
  const status = pickAllowed(body?.status, ['open', 'in-progress', 'resolved'], 'open')
  const priority = pickAllowed(body?.priority, ['low', 'medium', 'high'], 'medium')

  ensureMinLength(title, 5, 'Issue title must be at least 5 characters.')
  ensureMinLength(description, 10, 'Issue description must be at least 10 characters.')

  return {
    id: makeId('i'),
    title,
    category,
    description,
    status,
    priority,
    authorId: user.id,
    authorName: user.name,
    createdAt: todayIsoDate(),
    responses: [],
    votes: 0,
    flagged: false,
  }
}

function buildUpdatePayload(body, user) {
  const title = cleanText(body?.title, 140)
  const content = cleanText(body?.content, 4000)
  const category = cleanText(body?.category, 64) || 'Community'

  ensureMinLength(title, 5, 'Update title must be at least 5 characters.')
  ensureMinLength(content, 10, 'Update content must be at least 10 characters.')

  return {
    id: makeId('up'),
    title,
    content,
    authorId: user.id,
    authorName: user.name,
    createdAt: todayIsoDate(),
    category,
    likes: 0,
    comments: [],
  }
}

function buildDiscussionPayload(body, user) {
  const title = cleanText(body?.title, 140)
  const discussionBody = cleanText(body?.body, 4000)
  const category = cleanText(body?.category, 64) || 'Community'

  ensureMinLength(title, 5, 'Discussion title must be at least 5 characters.')
  ensureMinLength(discussionBody, 10, 'Discussion body must be at least 10 characters.')

  return {
    id: makeId('d'),
    title,
    body: discussionBody,
    authorId: user.id,
    authorName: user.name,
    createdAt: todayIsoDate(),
    category,
    replies: [],
    flagged: false,
  }
}

app.get('/', (_req, res) => {
  res.json({ ok: true, service: 'citizen-connect-backend', health: '/api/health' })
})

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, date: new Date().toISOString() })
})

app.get('/api/auth/google/config', (_req, res) => {
  res.json({ enabled: GOOGLE_AUTH_ENABLED, devFallback: GOOGLE_DEV_FALLBACK_ENABLED })
})

if (GOOGLE_AUTH_ENABLED) {
  app.get('/api/auth/google', authLimiter, (req, res, next) => {
    const allowedRoles = new Set(['citizen', 'politician', 'moderator'])
    const role = String(req.query.role || 'citizen').toLowerCase()
    const state = randomBytes(24).toString('hex')

    req.session.oauthRole = allowedRoles.has(role) ? role : 'citizen'
    req.session.oauthState = state

    passport.authenticate('google', {
      scope: ['profile', 'email'],
      prompt: 'select_account',
      state,
    })(req, res, next)
  })

  app.get(
    '/api/auth/google/callback',
    (req, res, next) => {
      const expectedState = String(req.session.oauthState || '')
      const receivedState = String(req.query.state || '')

      if (!expectedState || !receivedState || expectedState !== receivedState) {
        req.session.oauthState = undefined
        req.session.oauthRole = undefined
        return res.redirect(`${FRONTEND_URL}/?authError=invalid_oauth_state`)
      }

      req.session.oauthState = undefined
      return next()
    },
    passport.authenticate('google', {
      failureRedirect: `${FRONTEND_URL}/?authError=google_login_failed`,
      session: false,
    }),
    (req, res) => {
      const token = issueToken(req.user)
      const redirectUrl = new URL(FRONTEND_URL)
      redirectUrl.searchParams.set('token', token)
      return res.redirect(redirectUrl.toString())
    },
  )
} else {
  app.get('/api/auth/google', authLimiter, (req, res) => {
    if (!GOOGLE_DEV_FALLBACK_ENABLED) {
      return res.status(503).json({ error: 'Google authentication is not configured on the server.' })
    }

    const allowedRoles = new Set(['citizen', 'politician', 'moderator'])
    const role = String(req.query.role || 'citizen').toLowerCase()
    const selectedRole = allowedRoles.has(role) ? role : 'citizen'
    const fakeEmail = `dev-google-${selectedRole}@local.dev`

    const user = upsertGoogleUser(
      {
        id: `dev-google-${selectedRole}`,
        displayName: `Dev ${selectedRole[0].toUpperCase()}${selectedRole.slice(1)} User`,
        emails: [{ value: fakeEmail }],
        photos: [{ value: '' }],
      },
      selectedRole,
    )

    const token = issueToken(user)
    const redirectUrl = new URL(FRONTEND_URL)
    redirectUrl.searchParams.set('token', token)
    redirectUrl.searchParams.set('authMode', 'dev_google')
    return res.redirect(redirectUrl.toString())
  })

  app.get('/api/auth/google/callback', (_req, res) => {
    return res.redirect(`${FRONTEND_URL}/?authError=google_not_configured`)
  })
}

app.post('/api/auth/login', authLimiter, (req, res) => {
  const { email, password } = req.body || {}
  const cleanEmail = String(email || '').trim().toLowerCase()
  const cleanPassword = String(password || '').trim()
  const db = readDb()
  const found = db.users.find((u) => {
    const userEmail = String(u.email || '').trim().toLowerCase()
    const userPassword = String(u.password || '').trim()
    return userEmail === cleanEmail && userPassword === cleanPassword
  })
  if (!found) return res.status(401).json({ error: 'Invalid email or password.' })

  const user = withoutPassword(found)
  const token = issueToken(user)
  res.json({ user, token })
})

app.post('/api/auth/signup', authLimiter, (req, res) => {
  const { name, email, password, role } = req.body || {}
  const cleanEmail = String(email || '').trim().toLowerCase()
  const cleanName = String(name || '').trim()
  const cleanPassword = String(password || '').trim()

  if (cleanName.length < 2) return res.status(400).json({ error: 'Please enter your full name.' })
  if (cleanPassword.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' })
  if (!cleanEmail) return res.status(400).json({ error: 'Email is required.' })

  const db = readDb()
  if (db.users.some(u => u.email.toLowerCase() === cleanEmail)) {
    return res.status(409).json({ error: 'Email already registered.' })
  }

  const newUser = {
    id: 'u' + Date.now(),
    name: cleanName,
    email: cleanEmail,
    password: cleanPassword,
    role: role || 'citizen',
    avatar: cleanName.split(' ').map(w => w[0]).join('').slice(0, 2).toUpperCase(),
    joined: new Date().toISOString().slice(0, 10),
  }

  db.users.push(newUser)
  writeDb(db)

  const user = withoutPassword(newUser)
  const token = issueToken(user)
  res.status(201).json({ user, token })
})

app.get('/api/auth/me', auth, (req, res) => {
  const db = readDb()
  const current = db.users.find(u => u.id === req.user.id)
  if (!current) return res.status(404).json({ error: 'User not found.' })
  res.json({ user: withoutPassword(current) })
})

app.get('/api/bootstrap', auth, (_req, res) => {
  const db = readDb()
  res.json({
    users: db.users.map(withoutPassword),
    issues: db.issues,
    updates: db.updates,
    discussions: db.discussions,
  })
})

app.get('/api/users', auth, (_req, res) => {
  const db = readDb()
  res.json({ users: db.users.map(withoutPassword) })
})

app.patch('/api/users/:id', auth, requireAuth, requireRole('admin'), (req, res) => {
  const { id } = req.params
  const { role } = req.body || {}

  const db = readDb()
  const idx = db.users.findIndex(u => u.id === id)
  if (idx < 0) return res.status(404).json({ error: 'User not found.' })

  db.users[idx] = { ...db.users[idx], role: role || db.users[idx].role }
  writeDb(db)
  res.json({ user: withoutPassword(db.users[idx]) })
})

app.delete('/api/users/:id', auth, requireAuth, (req, res) => {
  const { id } = req.params
  const db = readDb()
  if (!db.users.some(u => u.id === id)) return res.status(404).json({ error: 'User not found.' })

  db.users = db.users.filter(u => u.id !== id)
  writeDb(db)
  res.status(204).end()
})

app.get('/api/issues', auth, (_req, res) => {
  const db = readDb()
  res.json({ issues: db.issues })
})

app.post('/api/issues', auth, requireAuth, (req, res) => {
  const db = readDb()
  const issue = buildIssuePayload(req.body || {}, req.user)
  db.issues.unshift(issue)
  writeDb(db)
  res.status(201).json({ issue })
})

app.patch('/api/issues/:id', auth, requireAuth, (req, res) => {
  const { id } = req.params
  const db = readDb()
  const idx = db.issues.findIndex(i => i.id === id)
  if (idx < 0) return res.status(404).json({ error: 'Issue not found.' })

  const patch = req.body || {}
  const nextIssue = { ...db.issues[idx] }
  if (patch.title !== undefined) {
    const title = cleanText(patch.title, 120)
    ensureMinLength(title, 5, 'Issue title must be at least 5 characters.')
    nextIssue.title = title
  }
  if (patch.description !== undefined) {
    const description = cleanText(patch.description, 3000)
    ensureMinLength(description, 10, 'Issue description must be at least 10 characters.')
    nextIssue.description = description
  }
  if (patch.status !== undefined) {
    nextIssue.status = pickAllowed(patch.status, ['open', 'in-progress', 'resolved'], nextIssue.status)
  }
  if (patch.priority !== undefined) {
    nextIssue.priority = pickAllowed(patch.priority, ['low', 'medium', 'high'], nextIssue.priority)
  }
  if (patch.category !== undefined) {
    nextIssue.category = cleanText(patch.category, 64) || nextIssue.category
  }

  db.issues[idx] = nextIssue
  writeDb(db)
  res.json({ issue: db.issues[idx] })
})

app.delete('/api/issues/:id', auth, requireAuth, (req, res) => {
  const { id } = req.params
  const db = readDb()
  db.issues = db.issues.filter(i => i.id !== id)
  writeDb(db)
  res.status(204).end()
})

app.post('/api/issues/:id/responses', auth, requireAuth, (req, res) => {
  const { id } = req.params
  const responseText = cleanText(req.body?.response?.text || req.body?.response || req.body?.text, 1200)
  ensureMinLength(responseText, 2, 'Response text must be at least 2 characters.')
  const db = readDb()
  const idx = db.issues.findIndex(i => i.id === id)
  if (idx < 0) return res.status(404).json({ error: 'Issue not found.' })

  const response = {
    id: makeId('ir'),
    authorId: req.user.id,
    authorName: req.user.name,
    text: responseText,
    createdAt: todayIsoDate(),
  }

  db.issues[idx] = {
    ...db.issues[idx],
    responses: [...(db.issues[idx].responses || []), response],
  }

  writeDb(db)
  res.json({ issue: db.issues[idx] })
})

app.post('/api/issues/:id/vote', auth, requireAuth, (req, res) => {
  const { id } = req.params
  const db = readDb()
  const idx = db.issues.findIndex(i => i.id === id)
  if (idx < 0) return res.status(404).json({ error: 'Issue not found.' })

  db.issues[idx] = { ...db.issues[idx], votes: (db.issues[idx].votes || 0) + 1 }
  writeDb(db)
  res.json({ issue: db.issues[idx] })
})

app.get('/api/updates', auth, (_req, res) => {
  const db = readDb()
  res.json({ updates: db.updates })
})

app.post('/api/updates', auth, requireAuth, requireRole('politician', 'admin'), (req, res) => {
  const db = readDb()
  const update = buildUpdatePayload(req.body || {}, req.user)
  db.updates.unshift(update)
  writeDb(db)
  res.status(201).json({ update })
})

app.post('/api/updates/:id/like', auth, requireAuth, (req, res) => {
  const { id } = req.params
  const db = readDb()
  const idx = db.updates.findIndex(u => u.id === id)
  if (idx < 0) return res.status(404).json({ error: 'Update not found.' })

  db.updates[idx] = { ...db.updates[idx], likes: (db.updates[idx].likes || 0) + 1 }
  writeDb(db)
  res.json({ update: db.updates[idx] })
})

app.post('/api/updates/:id/comments', auth, requireAuth, (req, res) => {
  const { id } = req.params
  const text = cleanText(req.body?.comment?.text || req.body?.comment || req.body?.text, 1200)
  ensureMinLength(text, 2, 'Comment must be at least 2 characters.')
  const db = readDb()
  const idx = db.updates.findIndex(u => u.id === id)
  if (idx < 0) return res.status(404).json({ error: 'Update not found.' })

  const comment = {
    id: makeId('uc'),
    authorId: req.user.id,
    authorName: req.user.name,
    text,
    createdAt: todayIsoDate(),
  }

  db.updates[idx] = {
    ...db.updates[idx],
    comments: [...(db.updates[idx].comments || []), comment],
  }

  writeDb(db)
  res.json({ update: db.updates[idx] })
})

app.get('/api/discussions', auth, (_req, res) => {
  const db = readDb()
  res.json({ discussions: db.discussions })
})

app.post('/api/discussions', auth, requireAuth, requireRole('politician', 'moderator', 'admin'), (req, res) => {
  const db = readDb()
  const discussion = buildDiscussionPayload(req.body || {}, req.user)
  db.discussions.unshift(discussion)
  writeDb(db)
  res.status(201).json({ discussion })
})

app.post('/api/discussions/:id/replies', auth, requireAuth, (req, res) => {
  const { id } = req.params
  const text = cleanText(req.body?.reply?.text || req.body?.reply || req.body?.text, 1200)
  ensureMinLength(text, 2, 'Reply must be at least 2 characters.')
  const db = readDb()
  const idx = db.discussions.findIndex(d => d.id === id)
  if (idx < 0) return res.status(404).json({ error: 'Discussion not found.' })

  const reply = {
    id: makeId('dr'),
    authorId: req.user.id,
    authorName: req.user.name,
    text,
    createdAt: todayIsoDate(),
  }

  db.discussions[idx] = {
    ...db.discussions[idx],
    replies: [...(db.discussions[idx].replies || []), reply],
  }

  writeDb(db)
  res.json({ discussion: db.discussions[idx] })
})

app.post('/api/moderation/flag', auth, requireAuth, requireRole('moderator', 'admin'), (req, res) => {
  const { type, id, flagged } = req.body || {}
  const db = readDb()

  if (type === 'issue') {
    const idx = db.issues.findIndex(i => i.id === id)
    if (idx < 0) return res.status(404).json({ error: 'Issue not found.' })
    db.issues[idx] = { ...db.issues[idx], flagged: Boolean(flagged) }
    writeDb(db)
    return res.json({ item: db.issues[idx] })
  }

  if (type === 'discussion') {
    const idx = db.discussions.findIndex(d => d.id === id)
    if (idx < 0) return res.status(404).json({ error: 'Discussion not found.' })
    db.discussions[idx] = { ...db.discussions[idx], flagged: Boolean(flagged) }
    writeDb(db)
    return res.json({ item: db.discussions[idx] })
  }

  return res.status(400).json({ error: 'Invalid moderation type.' })
})

app.use((req, res) => {
  res.status(404).json({ error: `Route not found: ${req.method} ${req.originalUrl}` })
})

app.use((err, _req, res, _next) => {
  const statusCode = Number(err?.statusCode || err?.status || 500)
  if (statusCode >= 500) {
    console.error(err)
  }

  if (err?.message === 'CORS origin not allowed.') {
    return res.status(403).json({ error: 'Request blocked by CORS policy.' })
  }

  return res.status(statusCode).json({ error: err?.message || 'Internal server error.' })
})

export default app

if (globalThis.process?.argv?.[1] === fileURLToPath(import.meta.url)) {
  app.listen(PORT, () => {
    console.log(`Citizen Connect backend running on http://localhost:${PORT}`)
  })
}
