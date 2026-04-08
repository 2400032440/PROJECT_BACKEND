import express from 'express'
import cors from 'cors'
import jwt from 'jsonwebtoken'
import { readDb, writeDb, withoutPassword } from './db.js'

const app = express()
const PORT = globalThis.process?.env?.PORT || 4000
const JWT_SECRET = globalThis.process?.env?.JWT_SECRET || 'citizen-connect-dev-secret'

app.use(cors())
app.use(express.json())

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

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, date: new Date().toISOString() })
})

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body || {}
  const cleanEmail = String(email || '').trim().toLowerCase()
  const db = readDb()
  const found = db.users.find(u => u.email.toLowerCase() === cleanEmail && u.password === password)
  if (!found) return res.status(401).json({ error: 'Invalid email or password.' })

  const user = withoutPassword(found)
  const token = issueToken(user)
  res.json({ user, token })
})

app.post('/api/auth/signup', (req, res) => {
  const { name, email, password, role } = req.body || {}
  const cleanEmail = String(email || '').trim().toLowerCase()
  const cleanName = String(name || '').trim()

  if (cleanName.length < 2) return res.status(400).json({ error: 'Please enter your full name.' })
  if (String(password || '').length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' })
  if (!cleanEmail) return res.status(400).json({ error: 'Email is required.' })

  const db = readDb()
  if (db.users.some(u => u.email.toLowerCase() === cleanEmail)) {
    return res.status(409).json({ error: 'Email already registered.' })
  }

  const newUser = {
    id: 'u' + Date.now(),
    name: cleanName,
    email: cleanEmail,
    password,
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

app.patch('/api/users/:id', auth, (req, res) => {
  const { id } = req.params
  const { role } = req.body || {}

  const db = readDb()
  const idx = db.users.findIndex(u => u.id === id)
  if (idx < 0) return res.status(404).json({ error: 'User not found.' })

  db.users[idx] = { ...db.users[idx], role: role || db.users[idx].role }
  writeDb(db)
  res.json({ user: withoutPassword(db.users[idx]) })
})

app.delete('/api/users/:id', auth, (req, res) => {
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

app.post('/api/issues', auth, (req, res) => {
  const db = readDb()
  const issue = req.body || {}
  db.issues.unshift(issue)
  writeDb(db)
  res.status(201).json({ issue })
})

app.patch('/api/issues/:id', auth, (req, res) => {
  const { id } = req.params
  const db = readDb()
  const idx = db.issues.findIndex(i => i.id === id)
  if (idx < 0) return res.status(404).json({ error: 'Issue not found.' })

  db.issues[idx] = { ...db.issues[idx], ...(req.body || {}) }
  writeDb(db)
  res.json({ issue: db.issues[idx] })
})

app.delete('/api/issues/:id', auth, (req, res) => {
  const { id } = req.params
  const db = readDb()
  db.issues = db.issues.filter(i => i.id !== id)
  writeDb(db)
  res.status(204).end()
})

app.post('/api/issues/:id/responses', auth, (req, res) => {
  const { id } = req.params
  const { response } = req.body || {}
  const db = readDb()
  const idx = db.issues.findIndex(i => i.id === id)
  if (idx < 0) return res.status(404).json({ error: 'Issue not found.' })

  db.issues[idx] = {
    ...db.issues[idx],
    responses: [...(db.issues[idx].responses || []), response],
  }

  writeDb(db)
  res.json({ issue: db.issues[idx] })
})

app.post('/api/issues/:id/vote', auth, (req, res) => {
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

app.post('/api/updates', auth, (req, res) => {
  const db = readDb()
  const update = req.body || {}
  db.updates.unshift(update)
  writeDb(db)
  res.status(201).json({ update })
})

app.post('/api/updates/:id/like', auth, (req, res) => {
  const { id } = req.params
  const db = readDb()
  const idx = db.updates.findIndex(u => u.id === id)
  if (idx < 0) return res.status(404).json({ error: 'Update not found.' })

  db.updates[idx] = { ...db.updates[idx], likes: (db.updates[idx].likes || 0) + 1 }
  writeDb(db)
  res.json({ update: db.updates[idx] })
})

app.post('/api/updates/:id/comments', auth, (req, res) => {
  const { id } = req.params
  const { comment } = req.body || {}
  const db = readDb()
  const idx = db.updates.findIndex(u => u.id === id)
  if (idx < 0) return res.status(404).json({ error: 'Update not found.' })

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

app.post('/api/discussions', auth, (req, res) => {
  const db = readDb()
  const discussion = req.body || {}
  db.discussions.unshift(discussion)
  writeDb(db)
  res.status(201).json({ discussion })
})

app.post('/api/discussions/:id/replies', auth, (req, res) => {
  const { id } = req.params
  const { reply } = req.body || {}
  const db = readDb()
  const idx = db.discussions.findIndex(d => d.id === id)
  if (idx < 0) return res.status(404).json({ error: 'Discussion not found.' })

  db.discussions[idx] = {
    ...db.discussions[idx],
    replies: [...(db.discussions[idx].replies || []), reply],
  }

  writeDb(db)
  res.json({ discussion: db.discussions[idx] })
})

app.post('/api/moderation/flag', auth, (req, res) => {
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

app.listen(PORT, () => {
  console.log(`Citizen Connect backend running on http://localhost:${PORT}`)
})
