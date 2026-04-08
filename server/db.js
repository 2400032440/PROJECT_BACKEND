import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { createSeedDb } from './seed.js'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const DB_FILE = path.join(__dirname, 'data', 'db.json')

function ensureDbFile() {
  if (!fs.existsSync(DB_FILE)) {
    fs.mkdirSync(path.dirname(DB_FILE), { recursive: true })
    fs.writeFileSync(DB_FILE, JSON.stringify(createSeedDb(), null, 2), 'utf-8')
  }
}

export function readDb() {
  ensureDbFile()
  const text = fs.readFileSync(DB_FILE, 'utf-8')
  const parsed = JSON.parse(text)
  return {
    users: parsed.users || [],
    issues: parsed.issues || [],
    updates: parsed.updates || [],
    discussions: parsed.discussions || [],
  }
}

export function writeDb(nextDb) {
  ensureDbFile()
  fs.writeFileSync(DB_FILE, JSON.stringify(nextDb, null, 2), 'utf-8')
}

export function withoutPassword(user) {
  if (!user) return null
  const { password: _PASSWORD, ...safeUser } = user
  return safeUser
}
