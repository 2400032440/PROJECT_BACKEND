import 'dotenv/config'
import mysql from 'mysql2/promise'
import { readDb } from './db.js'

const MYSQL_HOST = process.env.MYSQL_HOST || '127.0.0.1'
const MYSQL_PORT = Number(process.env.MYSQL_PORT || 3306)
const MYSQL_USER = process.env.MYSQL_USER || 'root'
const MYSQL_PASSWORD = process.env.MYSQL_PASSWORD || ''
const MYSQL_DATABASE = process.env.MYSQL_DATABASE || 'citizen_connect'

function toJson(value) {
  return JSON.stringify(value ?? null)
}

async function createDatabase() {
  const adminConn = await mysql.createConnection({
    host: MYSQL_HOST,
    port: MYSQL_PORT,
    user: MYSQL_USER,
    password: MYSQL_PASSWORD,
    multipleStatements: true,
  })

  try {
    await adminConn.query(`CREATE DATABASE IF NOT EXISTS \`${MYSQL_DATABASE}\``)
  } finally {
    await adminConn.end()
  }
}

async function createTables(conn) {
  await conn.query(`
    CREATE TABLE IF NOT EXISTS users (
      id VARCHAR(64) PRIMARY KEY,
      name VARCHAR(160) NOT NULL,
      email VARCHAR(190) NOT NULL UNIQUE,
      password VARCHAR(255) NOT NULL,
      role VARCHAR(32) NOT NULL,
      avatar VARCHAR(255) NULL,
      joined VARCHAR(32) NULL,
      googleId VARCHAR(128) NULL,
      authProvider VARCHAR(32) NULL,
      raw_json JSON NOT NULL,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )
  `)

  await conn.query(`
    CREATE TABLE IF NOT EXISTS issues (
      id VARCHAR(64) PRIMARY KEY,
      title VARCHAR(255) NOT NULL,
      category VARCHAR(120) NULL,
      description TEXT NOT NULL,
      status VARCHAR(32) NOT NULL,
      priority VARCHAR(32) NULL,
      authorId VARCHAR(64) NULL,
      authorName VARCHAR(160) NULL,
      createdAt VARCHAR(32) NULL,
      votes INT DEFAULT 0,
      flagged TINYINT(1) DEFAULT 0,
      responses_json JSON NULL,
      raw_json JSON NOT NULL,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )
  `)

  await conn.query(`
    CREATE TABLE IF NOT EXISTS updates (
      id VARCHAR(64) PRIMARY KEY,
      title VARCHAR(255) NOT NULL,
      content TEXT NOT NULL,
      authorId VARCHAR(64) NULL,
      authorName VARCHAR(160) NULL,
      createdAt VARCHAR(32) NULL,
      category VARCHAR(120) NULL,
      likes INT DEFAULT 0,
      comments_json JSON NULL,
      raw_json JSON NOT NULL,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )
  `)

  await conn.query(`
    CREATE TABLE IF NOT EXISTS discussions (
      id VARCHAR(64) PRIMARY KEY,
      title VARCHAR(255) NOT NULL,
      body TEXT NOT NULL,
      authorId VARCHAR(64) NULL,
      authorName VARCHAR(160) NULL,
      createdAt VARCHAR(32) NULL,
      category VARCHAR(120) NULL,
      flagged TINYINT(1) DEFAULT 0,
      replies_json JSON NULL,
      raw_json JSON NOT NULL,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )
  `)
}

async function upsertUsers(conn, users) {
  const sql = `
    INSERT INTO users (id, name, email, password, role, avatar, joined, googleId, authProvider, raw_json)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON DUPLICATE KEY UPDATE
      name = VALUES(name),
      email = VALUES(email),
      password = VALUES(password),
      role = VALUES(role),
      avatar = VALUES(avatar),
      joined = VALUES(joined),
      googleId = VALUES(googleId),
      authProvider = VALUES(authProvider),
      raw_json = VALUES(raw_json)
  `

  for (const user of users) {
    await conn.execute(sql, [
      user.id,
      user.name,
      user.email,
      user.password || '',
      user.role || 'citizen',
      user.avatar || null,
      user.joined || null,
      user.googleId || null,
      user.authProvider || null,
      toJson(user),
    ])
  }
}

async function upsertIssues(conn, issues) {
  const sql = `
    INSERT INTO issues (id, title, category, description, status, priority, authorId, authorName, createdAt, votes, flagged, responses_json, raw_json)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON DUPLICATE KEY UPDATE
      title = VALUES(title),
      category = VALUES(category),
      description = VALUES(description),
      status = VALUES(status),
      priority = VALUES(priority),
      authorId = VALUES(authorId),
      authorName = VALUES(authorName),
      createdAt = VALUES(createdAt),
      votes = VALUES(votes),
      flagged = VALUES(flagged),
      responses_json = VALUES(responses_json),
      raw_json = VALUES(raw_json)
  `

  for (const issue of issues) {
    await conn.execute(sql, [
      issue.id,
      issue.title,
      issue.category || null,
      issue.description || '',
      issue.status || 'open',
      issue.priority || 'medium',
      issue.authorId || null,
      issue.authorName || null,
      issue.createdAt || null,
      Number(issue.votes || 0),
      issue.flagged ? 1 : 0,
      toJson(issue.responses || []),
      toJson(issue),
    ])
  }
}

async function upsertUpdates(conn, updates) {
  const sql = `
    INSERT INTO updates (id, title, content, authorId, authorName, createdAt, category, likes, comments_json, raw_json)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON DUPLICATE KEY UPDATE
      title = VALUES(title),
      content = VALUES(content),
      authorId = VALUES(authorId),
      authorName = VALUES(authorName),
      createdAt = VALUES(createdAt),
      category = VALUES(category),
      likes = VALUES(likes),
      comments_json = VALUES(comments_json),
      raw_json = VALUES(raw_json)
  `

  for (const update of updates) {
    await conn.execute(sql, [
      update.id,
      update.title,
      update.content || '',
      update.authorId || null,
      update.authorName || null,
      update.createdAt || null,
      update.category || null,
      Number(update.likes || 0),
      toJson(update.comments || []),
      toJson(update),
    ])
  }
}

async function upsertDiscussions(conn, discussions) {
  const sql = `
    INSERT INTO discussions (id, title, body, authorId, authorName, createdAt, category, flagged, replies_json, raw_json)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON DUPLICATE KEY UPDATE
      title = VALUES(title),
      body = VALUES(body),
      authorId = VALUES(authorId),
      authorName = VALUES(authorName),
      createdAt = VALUES(createdAt),
      category = VALUES(category),
      flagged = VALUES(flagged),
      replies_json = VALUES(replies_json),
      raw_json = VALUES(raw_json)
  `

  for (const discussion of discussions) {
    await conn.execute(sql, [
      discussion.id,
      discussion.title,
      discussion.body || '',
      discussion.authorId || null,
      discussion.authorName || null,
      discussion.createdAt || null,
      discussion.category || null,
      discussion.flagged ? 1 : 0,
      toJson(discussion.replies || []),
      toJson(discussion),
    ])
  }
}

async function printCounts(conn) {
  const tables = ['users', 'issues', 'updates', 'discussions']
  for (const table of tables) {
    const [rows] = await conn.query(`SELECT COUNT(*) AS total FROM ${table}`)
    console.log(`${table}: ${rows[0].total}`)
  }
}

async function main() {
  console.log('Connecting to MySQL...')
  await createDatabase()

  const conn = await mysql.createConnection({
    host: MYSQL_HOST,
    port: MYSQL_PORT,
    user: MYSQL_USER,
    password: MYSQL_PASSWORD,
    database: MYSQL_DATABASE,
    multipleStatements: true,
  })

  try {
    await createTables(conn)

    const db = readDb()
    await upsertUsers(conn, db.users || [])
    await upsertIssues(conn, db.issues || [])
    await upsertUpdates(conn, db.updates || [])
    await upsertDiscussions(conn, db.discussions || [])

    console.log(`MySQL database ready: ${MYSQL_DATABASE}`)
    await printCounts(conn)
    console.log('Done.')
  } finally {
    await conn.end()
  }
}

main().catch((error) => {
  console.error('MySQL setup failed:', error.message)
  process.exit(1)
})
