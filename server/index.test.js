import test from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import app from './index.js'

test('GET /api/health responds with ok true', async () => {
  const response = await request(app).get('/api/health')
  assert.equal(response.status, 200)
  assert.equal(response.body.ok, true)
  assert.ok(typeof response.body.date === 'string')
})

test('GET /api/bootstrap returns expected collections', async () => {
  const response = await request(app).get('/api/bootstrap')
  assert.equal(response.status, 200)
  assert.ok(Array.isArray(response.body.users))
  assert.ok(Array.isArray(response.body.issues))
  assert.ok(Array.isArray(response.body.updates))
  assert.ok(Array.isArray(response.body.discussions))
})

test('POST /api/issues persists normalized issue payload', async () => {
  const login = await request(app)
    .post('/api/auth/login')
    .send({ email: 'citizen@demo.com', password: 'demo123' })

  assert.equal(login.status, 200)
  const token = login.body.token

  const create = await request(app)
    .post('/api/issues')
    .set('Authorization', `Bearer ${token}`)
    .send({
      title: '  Test issue for persistence  ',
      description: '  This issue confirms realistic server-side shaping and persistence.  ',
      category: 'Infrastructure',
      priority: 'high',
    })

  assert.equal(create.status, 201)
  assert.ok(create.body.issue.id.startsWith('i'))
  assert.equal(create.body.issue.votes, 0)
  assert.equal(create.body.issue.status, 'open')
  assert.equal(create.body.issue.title, 'Test issue for persistence')
  assert.equal(create.body.issue.authorName, 'Alice Chen')

  const list = await request(app)
    .get('/api/issues')
    .set('Authorization', `Bearer ${token}`)

  assert.equal(list.status, 200)
  assert.ok(list.body.issues.some((item) => item.id === create.body.issue.id))
})

test('role permissions are enforced for updates and moderation', async () => {
  const citizenLogin = await request(app)
    .post('/api/auth/login')
    .send({ email: 'citizen@demo.com', password: 'demo123' })
  const politicianLogin = await request(app)
    .post('/api/auth/login')
    .send({ email: 'politician@demo.com', password: 'demo123' })

  const citizenToken = citizenLogin.body.token
  const politicianToken = politicianLogin.body.token

  const blockedUpdate = await request(app)
    .post('/api/updates')
    .set('Authorization', `Bearer ${citizenToken}`)
    .send({
      title: 'Blocked citizen update',
      content: 'Citizens should not publish updates directly.',
      category: 'Community',
    })
  assert.equal(blockedUpdate.status, 403)

  const allowedUpdate = await request(app)
    .post('/api/updates')
    .set('Authorization', `Bearer ${politicianToken}`)
    .send({
      title: 'Allowed politician update',
      content: 'Politician can publish updates.',
      category: 'Community',
    })
  assert.equal(allowedUpdate.status, 201)

  const blockedModeration = await request(app)
    .post('/api/moderation/flag')
    .set('Authorization', `Bearer ${politicianToken}`)
    .send({ type: 'issue', id: 'i1', flagged: true })
  assert.equal(blockedModeration.status, 403)
})
