import { beforeEach, describe, expect, it, vi } from 'vitest'

const { post, put } = vi.hoisted(() => ({
  post: vi.fn(),
  put: vi.fn(),
}))

vi.mock('@/api/client', () => ({
  apiClient: {
    post,
    put,
  },
}))

import {
  batchUpdateLimits,
  bindUserAuthIdentity,
  create,
  update,
  updateBalance,
  type AdminBindAuthIdentityRequest,
  type AdminBoundAuthIdentity,
  type BatchUpdateUserLimitsRequest,
  type BatchUpdateUserLimitsResponse,
} from '@/api/admin/users'

function idempotencyHeader(callIndex: number): string {
  const config = post.mock.calls[callIndex]?.[2] as { headers?: Record<string, string> } | undefined
  return config?.headers?.['Idempotency-Key'] ?? ''
}

function roleIdempotencyHeader(callIndex: number): string {
  const config = put.mock.calls[callIndex]?.[2] as { headers?: Record<string, string> } | undefined
  return config?.headers?.['Idempotency-Key'] ?? ''
}

type Assert<T extends true> = T
type IsExact<T, U> = (
  (<G>() => G extends T ? 1 : 2) extends (<G>() => G extends U ? 1 : 2)
    ? ((<G>() => G extends U ? 1 : 2) extends (<G>() => G extends T ? 1 : 2) ? true : false)
    : false
)

type ExpectedAdminBindAuthIdentityRequest = {
  provider_type: string
  provider_key: string
  provider_subject: string
  issuer?: string
  metadata?: Record<string, unknown>
  channel?: {
    channel: string
    channel_app_id: string
    channel_subject: string
    metadata?: Record<string, unknown>
  }
}

type ExpectedAdminBoundAuthIdentity = {
  user_id: number
  provider_type: string
  provider_key: string
  provider_subject: string
  verified_at?: string | null
  issuer?: string | null
  metadata: Record<string, unknown> | null
  created_at: string
  updated_at: string
  channel?: {
    channel: string
    channel_app_id: string
    channel_subject: string
    metadata: Record<string, unknown> | null
    created_at: string
    updated_at: string
  } | null
}

const requestContractExact: Assert<
  IsExact<AdminBindAuthIdentityRequest, ExpectedAdminBindAuthIdentityRequest>
> = true
const responseContractExact: Assert<
  IsExact<AdminBoundAuthIdentity, ExpectedAdminBoundAuthIdentity>
> = true
const batchRequestContractExact: Assert<
  IsExact<
    BatchUpdateUserLimitsRequest,
    {
      user_ids: number[]
      all?: boolean
      concurrency?: number
      rpm_limit?: number
    }
  >
> = true
const batchResponseContractExact: Assert<
  IsExact<BatchUpdateUserLimitsResponse, { affected: number }>
> = true

describe('admin users api auth identity binding', () => {
  beforeEach(() => {
    post.mockReset()
  })

  it('posts the backend-compatible auth identity bind payload and returns the backend response shape', async () => {
    const payload: AdminBindAuthIdentityRequest = {
      provider_type: 'wechat',
      provider_key: 'wechat-main',
      provider_subject: 'union-123',
      metadata: { source: 'admin-repair' },
      channel: {
        channel: 'open',
        channel_app_id: 'wx-open',
        channel_subject: 'openid-123',
        metadata: { scene: 'migration' },
      },
    }

    const response: AdminBoundAuthIdentity = {
      user_id: 9,
      provider_type: 'wechat',
      provider_key: 'wechat-main',
      provider_subject: 'union-123',
      verified_at: '2026-04-22T00:00:00Z',
      issuer: null,
      metadata: { source: 'admin-repair' },
      created_at: '2026-04-22T00:00:00Z',
      updated_at: '2026-04-22T00:00:00Z',
      channel: {
        channel: 'open',
        channel_app_id: 'wx-open',
        channel_subject: 'openid-123',
        metadata: { scene: 'migration' },
        created_at: '2026-04-22T00:00:00Z',
        updated_at: '2026-04-22T00:00:00Z',
      },
    }
    post.mockResolvedValue({ data: response })

    const result = await bindUserAuthIdentity(9, payload)

    expect(post).toHaveBeenCalledWith('/admin/users/9/auth-identities', payload)
    expect(result).toEqual(response)
  })

  it('keeps bind auth identity request and response types aligned with the backend contract', () => {
    expect(requestContractExact).toBe(true)
    expect(responseContractExact).toBe(true)
  })

  it('posts batch limit updates once with only the supplied limit fields', async () => {
    const request: BatchUpdateUserLimitsRequest = {
      user_ids: [4, 7],
      all: false,
      rpm_limit: 0,
    }
    post.mockResolvedValue({ data: { affected: 2 } satisfies BatchUpdateUserLimitsResponse })

    const result = await batchUpdateLimits(request)

    expect(post).toHaveBeenCalledWith('/admin/users/batch-limits', request)
    expect(result).toEqual({ affected: 2 })
    expect(batchRequestContractExact).toBe(true)
    expect(batchResponseContractExact).toBe(true)
  })
})

describe('admin users create idempotency', () => {
  beforeEach(() => {
    post.mockReset()
    localStorage.clear()
    sessionStorage.clear()
  })

  it('reuses the admin-scoped key after an ambiguous failure without storing the password', async () => {
    localStorage.setItem('auth_user', JSON.stringify({ id: 7001 }))
    const payload = {
      email: 'retry@example.test',
      password: 'correct horse battery staple',
      role: 'user' as const,
      concurrency: 1,
    }
    post.mockRejectedValueOnce({ status: 0, message: 'network error' })
    post.mockResolvedValueOnce({ data: { id: 91 } })

    await expect(create(payload)).rejects.toMatchObject({ status: 0 })
    const firstKey = idempotencyHeader(0)
    const stored = sessionStorage.getItem('sub2api:admin:user-create:7001')
    expect(firstKey).toMatch(/^user-create-7001-/)
    expect(firstKey.length).toBeLessThanOrEqual(128)
    expect(stored).not.toBeNull()
    expect(stored).not.toContain(payload.password)
    expect(stored).not.toContain(payload.email)

    await create(payload)
    expect(idempotencyHeader(1)).toBe(firstKey)
    expect(sessionStorage.getItem('sub2api:admin:user-create:7001')).toBeNull()
  })

  it('rotates the key when the password changes after an ambiguous attempt', async () => {
    localStorage.setItem('auth_user', JSON.stringify({ id: 7002 }))
    const original = {
      email: 'password-change@example.test',
      password: 'first-password',
      concurrency: 1,
    }
    post.mockRejectedValueOnce({ status: 0 })
    post.mockResolvedValueOnce({ data: { id: 92 } })

    await expect(create(original)).rejects.toMatchObject({ status: 0 })
    const firstKey = idempotencyHeader(0)
    const pending = sessionStorage.getItem('sub2api:admin:user-create:7002')
    expect(pending).not.toContain('first-password')
    await create({ ...original, password: 'second-password' })

    expect(idempotencyHeader(1)).not.toBe(firstKey)
    expect(sessionStorage.getItem('sub2api:admin:user-create:7002')).toBeNull()
  })

  it('clears a definitive client failure so the corrected retry gets a new key', async () => {
    localStorage.setItem('auth_user', JSON.stringify({ id: 7003 }))
    const payload = {
      email: 'client-error@example.test',
      password: 'valid-password',
      concurrency: 1,
    }
    post.mockRejectedValueOnce({ status: 400, message: 'invalid request' })
    post.mockResolvedValueOnce({ data: { id: 93 } })

    await expect(create(payload)).rejects.toMatchObject({ status: 400 })
    const firstKey = idempotencyHeader(0)
    expect(sessionStorage.getItem('sub2api:admin:user-create:7003')).toBeNull()
    await create(payload)

    expect(idempotencyHeader(1)).not.toBe(firstKey)
  })

  it('separates pending creates when the signed-in administrator changes', async () => {
    const payload = {
      email: 'admin-scope@example.test',
      password: 'valid-password',
      concurrency: 1,
    }
    localStorage.setItem('auth_user', JSON.stringify({ id: 7004 }))
    post.mockRejectedValueOnce({ status: 503 })
    await expect(create(payload)).rejects.toMatchObject({ status: 503 })
    const firstKey = idempotencyHeader(0)

    localStorage.setItem('auth_user', JSON.stringify({ id: 7005 }))
    post.mockResolvedValueOnce({ data: { id: 94 } })
    await create(payload)

    expect(firstKey).toMatch(/^user-create-7004-/)
    expect(idempotencyHeader(1)).toMatch(/^user-create-7005-/)
    expect(idempotencyHeader(1)).not.toBe(firstKey)
  })
})

describe('admin user role-change idempotency', () => {
  beforeEach(() => {
    put.mockReset()
    localStorage.clear()
    sessionStorage.clear()
  })

  it('keeps one role operation across step-up and clears it after success without storing user secrets', async () => {
    localStorage.setItem('auth_user', JSON.stringify({ id: 8201, role: 'admin' }))
    const payload = {
      email: 'role-target@example.test',
      password: 'replacement password',
      role: 'admin' as const,
      concurrency: 2,
    }
    put.mockRejectedValueOnce({ status: 403, code: 'STEP_UP_REQUIRED' })
    put.mockResolvedValueOnce({ data: { id: 81, role: 'admin' } })

    await expect(update(81, payload, { roleOperation: true }))
      .rejects.toMatchObject({ code: 'STEP_UP_REQUIRED' })
    const firstKey = roleIdempotencyHeader(0)
    const stored = sessionStorage.getItem('sub2api:admin:user-role:8201:81')
    expect(firstKey).toMatch(/^user-role-8201-81-/)
    expect(firstKey.length).toBeLessThanOrEqual(128)
    expect(stored).not.toBeNull()
    expect(stored).not.toContain(payload.password)
    expect(stored).not.toContain(payload.email)
    expect(put.mock.calls[0]?.[2]).toMatchObject({
      headers: {
        'Idempotency-Key': firstKey,
        'X-Sub2API-Role-Operation': 'true',
      },
    })

    await update(81, payload, { roleOperation: true })
    expect(roleIdempotencyHeader(1)).toBe(firstKey)
    expect(sessionStorage.getItem('sub2api:admin:user-role:8201:81')).toBeNull()
  })

  it('rotates the operation when a password changes after an ambiguous attempt in the same page', async () => {
    localStorage.setItem('auth_user', JSON.stringify({ id: 8202, role: 'admin' }))
    const payload = { role: 'admin' as const, password: 'first replacement' }
    put.mockRejectedValueOnce({ status: 503 })
    put.mockResolvedValueOnce({ data: { id: 82, role: 'admin' } })

    await expect(update(82, payload, { roleOperation: true })).rejects.toMatchObject({ status: 503 })
    const firstKey = roleIdempotencyHeader(0)
    await update(82, { ...payload, password: 'second replacement' }, { roleOperation: true })

    expect(roleIdempotencyHeader(1)).not.toBe(firstKey)
    expect(sessionStorage.length).toBe(0)
  })

  it('leaves ordinary profile updates on the established unkeyed path', async () => {
    put.mockResolvedValueOnce({ data: { id: 83, role: 'user' } })

    await update(83, { username: 'ordinary' })

    expect(put).toHaveBeenCalledWith('/admin/users/83', { username: 'ordinary' })
    expect(sessionStorage.length).toBe(0)
  })
})

describe('admin users balance idempotency', () => {
  beforeEach(() => {
    post.mockReset()
    localStorage.clear()
    sessionStorage.clear()
  })

  it('reuses an administrator-and-payload-scoped key after ambiguous failures and clears it after success', async () => {
    localStorage.setItem('auth_user', JSON.stringify({ id: 8101, role: 'admin' }))
    post.mockRejectedValueOnce({ status: 503, message: 'upstream unavailable' })
    post.mockResolvedValueOnce({ data: { id: 71 } })
    post.mockResolvedValueOnce({ data: { id: 71 } })

    await expect(updateBalance(71, 1.25, 'add', 'manual credit')).rejects.toMatchObject({ status: 503 })
    const firstKey = idempotencyHeader(0)
    expect(firstKey).toMatch(/^user-balance-8101-[0-9a-f-]+-/)
    expect(firstKey.length).toBeLessThanOrEqual(128)
    expect(sessionStorage.length).toBe(1)

    await updateBalance(71, 1.25, 'add', 'manual credit')
    expect(idempotencyHeader(1)).toBe(firstKey)
    expect(post.mock.calls[1]?.[1]).toEqual({
      balance: 1.25,
      operation: 'add',
      notes: 'manual credit',
    })
    expect(sessionStorage.length).toBe(0)

    await updateBalance(71, 1.25, 'add', 'manual credit')
    expect(idempotencyHeader(2)).not.toBe(firstKey)
  })

  it('retains HTTP 408 but clears a definitive non-408 4xx outcome', async () => {
    localStorage.setItem('auth_user', JSON.stringify({ id: 8102, role: 'admin' }))
    post.mockRejectedValueOnce({ response: { status: 408 } })
    post.mockRejectedValueOnce({ status: 422 })
    post.mockResolvedValueOnce({ data: { id: 72 } })

    await expect(updateBalance(72, 2, 'subtract')).rejects.toMatchObject({ response: { status: 408 } })
    const timedOutKey = idempotencyHeader(0)
    await expect(updateBalance(72, 2, 'subtract')).rejects.toMatchObject({ status: 422 })
    expect(idempotencyHeader(1)).toBe(timedOutKey)
    expect(sessionStorage.length).toBe(0)

    await updateBalance(72, 2, 'subtract')
    expect(idempotencyHeader(2)).not.toBe(timedOutKey)
  })

  it('changes the key when target, operation, amount, notes, or administrator changes', async () => {
    localStorage.setItem('auth_user', JSON.stringify({ id: 8103, role: 'admin' }))
    post.mockRejectedValue({ status: 500 })

    await expect(updateBalance(73, 3, 'add', 'base')).rejects.toMatchObject({ status: 500 })
    await expect(updateBalance(73, 3, 'add', 'base')).rejects.toMatchObject({ status: 500 })
    await expect(updateBalance(74, 3, 'add', 'base')).rejects.toMatchObject({ status: 500 })
    await expect(updateBalance(73, 3, 'subtract', 'base')).rejects.toMatchObject({ status: 500 })
    await expect(updateBalance(73, 4, 'add', 'base')).rejects.toMatchObject({ status: 500 })
    await expect(updateBalance(73, 3, 'add', 'changed')).rejects.toMatchObject({ status: 500 })
    localStorage.setItem('auth_user', JSON.stringify({ id: 8104, role: 'admin' }))
    await expect(updateBalance(73, 3, 'add', 'base')).rejects.toMatchObject({ status: 500 })

    const keys = post.mock.calls.map((_, index) => idempotencyHeader(index))
    expect(keys[1]).toBe(keys[0])
    expect(new Set([keys[0], ...keys.slice(2)]).size).toBe(6)
    expect(keys[6]).toMatch(/^user-balance-8104-/)
  })
})
