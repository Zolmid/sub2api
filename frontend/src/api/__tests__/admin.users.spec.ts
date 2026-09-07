import { beforeEach, describe, expect, it, vi } from 'vitest'

const { post } = vi.hoisted(() => ({
  post: vi.fn(),
}))

vi.mock('@/api/client', () => ({
  apiClient: {
    post,
  },
}))

import {
  batchUpdateLimits,
  bindUserAuthIdentity,
  create,
  type AdminBindAuthIdentityRequest,
  type AdminBoundAuthIdentity,
  type BatchUpdateUserLimitsRequest,
  type BatchUpdateUserLimitsResponse,
} from '@/api/admin/users'

function idempotencyHeader(callIndex: number): string {
  const config = post.mock.calls[callIndex]?.[2] as { headers?: Record<string, string> } | undefined
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
