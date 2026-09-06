import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const { post } = vi.hoisted(() => ({
  post: vi.fn()
}))

vi.mock('@/api/client', () => ({
  apiClient: { post }
}))

import { create, duplicate } from '@/api/admin/groups'

describe('admin group duplicate API', () => {
  beforeEach(() => {
    localStorage.clear()
    sessionStorage.clear()
    localStorage.setItem('auth_user', JSON.stringify({ id: 7 }))
    post.mockReset()
    post.mockResolvedValue({ data: { id: 43, name: 'primary (Copy)', status: 'inactive' } })
    vi.spyOn(globalThis.crypto, 'randomUUID').mockReturnValue('11111111-1111-4111-8111-111111111111')
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('sends a stable idempotency key with the duplicate request', async () => {
    const group = await duplicate(42)

    expect(post).toHaveBeenCalledWith('/admin/groups/42/duplicate', undefined, {
      headers: {
        'Idempotency-Key': 'group-duplicate-7-42-11111111-1111-4111-8111-111111111111'
      }
    })
    expect(group).toEqual({ id: 43, name: 'primary (Copy)', status: 'inactive' })
    expect(sessionStorage.length).toBe(0)
  })

  it('reuses the operation key after an ambiguous failed request', async () => {
    post.mockRejectedValueOnce(new Error('network timeout'))
    await expect(duplicate(99)).rejects.toThrow('network timeout')

    post.mockResolvedValueOnce({ data: { id: 100, name: 'retry (Copy)' } })
    await duplicate(99)

    expect(post).toHaveBeenCalledTimes(2)
    expect(post.mock.calls[1][2].headers).toEqual(post.mock.calls[0][2].headers)
    expect(sessionStorage.length).toBe(0)
  })

  it('reuses the operation key after a page reload', async () => {
    post.mockRejectedValueOnce(new Error('network timeout'))
    await expect(duplicate(77)).rejects.toThrow('network timeout')
    const firstHeaders = post.mock.calls[0][2].headers

    vi.resetModules()
    post.mockResolvedValueOnce({ data: { id: 78, name: 'reload (Copy)' } })
    const { duplicate: duplicateAfterReload } = await import('@/api/admin/groups')
    await duplicateAfterReload(77)

    expect(post).toHaveBeenCalledTimes(2)
    expect(post.mock.calls[1][2].headers).toEqual(firstHeaders)
    expect(sessionStorage.length).toBe(0)
  })

  it('does not reuse an operation key across administrators for the same group', async () => {
    post.mockRejectedValueOnce(new Error('first admin timeout'))
    await expect(duplicate(55)).rejects.toThrow('first admin timeout')
    const firstAdminHeaders = post.mock.calls[0][2].headers

    localStorage.setItem('auth_user', JSON.stringify({ id: 8 }))
    vi.mocked(globalThis.crypto.randomUUID).mockReturnValueOnce(
      '22222222-2222-4222-8222-222222222222'
    )
    post.mockResolvedValueOnce({ data: { id: 56, name: 'second admin copy' } })
    await duplicate(55)

    expect(post.mock.calls[1][2].headers).not.toEqual(firstAdminHeaders)
    expect(post.mock.calls[1][2].headers).toEqual({
      'Idempotency-Key': 'group-duplicate-8-55-22222222-2222-4222-8222-222222222222'
    })
    expect(sessionStorage.getItem('sub2api:admin:group-duplicate:7:55')).toBe(
      firstAdminHeaders['Idempotency-Key']
    )
    expect(sessionStorage.getItem('sub2api:admin:group-duplicate:8:55')).toBeNull()
  })

  it('does not persist or reuse keys when the current user cannot be parsed', async () => {
    localStorage.setItem('auth_user', '{invalid json')
    post.mockRejectedValueOnce(new Error('network timeout'))
    await expect(duplicate(66)).rejects.toThrow('network timeout')
    const firstHeaders = post.mock.calls[0][2].headers

    vi.mocked(globalThis.crypto.randomUUID).mockReturnValueOnce(
      '33333333-3333-4333-8333-333333333333'
    )
    post.mockResolvedValueOnce({ data: { id: 67, name: 'fallback copy' } })
    await duplicate(66)

    expect(post.mock.calls[1][2].headers).not.toEqual(firstHeaders)
    expect(sessionStorage.length).toBe(0)
  })
})

describe('admin group create API', () => {
  beforeEach(() => {
    localStorage.clear()
    sessionStorage.clear()
    localStorage.setItem('auth_user', JSON.stringify({ id: '9007199254740993' }))
    post.mockReset()
    post.mockResolvedValue({ data: { id: 43, name: 'primary', status: 'active' } })
    vi.spyOn(globalThis.crypto, 'randomUUID').mockReturnValue('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa')
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('sends and clears a create idempotency key scoped to the current admin and payload', async () => {
    const group = await create({
      name: 'primary',
      platform: 'openai',
      subscription_type: 'standard',
      is_exclusive: false
    } as any)

    expect(post).toHaveBeenCalledWith(
      '/admin/groups',
      {
        name: 'primary',
        platform: 'openai',
        subscription_type: 'standard',
        is_exclusive: false
      },
      {
        headers: {
          'Idempotency-Key':
            'group-create-9007199254740993-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
        }
      }
    )
    expect(group).toEqual({ id: 43, name: 'primary', status: 'active' })
    expect(sessionStorage.length).toBe(0)
  })

  it('reuses the pending create key after an ambiguous failed request', async () => {
    const payload = { name: 'retry', platform: 'openai', subscription_type: 'standard' } as any
    post.mockRejectedValueOnce(new Error('network timeout'))
    await expect(create(payload)).rejects.toThrow('network timeout')
    const firstHeaders = post.mock.calls[0][2].headers

    post.mockResolvedValueOnce({ data: { id: 44, name: 'retry', status: 'active' } })
    await create(payload)

    expect(post).toHaveBeenCalledTimes(2)
    expect(post.mock.calls[1][2].headers).toEqual(firstHeaders)
    expect(sessionStorage.length).toBe(0)
  })

  it('rotates the pending key when the full create payload changes', async () => {
    vi.mocked(globalThis.crypto.randomUUID)
      .mockReturnValueOnce('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa')
      .mockReturnValueOnce('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb')
    const payload = { name: 'retry', platform: 'openai', subscription_type: 'standard' } as any
    post.mockRejectedValueOnce(new Error('network timeout'))
    await expect(create(payload)).rejects.toThrow('network timeout')
    const firstKey = post.mock.calls[0][2].headers['Idempotency-Key']

    post.mockResolvedValueOnce({ data: { id: 45, name: 'retry', status: 'active' } })
    await create({ ...payload, is_exclusive: true })
    const secondKey = post.mock.calls[1][2].headers['Idempotency-Key']

    expect(secondKey).not.toBe(firstKey)
    expect(secondKey).toBe(
      'group-create-9007199254740993-bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
    )
    expect(sessionStorage.length).toBe(0)
  })

  it('does not copy an out-of-range admin id into the idempotency header', async () => {
    localStorage.setItem('auth_user', JSON.stringify({ id: '9'.repeat(100) }))
    await create({ name: 'bounded', platform: 'openai' } as any)

    const key = post.mock.calls[0][2].headers['Idempotency-Key']
    expect(key).toBe('group-create-unknown-admin-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa')
    expect(key.length).toBeLessThanOrEqual(128)
  })
})
