import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { CreateAccountRequest } from '@/types'

const post = vi.fn()
const get = vi.fn()
const put = vi.fn()
const remove = vi.fn()

vi.mock('@/api/client', () => ({ apiClient: { post, get, put, delete: remove } }))

const payload = (
  overrides: Partial<CreateAccountRequest> = {}
): CreateAccountRequest => ({
  name: 'managed account',
  platform: 'openai',
  type: 'apikey',
  concurrency: 2,
  priority: 3,
  credentials: {
    api_key: 'upstream-secret-value',
    base_url: 'https://mock.upstream'
  },
  extra: { privacy_mode: 'training_off' },
  group_ids: ['9007199254740993'],
  ...overrides
})

const operationKey = (call: number): string =>
  post.mock.calls[call][2].headers['Idempotency-Key'] as string

async function accountCreate() {
  return (await import('@/api/admin/accounts')).create
}

async function accountAPI() {
  return import('@/api/admin/accounts')
}

function setAdmin(id: number | string): void {
  localStorage.setItem('auth_user', JSON.stringify({ id, role: 'admin' }))
}

describe('admin account create idempotency', () => {
  beforeEach(() => {
    post.mockReset()
    get.mockReset()
    put.mockReset()
    remove.mockReset()
    localStorage.clear()
    sessionStorage.clear()
    window.__APP_CONFIG__ = { version: 'cloudflare' } as Window['__APP_CONFIG__']
    setAdmin('9007199254740991')
    vi.resetModules()
  })

  it('reuses the key for an equivalent reconstructed credential-bearing payload', async () => {
    const create = await accountCreate()
    post.mockRejectedValueOnce(new Error('network'))
    await expect(create(payload())).rejects.toThrow('network')
    post.mockResolvedValueOnce({ data: { id: '9007199254740994' } })
    await create(payload())

    expect(operationKey(1)).toBe(operationKey(0))
    expect(operationKey(0)).toMatch(/^account-create-9007199254740991-/)
  })

  it('recovers the nonsecret operation scope after a simulated page reload', async () => {
    let create = await accountCreate()
    post.mockRejectedValueOnce(new Error('connection reset'))
    await expect(create(payload())).rejects.toThrow('connection reset')
    const firstKey = operationKey(0)
    const storedBeforeReload = sessionStorage.getItem(
      'sub2api:admin:account-create:9007199254740991'
    )
    expect(storedBeforeReload).toBeTruthy()
    expect(storedBeforeReload).not.toContain('upstream-secret-value')
    expect(storedBeforeReload).not.toContain('https://mock.upstream')
    expect(storedBeforeReload).not.toContain('api_key')
    expect(storedBeforeReload).not.toContain('base_url')

    vi.resetModules()
    create = await accountCreate()
    post.mockResolvedValueOnce({ data: { id: '9007199254740994' } })
    await create(payload())

    expect(operationKey(1)).toBe(firstKey)
    expect(sessionStorage.length).toBe(0)
  })

  it('isolates changed credentials and changed nonsecret payloads while memory is live', async () => {
    const create = await accountCreate()
    post.mockRejectedValue(new Error('network'))
    await expect(create(payload())).rejects.toThrow('network')
    await expect(create(payload({
      credentials: { api_key: 'different-secret', base_url: 'https://mock.upstream' }
    }))).rejects.toThrow('network')
    await expect(create(payload({ name: 'different account' }))).rejects.toThrow('network')

    expect(operationKey(1)).not.toBe(operationKey(0))
    expect(operationKey(2)).not.toBe(operationKey(1))
  })

  it('clears after a definitive 4xx but retains the key for HTTP 408', async () => {
    const create = await accountCreate()
    post.mockRejectedValueOnce({ response: { status: 422 } })
    await expect(create(payload())).rejects.toMatchObject({ response: { status: 422 } })
    post.mockRejectedValueOnce({ status: 408 })
    await expect(create(payload())).rejects.toMatchObject({ status: 408 })
    post.mockResolvedValueOnce({ data: { id: '9007199254740994' } })
    await create(payload())

    expect(operationKey(1)).not.toBe(operationKey(0))
    expect(operationKey(2)).toBe(operationKey(1))
    expect(sessionStorage.length).toBe(0)

    post.mockResolvedValueOnce({ data: { id: '9007199254740995' } })
    await create(payload())
    expect(operationKey(3)).not.toBe(operationKey(2))
  })

  it('scopes pending creates by authenticated administrator', async () => {
    const create = await accountCreate()
    post.mockRejectedValue(new Error('network'))
    await expect(create(payload())).rejects.toThrow('network')
    const adminOneKey = operationKey(0)

    setAdmin('9007199254740992')
    await expect(create(payload())).rejects.toThrow('network')
    const adminTwoKey = operationKey(1)

    setAdmin('9007199254740991')
    await expect(create(payload())).rejects.toThrow('network')
    expect(operationKey(2)).toBe(adminOneKey)
    expect(adminTwoKey).not.toBe(adminOneKey)
    expect(sessionStorage.getItem('sub2api:admin:account-create:9007199254740991')).toContain(adminOneKey)
    expect(sessionStorage.getItem('sub2api:admin:account-create:9007199254740992')).toContain(adminTwoKey)
  })

  it('preserves exact decimal-string account and group IDs in CRUD helpers', async () => {
    const api = await accountAPI()
    const accountID = '9007199254740997'
    const groupID = '9007199254740998'
    get.mockResolvedValueOnce({ data: { id: accountID } })
    put.mockResolvedValueOnce({ data: { id: accountID } })
    remove.mockResolvedValueOnce({ data: { message: 'ok' } })

    await api.getById(accountID)
    await api.update(accountID, { group_ids: [groupID] })
    await api.deleteAccount(accountID)

    expect(get).toHaveBeenCalledWith(`/admin/accounts/${accountID}`)
    expect(put).toHaveBeenCalledWith(`/admin/accounts/${accountID}`, { group_ids: [groupID] })
    expect(remove).toHaveBeenCalledWith(`/admin/accounts/${accountID}`)
  })

  it('sends a strict field allowlist in Cloudflare mode before fingerprinting', async () => {
    window.__APP_CONFIG__ = { version: 'cloudflare' } as Window['__APP_CONFIG__']
    const create = await accountCreate()
    post.mockResolvedValueOnce({ data: { id: '9007199254740994' } })

    await create(payload({
      notes: 'must not leave the browser adapter',
      proxy_id: 42,
      load_factor: 99,
      rate_multiplier: 5,
      expires_at: 123,
      upstream_billing_probe_enabled: true,
      auto_pause_on_expired: true,
      credentials: {
        api_key: 'upstream-secret-value',
        base_url: 'https://mock.upstream',
        model_mapping: { public: 'private' },
      },
      extra: {
        privacy_mode: 'training_off',
        openai_passthrough: true,
      },
    }))

    expect(post.mock.calls[0]?.[1]).toEqual({
      name: 'managed account',
      platform: 'openai',
      type: 'apikey',
      credentials: {
        api_key: 'upstream-secret-value',
        base_url: 'https://mock.upstream',
      },
      extra: { privacy_mode: 'training_off' },
      concurrency: 2,
      priority: 3,
      group_ids: ['9007199254740993'],
    })
  })

  it('does not rewrite account payloads in traditional mode', async () => {
    delete window.__APP_CONFIG__
    const create = await accountCreate()
    const legacyPayload = payload({
      notes: 'legacy option',
      proxy_id: 7,
      credentials: {
        api_key: 'upstream-secret-value',
        base_url: 'https://mock.upstream',
        model_mapping: { public: 'private' },
      },
    })
    post.mockResolvedValueOnce({ data: { id: 42 } })

    await create(legacyPayload)

    expect(post).toHaveBeenCalledWith('/admin/accounts', legacyPayload)
    expect(post.mock.calls[0]?.[1]).toBe(legacyPayload)
    expect(sessionStorage.length).toBe(0)
  })

  it('uses the strict Cloudflare update route for field patches and schedulable toggles', async () => {
    window.__APP_CONFIG__ = { version: 'cloudflare' } as Window['__APP_CONFIG__']
    const api = await accountAPI()
    const accountID = '9007199254740997'
    put.mockResolvedValue({ data: { id: accountID } })

    await api.update(accountID, {
      name: 'managed account',
      notes: 'drop me',
      proxy_id: 42,
      concurrency: 4,
      priority: -3,
      status: 'inactive',
      schedulable: false,
      group_ids: ['9007199254740998'],
      credentials: {
        api_key: 'replacement-secret',
        base_url: 'https://relay.example',
        model_mapping: { public: 'private' }
      },
      extra: {
        privacy_mode: 'training_off',
        openai_passthrough: true
      }
    })
    await api.setSchedulable(accountID, true)

    expect(put.mock.calls[0]).toEqual([
      `/admin/accounts/${accountID}`,
      {
        name: 'managed account',
        concurrency: 4,
        priority: -3,
        status: 'inactive',
        schedulable: false,
        group_ids: ['9007199254740998'],
        credentials: {
          api_key: 'replacement-secret',
          base_url: 'https://relay.example'
        },
        extra: { privacy_mode: 'training_off' }
      }
    ])
    expect(put.mock.calls[1]).toEqual([
      `/admin/accounts/${accountID}`,
      { schedulable: true }
    ])
    expect(post).not.toHaveBeenCalled()
  })

  it('keeps the legacy schedulable endpoint in traditional mode', async () => {
    delete window.__APP_CONFIG__
    const api = await accountAPI()
    post.mockResolvedValueOnce({ data: { id: 42 } })

    await api.setSchedulable(42, false)

    expect(post).toHaveBeenCalledWith('/admin/accounts/42/schedulable', { schedulable: false })
    expect(put).not.toHaveBeenCalled()
  })
})
