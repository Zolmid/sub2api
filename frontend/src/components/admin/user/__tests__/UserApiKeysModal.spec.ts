import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import UserApiKeysModal from '../UserApiKeysModal.vue'

const { getUserApiKeys, getAll, updateApiKeyGroup, appStore } = vi.hoisted(() => ({
  getUserApiKeys: vi.fn(),
  getAll: vi.fn(),
  updateApiKeyGroup: vi.fn(),
  appStore: { cachedPublicSettings: null as { version: string } | null, showSuccess: vi.fn(), showError: vi.fn() }
}))

vi.mock('@/api/admin', () => ({
  adminAPI: {
    users: { getUserApiKeys },
    groups: { getAll },
    apiKeys: { updateApiKeyGroup }
  }
}))

vi.mock('@/stores/app', () => ({ useAppStore: () => appStore }))

vi.mock('vue-i18n', async () => {
  const actual = await vi.importActual<typeof import('vue-i18n')>('vue-i18n')
  return { ...actual, useI18n: () => ({ t: (key: string) => key }) }
})

const groups = [
  { id: 101, name: 'standard-openai', status: 'active', platform: 'openai', subscription_type: 'standard' },
  { id: 102, name: 'inactive-openai', status: 'inactive', platform: 'openai', subscription_type: 'standard' },
  { id: 103, name: 'subscription-openai', status: 'active', platform: 'openai', subscription_type: 'subscription' },
  { id: 104, name: 'standard-anthropic', status: 'active', platform: 'anthropic', subscription_type: 'standard' }
]

const apiKey = {
  id: '9007199254740995', group_id: 101, name: 'key', key: 'sk-test-key',
  status: 'active', created_at: '2026-09-07T00:00:00Z', group: groups[0]
}

const mountModal = async (version: string | null, availableGroups = groups) => {
  appStore.cachedPublicSettings = version === null ? null : { version }
  getUserApiKeys.mockResolvedValue({ items: [{ ...apiKey }] })
  getAll.mockResolvedValue(availableGroups)
  const wrapper = mount(UserApiKeysModal, {
    props: { show: false, user: { id: 1, email: 'admin@example.test', username: 'admin' } as never },
    global: {
      stubs: {
        BaseDialog: { props: ['show'], template: '<div v-if="show"><slot /></div>' },
        GroupBadge: true,
        GroupOptionItem: { props: ['name'], template: '<span>{{ name }}</span>' },
        Teleport: true
      }
    }
  })
  await wrapper.setProps({ show: true })
  await flushPromises()
  await wrapper.get('button[class*="cursor-pointer"]').trigger('click')
  return wrapper
}

describe('UserApiKeysModal Cloudflare group choices', () => {
  beforeEach(() => {
    getUserApiKeys.mockReset()
    getAll.mockReset()
    updateApiKeyGroup.mockReset()
    appStore.showSuccess.mockReset()
    appStore.showError.mockReset()
  })

  it('uses public settings version, hides unbind, and filters choices in Cloudflare mode', async () => {
    const wrapper = await mountModal('cloudflare')
    expect(wrapper.text()).toContain('standard-openai')
    expect(wrapper.findAll('button').filter((button) => button.text() === 'admin.users.none')).toHaveLength(0)
    expect(wrapper.text()).not.toContain('inactive-openai')
    expect(wrapper.text()).not.toContain('subscription-openai')
    expect(wrapper.text()).not.toContain('standard-anthropic')
  })

  it('retains the traditional selector, including unbind and inactive choices', async () => {
    const wrapper = await mountModal('traditional')
    expect(wrapper.text()).toContain('admin.users.none')
    expect(wrapper.text()).toContain('standard-openai')
    expect(wrapper.text()).toContain('inactive-openai')
    expect(wrapper.text()).toContain('subscription-openai')
    expect(wrapper.text()).toContain('standard-anthropic')
  })

  it('sends a Cloudflare large decimal group ID without coercing it to a number', async () => {
    const largeGroupID = '9007199254741997'
    updateApiKeyGroup.mockResolvedValue({
      api_key: { ...apiKey, group_id: largeGroupID },
      auto_granted_group_access: false,
      granted_group_id: largeGroupID
    })
    const wrapper = await mountModal('cloudflare', [{ ...groups[0], id: largeGroupID, name: 'large-openai' }])
    const choice = wrapper.findAll('button').find((button) => button.text().includes('large-openai'))
    expect(choice).toBeDefined()
    await choice!.trigger('click')
    await flushPromises()
    expect(updateApiKeyGroup).toHaveBeenCalledWith('9007199254740995', largeGroupID)
  })
})
