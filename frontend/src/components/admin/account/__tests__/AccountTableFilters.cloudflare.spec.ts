import { defineComponent } from 'vue'
import { mount } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'

vi.mock('vue-i18n', async () => {
  const actual = await vi.importActual<typeof import('vue-i18n')>('vue-i18n')
  return { ...actual, useI18n: () => ({ t: (key: string) => key }) }
})

import AccountTableFilters from '../AccountTableFilters.vue'

const SelectStub = defineComponent({
  name: 'SelectStub',
  props: {
    modelValue: { type: [String, Number, Boolean], default: '' },
    options: { type: Array, default: () => [] }
  },
  emits: ['update:modelValue', 'change'],
  template: '<div />'
})

const groups = [
  { id: '9007199254740993', name: 'OpenAI standard', platform: 'openai', status: 'active', subscription_type: 'standard' },
  { id: 2, name: 'Disabled OpenAI', platform: 'openai', status: 'inactive', subscription_type: 'standard' },
  { id: 3, name: 'Anthropic', platform: 'anthropic', status: 'active', subscription_type: 'standard' }
] as any[]

function optionValues(wrapper: ReturnType<typeof mount>, index: number): unknown[] {
  return (wrapper.findAllComponents(SelectStub)[index]?.props('options') as Array<{ value: unknown }>)
    .map(option => option.value)
}

describe('AccountTableFilters Cloudflare compatibility', () => {
  it('offers only filters accepted by the Cloudflare account-list contract', () => {
    const wrapper = mount(AccountTableFilters, {
      props: {
        searchQuery: '',
        filters: {},
        groups,
        cloudflareMode: true
      },
      global: { stubs: { Select: SelectStub, SearchInput: true } }
    })

    expect(optionValues(wrapper, 0)).toEqual(['', 'openai'])
    expect(optionValues(wrapper, 1)).toEqual(['', 'apikey'])
    expect(optionValues(wrapper, 2)).toEqual(['', 'active', 'inactive'])
    expect(optionValues(wrapper, 4)).toEqual(['', '9007199254740993'])
  })

  it('retains traditional platform, type, status, and ungrouped options', () => {
    const wrapper = mount(AccountTableFilters, {
      props: {
        searchQuery: '',
        filters: {},
        groups,
        cloudflareMode: false
      },
      global: { stubs: { Select: SelectStub, SearchInput: true } }
    })

    expect(optionValues(wrapper, 0)).toContain('anthropic')
    expect(optionValues(wrapper, 1)).toContain('oauth')
    expect(optionValues(wrapper, 2)).toContain('error')
    expect(optionValues(wrapper, 4)).toContain('ungrouped')
  })
})
