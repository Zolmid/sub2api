/**
 * Admin Users API endpoints
 * Handles user management for administrators
 */

import { apiClient } from '../client'
import type { AdminUser, UpdateUserRequest, PaginatedResponse, ApiKey } from '@/types'

export interface AdminUserCreateRequest {
  email: string
  password: string
  username?: string
  notes?: string
  role?: 'admin' | 'user'
  balance?: number
  concurrency?: number
  rpm_limit?: number
  allowed_groups?: number[] | null
  restrict_public_groups?: boolean
}

interface PendingUserCreateOperation {
  fullFingerprint: string
  nonsecretFingerprint: string
  idempotencyKey: string
}

interface StoredUserCreateOperation {
  nonsecretFingerprint: string
  idempotencyKey: string
}

interface UserCreateOperationScope {
  adminID: string
  storageKey: string
  fullFingerprint: string
  nonsecretFingerprint: string
}

const pendingUserCreateOperations = new Map<string, PendingUserCreateOperation>()
let fallbackUserRequestSequence = 0

export interface AdminBindAuthIdentityChannelRequest {
  channel: string
  channel_app_id: string
  channel_subject: string
  metadata?: Record<string, unknown> | null
}

export interface AdminBindAuthIdentityRequest {
  provider_type: string
  provider_key: string
  provider_subject: string
  issuer?: string | null
  metadata?: Record<string, unknown> | null
  channel?: AdminBindAuthIdentityChannelRequest
}

export interface AdminBoundAuthIdentityChannel {
  channel: string
  channel_app_id: string
  channel_subject: string
  metadata: Record<string, unknown> | null
  created_at: string
  updated_at: string
}

export interface AdminBoundAuthIdentity {
  user_id: number
  provider_type: string
  provider_key: string
  provider_subject: string
  verified_at?: string | null
  issuer?: string | null
  metadata: Record<string, unknown> | null
  created_at: string
  updated_at: string
  channel?: AdminBoundAuthIdentityChannel | null
}

export interface BatchUpdateUserLimitsRequest {
  user_ids: number[]
  all?: boolean
  concurrency?: number
  rpm_limit?: number
}

export interface BatchUpdateUserLimitsResponse {
  affected: number
}

/**
 * List all users with pagination
 * @param page - Page number (default: 1)
 * @param pageSize - Items per page (default: 20)
 * @param filters - Optional filters (status, role, search, attributes)
 * @param options - Optional request options (signal)
 * @returns Paginated list of users
 */
export async function list(
  page: number = 1,
  pageSize: number = 20,
  filters?: {
    status?: 'active' | 'disabled'
    role?: 'admin' | 'user'
    search?: string
    group_name?: string         // fuzzy filter by allowed group name
    api_key_group_id?: number   // filter users by the group their API keys are bound to
    attributes?: Record<number, string>  // attributeId -> value
    include_subscriptions?: boolean
    sort_by?: string
    sort_order?: 'asc' | 'desc'
  },
  options?: {
    signal?: AbortSignal
  }
): Promise<PaginatedResponse<AdminUser>> {
  // Build params with attribute filters in attr[id]=value format
  const params: Record<string, any> = {
    page,
    page_size: pageSize,
    status: filters?.status,
    role: filters?.role,
    search: filters?.search,
    group_name: filters?.group_name,
    api_key_group_id: filters?.api_key_group_id,
    include_subscriptions: filters?.include_subscriptions,
    sort_by: filters?.sort_by,
    sort_order: filters?.sort_order
  }

  // Add attribute filters as attr[id]=value
  if (filters?.attributes) {
    for (const [attrId, value] of Object.entries(filters.attributes)) {
      if (value) {
        params[`attr[${attrId}]`] = value
      }
    }
  }
  const { data } = await apiClient.get<PaginatedResponse<AdminUser>>('/admin/users', {
    params,
    signal: options?.signal
  })
  return data
}

/**
 * Get user by ID
 * @param id - User ID
 * @param includeDeleted - Whether to include soft-deleted users
 * @returns User details
 */
export async function getById(id: number, includeDeleted = false): Promise<AdminUser> {
  const url = includeDeleted ? `/admin/users/${id}?include_deleted=true` : `/admin/users/${id}`
  const { data } = await apiClient.get<AdminUser>(url)
  return data
}

/**
 * Create new user
 * @param userData - User data (email, password, etc.)
 * @returns Created user
 */
export async function create(userData: AdminUserCreateRequest): Promise<AdminUser> {
  const scope = await userCreateOperationScope(userData)
  const inMemory = scope ? pendingUserCreateOperations.get(scope.storageKey) : null
  const stored = scope ? getStoredUserCreateOperation(scope.storageKey) : null
  let idempotencyKey: string | null = null
  if (scope && inMemory && inMemory.fullFingerprint === scope.fullFingerprint) {
    idempotencyKey = inMemory.idempotencyKey
  } else if (scope && !inMemory && stored && stored.nonsecretFingerprint === scope.nonsecretFingerprint) {
    idempotencyKey = stored.idempotencyKey
  }
  if (!idempotencyKey) {
    idempotencyKey = `user-create-${scope?.adminID ?? 'unknown-admin'}-${newUserRequestID()}`
  }
  if (scope) {
    pendingUserCreateOperations.set(scope.storageKey, {
      fullFingerprint: scope.fullFingerprint,
      nonsecretFingerprint: scope.nonsecretFingerprint,
      idempotencyKey
    })
    storeUserCreateOperation(scope.storageKey, {
      nonsecretFingerprint: scope.nonsecretFingerprint,
      idempotencyKey
    })
  }

  try {
    const { data } = await apiClient.post<AdminUser>('/admin/users', userData, {
      headers: { 'Idempotency-Key': idempotencyKey }
    })
    if (scope) clearUserCreateOperation(scope.storageKey, idempotencyKey)
    return data
  } catch (error) {
    if (scope && isDefinitiveUserCreateFailure(error)) {
      clearUserCreateOperation(scope.storageKey, idempotencyKey)
    }
    throw error
  }
}

function currentAdminID(): string | null {
  try {
    const rawUser = globalThis.localStorage?.getItem('auth_user')
    if (!rawUser) return null
    const user: unknown = JSON.parse(rawUser)
    if (typeof user !== 'object' || user === null) return null
    const id = (user as { id?: unknown }).id
    if (typeof id === 'number' && Number.isSafeInteger(id) && id > 0) return String(id)
    if (
      typeof id === 'string' &&
      /^[1-9][0-9]*$/.test(id) &&
      (id.length < 19 || (id.length === 19 && id <= '9223372036854775807'))
    ) return id
    return null
  } catch {
    return null
  }
}

async function userCreateOperationScope(
  userData: AdminUserCreateRequest
): Promise<UserCreateOperationScope | null> {
  const adminID = currentAdminID()
  if (!adminID) return null
  const nonsecret = Object.fromEntries(
    Object.entries(userData).filter(([key]) => key !== 'password')
  )
  const [fullFingerprint, nonsecretFingerprint] = await Promise.all([
    userPayloadFingerprint(userData),
    userPayloadFingerprint(nonsecret)
  ])
  return {
    adminID,
    storageKey: `sub2api:admin:user-create:${adminID}`,
    fullFingerprint,
    nonsecretFingerprint
  }
}

function canonicalUserPayload(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalUserPayload)
  if (typeof value !== 'object' || value === null) return value
  const source = value as Record<string, unknown>
  const result: Record<string, unknown> = {}
  for (const key of Object.keys(source).sort()) {
    if (source[key] !== undefined) result[key] = canonicalUserPayload(source[key])
  }
  return result
}

async function userPayloadFingerprint(value: unknown): Promise<string> {
  const encoded = new TextEncoder().encode(JSON.stringify(canonicalUserPayload(value)))
  if (globalThis.crypto?.subtle) {
    const digest = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', encoded))
    return Array.from(digest, byte => byte.toString(16).padStart(2, '0')).join('')
  }

  // Supported browsers provide Web Crypto. This non-cryptographic fallback is
  // only an in-memory/session scoping aid for tests or legacy runtimes.
  let first = 0x811c9dc5
  let second = 0x9e3779b9
  for (const byte of encoded) {
    first = Math.imul(first ^ byte, 0x01000193)
    second = Math.imul(second ^ byte, 0x85ebca6b)
  }
  return `${encoded.length.toString(16)}-${(first >>> 0).toString(16).padStart(8, '0')}${(second >>> 0).toString(16).padStart(8, '0')}`
}

function newUserRequestID(): string {
  if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID()
  if (globalThis.crypto?.getRandomValues) {
    const bytes = globalThis.crypto.getRandomValues(new Uint8Array(16))
    return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('')
  }
  fallbackUserRequestSequence += 1
  return `${Date.now().toString(36)}-${fallbackUserRequestSequence.toString(36)}`
}

function getStoredUserCreateOperation(storageKey: string): StoredUserCreateOperation | null {
  try {
    const raw = globalThis.sessionStorage?.getItem(storageKey)
    if (!raw) return null
    const value: unknown = JSON.parse(raw)
    if (typeof value !== 'object' || value === null) return null
    const operation = value as Partial<StoredUserCreateOperation>
    if (
      typeof operation.nonsecretFingerprint !== 'string' ||
      operation.nonsecretFingerprint.length < 1 || operation.nonsecretFingerprint.length > 128 ||
      typeof operation.idempotencyKey !== 'string' || operation.idempotencyKey.length < 1 ||
      operation.idempotencyKey.length > 128 || !/^[\x21-\x7E]+$/.test(operation.idempotencyKey)
    ) return null
    return {
      nonsecretFingerprint: operation.nonsecretFingerprint,
      idempotencyKey: operation.idempotencyKey
    }
  } catch {
    return null
  }
}

function storeUserCreateOperation(
  storageKey: string,
  operation: StoredUserCreateOperation | null
): void {
  try {
    if (operation) globalThis.sessionStorage?.setItem(storageKey, JSON.stringify(operation))
    else globalThis.sessionStorage?.removeItem(storageKey)
  } catch {
    // The in-memory retry guard remains active when browser storage is unavailable.
  }
}

function clearUserCreateOperation(storageKey: string, idempotencyKey: string): void {
  if (pendingUserCreateOperations.get(storageKey)?.idempotencyKey === idempotencyKey) {
    pendingUserCreateOperations.delete(storageKey)
  }
  if (getStoredUserCreateOperation(storageKey)?.idempotencyKey === idempotencyKey) {
    storeUserCreateOperation(storageKey, null)
  }
}

function isDefinitiveUserCreateFailure(error: unknown): boolean {
  if (typeof error !== 'object' || error === null) return false
  const status = (error as { status?: unknown }).status
  return typeof status === 'number' && status >= 400 && status < 500 && status !== 408
}

/**
 * Update user
 * @param id - User ID
 * @param updates - Fields to update
 * @returns Updated user
 */
export async function update(id: number, updates: UpdateUserRequest): Promise<AdminUser> {
  const { data } = await apiClient.put<AdminUser>(`/admin/users/${id}`, updates)
  return data
}

/**
 * Delete user
 * @param id - User ID
 * @returns Success confirmation
 */
export async function deleteUser(id: number): Promise<{ message: string }> {
  const { data } = await apiClient.delete<{ message: string }>(`/admin/users/${id}`)
  return data
}

/**
 * Update user balance
 * @param id - User ID
 * @param balance - New balance
 * @param operation - Operation type ('set', 'add', 'subtract')
 * @param notes - Optional notes for the balance adjustment
 * @returns Updated user
 */
export async function updateBalance(
  id: number,
  balance: number,
  operation: 'set' | 'add' | 'subtract' = 'set',
  notes?: string
): Promise<AdminUser> {
  const { data } = await apiClient.post<AdminUser>(`/admin/users/${id}/balance`, {
    balance,
    operation,
    notes: notes || ''
  })
  return data
}

/**
 * Update user concurrency
 * @param id - User ID
 * @param concurrency - New concurrency limit
 * @returns Updated user
 */
export async function updateConcurrency(id: number, concurrency: number): Promise<AdminUser> {
  return update(id, { concurrency })
}

/** Overwrite concurrency and/or RPM limits for multiple users in one request. */
export async function batchUpdateLimits(
  request: BatchUpdateUserLimitsRequest
): Promise<BatchUpdateUserLimitsResponse> {
  const { data } = await apiClient.post<BatchUpdateUserLimitsResponse>(
    '/admin/users/batch-limits',
    request
  )
  return data
}

/**
 * Toggle user status
 * @param id - User ID
 * @param status - New status
 * @returns Updated user
 */
export async function toggleStatus(id: number, status: 'active' | 'disabled'): Promise<AdminUser> {
  return update(id, { status })
}

/**
 * Get user's API keys
 * @param id - User ID
 * @returns List of user's API keys
 */
export async function getUserApiKeys(id: number | string): Promise<PaginatedResponse<ApiKey>> {
  const { data } = await apiClient.get<PaginatedResponse<ApiKey>>(`/admin/users/${id}/api-keys`)
  return data
}

/**
 * Get user's usage statistics
 * @param id - User ID
 * @param period - Time period
 * @returns User usage statistics
 */
export async function getUserUsageStats(
  id: number,
  period: string = 'month'
): Promise<{
  total_requests: number
  total_cost: number
  total_tokens: number
}> {
  const { data } = await apiClient.get<{
    total_requests: number
    total_cost: number
    total_tokens: number
  }>(`/admin/users/${id}/usage`, {
    params: { period }
  })
  return data
}

/**
 * Balance history item returned from the API
 */
export interface BalanceHistoryItem {
  id: number
  code: string
  type: string
  value: number
  status: string
  used_by: number | null
  used_at: string | null
  created_at: string
  group_id: number | null
  validity_days: number
  notes: string
  user?: { id: number; email: string } | null
  group?: { id: number; name: string } | null
}

// Balance history response extends pagination with total_recharged summary
export interface BalanceHistoryResponse extends PaginatedResponse<BalanceHistoryItem> {
  total_recharged: number
}

/**
 * Get user's balance/concurrency change history
 * @param id - User ID
 * @param page - Page number
 * @param pageSize - Items per page
 * @param type - Optional type filter (balance, affiliate_balance, admin_balance, concurrency, admin_concurrency, subscription)
 * @returns Paginated balance history with total_recharged
 */
export async function getUserBalanceHistory(
  id: number,
  page: number = 1,
  pageSize: number = 20,
  type?: string
): Promise<BalanceHistoryResponse> {
  const params: Record<string, any> = { page, page_size: pageSize }
  if (type) params.type = type
  const { data } = await apiClient.get<BalanceHistoryResponse>(
    `/admin/users/${id}/balance-history`,
    { params }
  )
  return data
}

/**
 * Replace user's exclusive group
 * @param userId - User ID
 * @param oldGroupId - Current group ID to replace
 * @param newGroupId - New group ID to replace with
 * @returns Number of migrated keys
 */
export async function replaceGroup(
  userId: number,
  oldGroupId: number,
  newGroupId: number
): Promise<{ migrated_keys: number }> {
  const { data } = await apiClient.post<{ migrated_keys: number }>(
    `/admin/users/${userId}/replace-group`,
    { old_group_id: oldGroupId, new_group_id: newGroupId }
  )
  return data
}

export async function bindUserAuthIdentity(
  userId: number,
  input: AdminBindAuthIdentityRequest
): Promise<AdminBoundAuthIdentity> {
  const { data } = await apiClient.post<AdminBoundAuthIdentity>(
    `/admin/users/${userId}/auth-identities`,
    input
  )
  return data
}

/**
 * Platform quota types
 */
export type PlatformQuotaPlatform = 'anthropic' | 'openai' | 'gemini' | 'antigravity' | 'grok'
export type PlatformQuotaWindow = 'daily' | 'weekly' | 'monthly'

export interface PlatformQuotaItem {
  platform: PlatformQuotaPlatform
  daily_limit_usd: number | null
  weekly_limit_usd: number | null
  monthly_limit_usd: number | null
  daily_usage_usd: number
  weekly_usage_usd: number
  monthly_usage_usd: number
  daily_window_start?: string | null
  weekly_window_start?: string | null
  monthly_window_start?: string | null
  daily_window_resets_at?: string | null
  weekly_window_resets_at?: string | null
  monthly_window_resets_at?: string | null
}

export interface PlatformQuotaUpdateItem {
  platform: PlatformQuotaPlatform
  daily_limit_usd: number | null
  weekly_limit_usd: number | null
  monthly_limit_usd: number | null
}

export interface PlatformQuotasResponse {
  platform_quotas: PlatformQuotaItem[]
}

/**
 * Get user's platform quotas
 */
export async function getPlatformQuotas(id: number): Promise<PlatformQuotasResponse> {
  const { data } = await apiClient.get<PlatformQuotasResponse>(
    `/admin/users/${id}/platform-quotas`
  )
  return data
}

/**
 * Replace user's platform quotas (全量替换)
 */
export async function updatePlatformQuotas(
  id: number,
  quotas: PlatformQuotaUpdateItem[]
): Promise<PlatformQuotasResponse> {
  const { data } = await apiClient.put<PlatformQuotasResponse>(
    `/admin/users/${id}/platform-quotas`,
    { quotas }
  )
  return data
}

/**
 * Reset a single (platform, window) usage immediately
 */
export async function resetPlatformQuotaWindow(
  id: number,
  platform: PlatformQuotaPlatform,
  window: PlatformQuotaWindow
): Promise<PlatformQuotasResponse> {
  const { data } = await apiClient.post<PlatformQuotasResponse>(
    `/admin/users/${id}/platform-quotas/reset`,
    { platform, window }
  )
  return data
}

export const usersAPI = {
  list,
  getById,
  create,
  update,
  delete: deleteUser,
  updateBalance,
  updateConcurrency,
  batchUpdateLimits,
  toggleStatus,
  getUserApiKeys,
  getUserUsageStats,
  getUserBalanceHistory,
  replaceGroup,
  bindUserAuthIdentity,
  getPlatformQuotas,
  updatePlatformQuotas,
  resetPlatformQuotaWindow,
}

export default usersAPI
