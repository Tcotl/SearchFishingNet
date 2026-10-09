// 前端会话状态：路由守卫与布局共用。
// 会话凭证是后端下发的 HttpOnly Cookie，这里只缓存用户名，/api/auth/me 探测真实有效性。

let username = ''
let checked = false

export function currentUser(): string {
  return username
}

export async function ensureAuthed(): Promise<boolean> {
  if (checked) return !!username
  try {
    const resp = await fetch('/api/auth/me')
    if (resp.ok) {
      username = ((await resp.json()) as { username: string }).username
      checked = true
      return true
    }
  } catch { /* 后端不可达时按未登录处理，由页面提示 */ }
  return false
}

export function setSession(user: string): void {
  username = user
  checked = true
}

export function clearSession(): void {
  username = ''
  checked = true
}
