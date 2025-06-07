import { createContext, useContext, useEffect, useState } from 'react'
import { decodeJwt, randomString } from './utils'
import { generateCodeChallenge, generateCodeVerifier } from './pkce'

const AUTH_ENDPOINT = 'https://auth.hyperc.tr/application/o/authorize/'
const TOKEN_ENDPOINT = 'https://auth.hyperc.tr/application/o/token/'
const CLIENT_ID = 'b2fS6rmY8JzD80iVplmaBq6ylM6xzKi73nEh9TVd'
const REDIRECT_URI = 'http://localhost:5173'
const SCOPES = 'openid email profile'

export interface AuthState {
  accessToken?: string
  idToken?: string
  user?: unknown
}

interface Context {
  auth: AuthState
  login: () => Promise<void>
  logout: () => void
}

const AuthContext = createContext<Context | undefined>(undefined)

export const useAuth = (): Context => {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('AuthContext not ready')
  return ctx
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [auth, setAuth] = useState<AuthState>(() => {
    const accessToken = localStorage.getItem('access_token') ?? undefined
    const idToken = localStorage.getItem('id_token') ?? undefined
    return {
      accessToken,
      idToken,
      user: idToken ? decodeJwt(idToken) : undefined,
    }
  })

  async function login() {
    const state = randomString(16)
    const verifier = generateCodeVerifier()
    const challenge = await generateCodeChallenge(verifier)

    sessionStorage.setItem('pkce_state', state)
    sessionStorage.setItem('pkce_verifier', verifier)

    const params = new URLSearchParams({
      response_type: 'code',
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      scope: SCOPES,
      state,
      code_challenge: challenge,
      code_challenge_method: 'S256',
    })

    window.location.href = `${AUTH_ENDPOINT}?${params.toString()}`
  }

  function logout() {
    localStorage.removeItem('access_token')
    localStorage.removeItem('id_token')
    setAuth({})
  }

  async function handleRedirect() {
    const params = new URLSearchParams(window.location.search)
    const code = params.get('code')
    const state = params.get('state')
    if (!code) return
    const storedState = sessionStorage.getItem('pkce_state')
    const verifier = sessionStorage.getItem('pkce_verifier')
    sessionStorage.removeItem('pkce_state')
    sessionStorage.removeItem('pkce_verifier')
    if (!verifier || !storedState || storedState !== state) return

    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: CLIENT_ID,
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: verifier,
    })

    const res = await fetch(TOKEN_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    })

    if (!res.ok) {
      console.error('Token request failed')
      return
    }

    const tokens = await res.json()
    const { access_token, id_token } = tokens
    if (access_token) localStorage.setItem('access_token', access_token)
    if (id_token) localStorage.setItem('id_token', id_token)
    setAuth({
      accessToken: access_token,
      idToken: id_token,
      user: id_token ? decodeJwt(id_token) : undefined,
    })
    window.history.replaceState({}, '', '/')
  }

  useEffect(() => {
    handleRedirect().catch(console.error)
  }, [])

  return (
    <AuthContext.Provider value={{ auth, login, logout }}>
      {children}
    </AuthContext.Provider>
  )
}
