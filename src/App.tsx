/* eslint-disable @typescript-eslint/no-explicit-any */
import { useState } from 'react'
import { useAuth } from './auth/AuthProvider'
import reactLogo from './assets/react.svg'
import viteLogo from '/vite.svg'
import './App.css'
import { SecurePage } from './pages/SecurePage'

function App() {
  const [count, setCount] = useState(0)
  const { auth, login, logout } = useAuth()

  return (
    <>
      <div className="auth">
        {auth.user ? (
          <>
            <p>Signed in as {(auth.user as any).email ?? 'User'}</p>
            <button onClick={logout}>Logout</button>
            <SecurePage />
          </>
        ) : (
          <button onClick={login}>Login</button>
        )}
      </div>
      <div>
        <a href="https://vite.dev" target="_blank">
          <img src={viteLogo} className="logo" alt="Vite logo" />
        </a>
        <a href="https://react.dev" target="_blank">
          <img src={reactLogo} className="logo react" alt="React logo" />
        </a>
      </div>
      <h1>Vite + React</h1>
      <div className="card">
        <button onClick={() => setCount((count) => count + 1)}>
          count is {count}
        </button>
        <p>
          Edit <code>src/App.tsx</code> and save to test HMR
        </p>
      </div>
      <p className="read-the-docs">
        Click on the Vite and React logos to learn more
      </p>
    </>
  )
}

export default App
