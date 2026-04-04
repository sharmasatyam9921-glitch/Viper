'use client'

import { useState, useEffect, useCallback } from 'react'

const SESSION_STORAGE_KEY = 'redamon-session-id'

function generateSessionId(): string {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
  let code = ''
  for (let i = 0; i < 8; i++) code += chars[Math.floor(Math.random() * chars.length)]
  return `session_${code}`
}

export function useSession() {
  const [sessionId, setSessionId] = useState<string>('')
  const [mounted, setMounted] = useState(false)

  // Initialize session on mount
  useEffect(() => {
    // Use environment variable if available, otherwise generate new session ID
    const envSessionId = process.env.NEXT_PUBLIC_SESSION_ID
    const newSessionId = envSessionId || generateSessionId()
    setSessionId(newSessionId)
    sessionStorage.setItem(SESSION_STORAGE_KEY, newSessionId)
    setMounted(true)
  }, [])

  const resetSession = useCallback(() => {
    const newSessionId = generateSessionId()
    setSessionId(newSessionId)
    sessionStorage.setItem(SESSION_STORAGE_KEY, newSessionId)
    return newSessionId
  }, [])

  const switchSession = useCallback((existingSessionId: string) => {
    setSessionId(existingSessionId)
    sessionStorage.setItem(SESSION_STORAGE_KEY, existingSessionId)
  }, [])

  return {
    sessionId,
    resetSession,
    switchSession,
    mounted,
  }
}
