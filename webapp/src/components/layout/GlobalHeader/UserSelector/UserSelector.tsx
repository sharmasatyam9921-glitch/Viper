'use client'

import { useState, useRef, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { ChevronDown, User, Users } from 'lucide-react'
import { useProject } from '@/providers/ProjectProvider'
import { useUsers } from '@/hooks/useUsers'
import styles from './UserSelector.module.css'

export function UserSelector() {
  const router = useRouter()
  const [isOpen, setIsOpen] = useState(false)
  const dropdownRef = useRef<HTMLDivElement>(null)
  const { userId, setUserId, setCurrentProject } = useProject()
  const { data: users } = useUsers()

  const currentUser = users?.find(u => u.id === userId)

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  const handleSelectUser = (user: { id: string; name: string }) => {
    if (user.id !== userId) {
      setUserId(user.id)
      setCurrentProject(null)
    }
    setIsOpen(false)
  }

  const handleManageUsers = () => {
    router.push('/projects')
    setIsOpen(false)
  }

  const initials = currentUser
    ? currentUser.name.split(' ').map(w => w[0]).join('').toUpperCase().slice(0, 2)
    : '?'

  return (
    <div className={styles.container} ref={dropdownRef}>
      <button
        className={styles.trigger}
        onClick={() => setIsOpen(!isOpen)}
        title="Select User"
      >
        <div className={styles.avatar}>
          <span>{initials}</span>
        </div>
        <span className={styles.userName}>
          {currentUser?.name || 'No User'}
        </span>
        <ChevronDown size={14} className={isOpen ? styles.iconOpen : ''} />
      </button>

      {isOpen && (
        <div className={styles.dropdown}>
          <div className={styles.header}>
            <span className={styles.headerTitle}>Users</span>
          </div>

          <div className={styles.list}>
            {users && users.length > 0 ? (
              users.map((user) => (
                <button
                  key={user.id}
                  className={`${styles.item} ${userId === user.id ? styles.itemActive : ''}`}
                  onClick={() => handleSelectUser(user)}
                >
                  <div className={styles.itemAvatar}>
                    <span>{user.name.split(' ').map(w => w[0]).join('').toUpperCase().slice(0, 2)}</span>
                  </div>
                  <div className={styles.itemContent}>
                    <span className={styles.itemName}>{user.name}</span>
                    <span className={styles.itemEmail}>{user.email}</span>
                  </div>
                </button>
              ))
            ) : (
              <div className={styles.empty}>
                No users yet
              </div>
            )}
          </div>

          <div className={styles.footer}>
            <button className={styles.footerButton} onClick={handleManageUsers}>
              <Users size={12} />
              Manage Users
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

export default UserSelector
