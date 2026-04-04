'use client'

import { memo, useState } from 'react'
import { Check, X, MessageSquare } from 'lucide-react'
import styles from './DiffBlock.module.css'

interface BlockActionsProps {
  blockId: string
  status: 'pending' | 'accepted' | 'rejected'
  onAccept: (blockId: string) => void
  onReject: (blockId: string, reason?: string) => void
}

export const BlockActions = memo(function BlockActions({
  blockId,
  status,
  onAccept,
  onReject,
}: BlockActionsProps) {
  const [showRejectInput, setShowRejectInput] = useState(false)
  const [rejectReason, setRejectReason] = useState('')

  if (status === 'accepted') {
    return (
      <div className={styles.actionsBar}>
        <span className={styles.acceptedLabel}>
          <Check size={14} />
          Accepted
        </span>
      </div>
    )
  }

  if (status === 'rejected') {
    return (
      <div className={styles.actionsBar}>
        <span className={styles.rejectedLabel}>
          <X size={14} />
          Rejected
        </span>
      </div>
    )
  }

  const handleReject = () => {
    if (showRejectInput) {
      onReject(blockId, rejectReason || undefined)
      setShowRejectInput(false)
      setRejectReason('')
    } else {
      setShowRejectInput(true)
    }
  }

  return (
    <div className={styles.actionsBar}>
      {showRejectInput ? (
        <div className={styles.rejectInputRow}>
          <input
            type="text"
            className={styles.rejectInput}
            placeholder="Reason for rejection (optional)"
            value={rejectReason}
            onChange={e => setRejectReason(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter') handleReject()
              if (e.key === 'Escape') setShowRejectInput(false)
            }}
            autoFocus
          />
          <button className={styles.rejectConfirmBtn} onClick={handleReject}>
            <X size={12} />
            Reject
          </button>
          <button
            className={styles.cancelBtn}
            onClick={() => setShowRejectInput(false)}
          >
            Cancel
          </button>
        </div>
      ) : (
        <>
          <button className={styles.acceptBtn} onClick={() => onAccept(blockId)}>
            <Check size={14} />
            Accept
          </button>
          <button className={styles.rejectBtn} onClick={handleReject}>
            <X size={14} />
            Reject
          </button>
        </>
      )}
    </div>
  )
})
