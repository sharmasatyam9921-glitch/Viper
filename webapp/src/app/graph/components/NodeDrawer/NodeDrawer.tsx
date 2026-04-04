'use client'

import { useState } from 'react'
import { AlertTriangle } from 'lucide-react'
import { Drawer } from '@/components/ui'
import { GraphNode } from '../../types'
import { getNodeColor } from '../../utils'
import { formatPropertyValue } from '../../utils/formatters'
import styles from './NodeDrawer.module.css'

interface NodeDrawerProps {
  node: GraphNode | null
  isOpen: boolean
  onClose: () => void
  onDeleteNode?: (nodeId: string) => Promise<void>
}

export function NodeDrawer({ node, isOpen, onClose, onDeleteNode }: NodeDrawerProps) {
  const [isDeleting, setIsDeleting] = useState(false)
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false)

  const handleDeleteClick = () => {
    setShowDeleteConfirm(true)
  }

  const handleDeleteConfirm = async () => {
    if (!node || !onDeleteNode) return
    setIsDeleting(true)
    try {
      await onDeleteNode(node.id)
      setShowDeleteConfirm(false)
      onClose()
    } finally {
      setIsDeleting(false)
    }
  }

  const handleDeleteCancel = () => {
    setShowDeleteConfirm(false)
  }

  // Filter out internal IDs and sort with timestamps at the bottom
  const hiddenKeys = ['project_id', 'user_id']
  const sortedProperties = node
    ? Object.entries(node.properties || {})
        .filter(([key]) => !hiddenKeys.includes(key))
        .sort(([a], [b]) => {
          const bottomKeys = ['created_at', 'updated_at']
          const aIsBottom = bottomKeys.includes(a)
          const bIsBottom = bottomKeys.includes(b)
          if (aIsBottom && !bIsBottom) return 1
          if (!aIsBottom && bIsBottom) return -1
          if (aIsBottom && bIsBottom) return bottomKeys.indexOf(a) - bottomKeys.indexOf(b)
          return 0
        })
    : []

  return (
    <Drawer
      isOpen={isOpen}
      onClose={onClose}
      position="left"
      mode="overlay"
      title={node ? `${node.type}: ${node.name}` : undefined}
    >
      {node && (
        <>
          <div className={styles.section}>
            <div className={styles.sectionHeader}>
              <h3 className={styles.sectionTitleBasicInfo}>Basic Info</h3>
              {node.type !== 'Domain' && node.type !== 'Subdomain' && onDeleteNode && (
                <button
                  className={styles.deleteButton}
                  onClick={handleDeleteClick}
                  disabled={isDeleting}
                  title="Delete node"
                >
                  {isDeleting ? '...' : '\uD83D\uDDD1'}
                </button>
              )}
            </div>
            <div className={styles.propertyRow}>
              <span className={styles.propertyKey}>Type</span>
              <span
                className={styles.propertyBadge}
                style={{ backgroundColor: getNodeColor(node) }}
              >
                {node.type}
              </span>
            </div>
            <div className={styles.propertyRow}>
              <span className={styles.propertyKey}>ID</span>
              <span className={styles.propertyValue}>{node.id}</span>
            </div>
            <div className={styles.propertyRow}>
              <span className={styles.propertyKey}>Name</span>
              <span className={styles.propertyValue}>{node.name}</span>
            </div>
          </div>

          <div className={styles.section}>
            <h3 className={styles.sectionTitleProperties}>Properties</h3>
            {sortedProperties.map(([key, value]) => (
              <div key={key} className={styles.propertyRow}>
                <span className={styles.propertyKey}>{key}</span>
                <span className={styles.propertyValue}>
                  {formatPropertyValue(value)}
                </span>
              </div>
            ))}
            {sortedProperties.length === 0 && (
              <p className={styles.emptyProperties}>No additional properties</p>
            )}
          </div>

          {/* Delete confirmation modal */}
          {showDeleteConfirm && (
            <div className={styles.confirmOverlay} onClick={handleDeleteCancel}>
              <div className={styles.confirmModal} onClick={(e) => e.stopPropagation()}>
                <div className={styles.confirmIcon}>
                  <AlertTriangle size={28} />
                </div>
                <h4 className={styles.confirmTitle}>Delete Node</h4>
                <p className={styles.confirmText}>
                  Deleting <strong>{node.type}: {node.name}</strong> will permanently remove
                  this node and all its relationships from the graph.
                </p>
                <p className={styles.confirmWarning}>
                  This may break the connectivity of the graph and affect
                  the agent&apos;s ability to interpret the attack chain context.
                </p>
                <div className={styles.confirmActions}>
                  <button
                    className={styles.confirmCancelBtn}
                    onClick={handleDeleteCancel}
                  >
                    Cancel
                  </button>
                  <button
                    className={styles.confirmDeleteBtn}
                    onClick={handleDeleteConfirm}
                    disabled={isDeleting}
                  >
                    {isDeleting ? 'Deleting...' : 'Delete'}
                  </button>
                </div>
              </div>
            </div>
          )}
        </>
      )}
    </Drawer>
  )
}
