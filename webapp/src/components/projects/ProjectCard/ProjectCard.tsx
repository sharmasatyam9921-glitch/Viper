'use client'

import { Globe, Calendar, Settings, Trash2 } from 'lucide-react'
import Link from 'next/link'
import styles from './ProjectCard.module.css'

interface ProjectCardProps {
  id: string
  name: string
  targetDomain: string
  description?: string | null
  createdAt: string
  isSelected?: boolean
  onSelect?: () => void
  onDelete?: () => void
}

export function ProjectCard({
  id,
  name,
  targetDomain,
  description,
  createdAt,
  isSelected,
  onSelect,
  onDelete
}: ProjectCardProps) {
  const formattedDate = new Date(createdAt).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric'
  })

  return (
    <div
      className={`card cardClickable ${isSelected ? 'cardSelected' : ''} ${styles.projectCard}`}
      onClick={onSelect}
    >
      <div className="cardHeader">
        <div>
          <h3 className="cardTitle">{name}</h3>
          {description && <p className="cardSubtitle">{description}</p>}
        </div>
        <div className={styles.actions}>
          <Link
            href={`/projects/${id}/settings`}
            className="iconButton"
            onClick={(e) => e.stopPropagation()}
            title="Project Settings"
          >
            <Settings size={14} />
          </Link>
          {onDelete && (
            <button
              className="iconButton"
              onClick={(e) => {
                e.stopPropagation()
                onDelete()
              }}
              title="Delete Project"
            >
              <Trash2 size={14} />
            </button>
          )}
        </div>
      </div>
      <div className="cardBody">
        <div className={styles.meta}>
          <div className={styles.metaItem}>
            <Globe size={12} />
            <span>{targetDomain || 'No target set'}</span>
          </div>
          <div className={styles.metaItem}>
            <Calendar size={12} />
            <span>{formattedDate}</span>
          </div>
        </div>
      </div>
    </div>
  )
}

export default ProjectCard
