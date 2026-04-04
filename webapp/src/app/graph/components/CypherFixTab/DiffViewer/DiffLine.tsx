'use client'

import { memo } from 'react'
import styles from './DiffLine.module.css'

type LineType = 'addition' | 'deletion' | 'context'

interface DiffLineProps {
  lineNumber: number
  content: string
  type: LineType
}

export const DiffLine = memo(function DiffLine({ lineNumber, content, type }: DiffLineProps) {
  const prefix = type === 'addition' ? '+' : type === 'deletion' ? '-' : ' '

  return (
    <div className={`${styles.line} ${styles[type]}`}>
      <span className={styles.lineNumber}>{lineNumber}</span>
      <span className={styles.prefix}>{prefix}</span>
      <span className={styles.content}>{content}</span>
    </div>
  )
})
