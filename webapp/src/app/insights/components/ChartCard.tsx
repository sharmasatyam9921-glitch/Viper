'use client'

import { ReactNode } from 'react'
import styles from './ChartCard.module.css'

interface ChartCardProps {
  title: string
  subtitle?: string
  children: ReactNode
  isLoading?: boolean
  isEmpty?: boolean
  className?: string
}

export function ChartCard({ title, subtitle, children, isLoading, isEmpty, className }: ChartCardProps) {
  return (
    <div className={`card ${styles.chartCard} ${className || ''}`}>
      <div className="cardHeader">
        <div>
          <div className="cardTitle">{title}</div>
          {subtitle && <div className="cardSubtitle">{subtitle}</div>}
        </div>
      </div>
      <div className={`cardBody ${styles.chartBody}`}>
        {isLoading ? (
          <div className={styles.skeleton}>
            <div className={styles.skeletonBar} />
            <div className={styles.skeletonBar} />
            <div className={styles.skeletonBar} />
          </div>
        ) : isEmpty ? (
          <div className={styles.empty}>No data available</div>
        ) : (
          children
        )}
      </div>
    </div>
  )
}
