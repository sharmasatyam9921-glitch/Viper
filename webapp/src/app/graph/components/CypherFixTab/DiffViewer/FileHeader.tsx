'use client'

import { memo } from 'react'
import { FileCode } from 'lucide-react'

interface FileHeaderProps {
  filePath: string
  language: string
}

export const FileHeader = memo(function FileHeader({ filePath, language }: FileHeaderProps) {
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        padding: '8px 12px',
        background: 'var(--bg-tertiary)',
        borderBottom: '1px solid var(--border-default)',
        fontSize: '12px',
      }}
    >
      <FileCode size={14} style={{ color: 'var(--text-tertiary)' }} />
      <span style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', fontWeight: 500 }}>
        {filePath}
      </span>
      <span
        style={{
          padding: '1px 6px',
          borderRadius: 'var(--radius-sm)',
          background: 'var(--bg-secondary)',
          color: 'var(--text-tertiary)',
          fontSize: '10px',
          fontWeight: 500,
          textTransform: 'uppercase',
        }}
      >
        {language}
      </span>
    </div>
  )
})
