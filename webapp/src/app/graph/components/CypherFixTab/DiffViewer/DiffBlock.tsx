'use client'

import { memo, useMemo } from 'react'
import { DiffLine } from './DiffLine'
import { FileHeader } from './FileHeader'
import { BlockActions } from './BlockActions'
import type { DiffBlockPayload } from '@/lib/cypherfix-types'
import styles from './DiffBlock.module.css'

interface DiffBlockProps {
  block: DiffBlockPayload
  index: number
  total: number
  onAccept: (blockId: string) => void
  onReject: (blockId: string, reason?: string) => void
}

export const DiffBlock = memo(function DiffBlock({
  block,
  index,
  total,
  onAccept,
  onReject,
}: DiffBlockProps) {
  // Parse context + old/new into renderable lines
  const { oldLines, newLines } = useMemo(() => {
    const contextBeforeLines = block.context_before
      ? block.context_before.split('\n').filter(l => l !== '')
      : []
    const contextAfterLines = block.context_after
      ? block.context_after.split('\n').filter(l => l !== '')
      : []
    const oldCodeLines = block.old_code ? block.old_code.split('\n') : []
    const newCodeLines = block.new_code ? block.new_code.split('\n') : []

    const ctxCount = contextBeforeLines.length
    const startLine = Math.max(1, block.start_line - ctxCount)

    // Old pane
    const old: Array<{ lineNumber: number; content: string; type: 'addition' | 'deletion' | 'context' }> = []
    contextBeforeLines.forEach((line, i) => {
      old.push({ lineNumber: startLine + i, content: line, type: 'context' })
    })
    oldCodeLines.forEach((line, i) => {
      old.push({ lineNumber: block.start_line + i, content: line, type: 'deletion' })
    })
    contextAfterLines.forEach((line, i) => {
      old.push({ lineNumber: block.end_line + 1 + i, content: line, type: 'context' })
    })

    // New pane
    const newL: Array<{ lineNumber: number; content: string; type: 'addition' | 'deletion' | 'context' }> = []
    contextBeforeLines.forEach((line, i) => {
      newL.push({ lineNumber: startLine + i, content: line, type: 'context' })
    })
    newCodeLines.forEach((line, i) => {
      newL.push({ lineNumber: block.start_line + i, content: line, type: 'addition' })
    })
    contextAfterLines.forEach((line, i) => {
      newL.push({
        lineNumber: block.start_line + newCodeLines.length + i,
        content: line,
        type: 'context',
      })
    })

    return { oldLines: old, newLines: newL }
  }, [block])

  return (
    <div className={styles.block}>
      <FileHeader filePath={block.file_path} language={block.language} />

      {/* Block info bar */}
      <div className={styles.infoBar}>
        <span className={styles.blockIndex}>Block {index + 1} of {total}</span>
        <span className={styles.lineRange}>
          Lines {block.start_line}-{block.end_line}
        </span>
        {block.description && (
          <span className={styles.blockDesc}>{block.description}</span>
        )}
      </div>

      {/* Split pane diff */}
      <div className={styles.splitPane}>
        <div className={styles.pane}>
          <div className={styles.paneHeader}>OLD</div>
          <div className={styles.paneContent}>
            {oldLines.map((line, i) => (
              <DiffLine
                key={`old-${i}`}
                lineNumber={line.lineNumber}
                content={line.content}
                type={line.type}
              />
            ))}
          </div>
        </div>
        <div className={styles.paneDivider} />
        <div className={styles.pane}>
          <div className={styles.paneHeader}>NEW</div>
          <div className={styles.paneContent}>
            {newLines.map((line, i) => (
              <DiffLine
                key={`new-${i}`}
                lineNumber={line.lineNumber}
                content={line.content}
                type={line.type}
              />
            ))}
          </div>
        </div>
      </div>

      {/* Actions */}
      <BlockActions
        blockId={block.block_id}
        status={block.status}
        onAccept={onAccept}
        onReject={onReject}
      />
    </div>
  )
})
