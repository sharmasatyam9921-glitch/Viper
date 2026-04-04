'use client'

import { Swords, CheckCircle, XCircle, Footprints } from 'lucide-react'
import { ChartCard } from './ChartCard'
import styles from './AttackChainCards.module.css'

interface AttackChainCardsProps {
  chains: { title: string; status: string; steps: number; findings: number; failures: number }[] | undefined
  toolUsage: { tool: string; uses: number; successes: number }[] | undefined
  isLoading: boolean
}

export function AttackChainCards({ chains, toolUsage, isLoading }: AttackChainCardsProps) {
  const hasData = (chains && chains.length > 0) || (toolUsage && toolUsage.length > 0)

  return (
    <ChartCard title="Attack Chains" subtitle={`${chains?.length || 0} chains`} isLoading={isLoading} isEmpty={!hasData}>
      <div className={styles.wrapper}>
        {chains && chains.length > 0 && (
          <div className={styles.chainList}>
            {chains.map((chain, i) => (
              <div key={i} className={styles.chain}>
                <div className={styles.chainHeader}>
                  <Swords size={12} />
                  <span className={styles.chainTitle}>{chain.title}</span>
                  <span className={`${styles.statusBadge} ${styles[`status_${chain.status}`] || ''}`}>
                    {chain.status}
                  </span>
                </div>
                <div className={styles.chainStats}>
                  <span><Footprints size={11} /> {chain.steps} steps</span>
                  <span><CheckCircle size={11} /> {chain.findings} findings</span>
                  <span><XCircle size={11} /> {chain.failures} failures</span>
                </div>
              </div>
            ))}
          </div>
        )}
        {toolUsage && toolUsage.length > 0 && (() => {
          const maxUses = Math.max(...toolUsage.map(t => t.uses))
          return (
          <div className={styles.toolList}>
            <div className={styles.toolHeader}>Tool Usage</div>
            {toolUsage.map((t) => (
              <div key={t.tool} className={styles.toolRow}>
                <span className={styles.toolName}>{t.tool}</span>
                <div className={styles.toolBar}>
                  <div
                    className={styles.toolBarFill}
                    style={{ width: `${(t.uses / maxUses) * 100}%`, opacity: t.successes === t.uses ? 1 : undefined, background: t.successes < t.uses ? 'var(--status-warning)' : undefined }}
                  />
                </div>
                <span className={styles.toolCount}>{t.successes < t.uses ? `${t.successes}/${t.uses}` : t.uses}</span>
              </div>
            ))}
          </div>
          )
        })()}
      </div>
    </ChartCard>
  )
}
