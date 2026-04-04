'use client'

import { useState } from 'react'
import { ChevronDown, Search } from 'lucide-react'
import { Toggle } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { NodeInfoTooltip } from '../NodeInfoTooltip'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface ParamSpiderSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
}

export function ParamSpiderSection({ data, updateField }: ParamSpiderSectionProps) {
  const [isOpen, setIsOpen] = useState(false)

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Search size={16} />
          ParamSpider Parameter Discovery
          <NodeInfoTooltip section="ParamSpider" />
          <span className={styles.badgePassive}>Passive</span>
        </h2>
        <div className={styles.sectionHeaderRight}>
          <div onClick={(e) => e.stopPropagation()}>
            <Toggle
              checked={data.paramspiderEnabled}
              onChange={(checked) => updateField('paramspiderEnabled', checked)}
            />
          </div>
          <ChevronDown
            size={16}
            className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`}
          />
        </div>
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            Passive URL parameter discovery using ParamSpider. Queries the Wayback Machine for historically-documented URLs containing query parameters. Only returns parameterized URLs (with ?key=value), making results directly useful for fuzzing and vulnerability testing. Complements GAU by focusing specifically on parameter-bearing endpoints. No API keys required.
          </p>

          {data.paramspiderEnabled && (
            <>
              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Placeholder</label>
                  <input
                    type="text"
                    className="textInput"
                    value={data.paramspiderPlaceholder}
                    onChange={(e) => updateField('paramspiderPlaceholder', e.target.value || 'FUZZ')}
                  />
                  <span className={styles.fieldHint}>Replacement value for parameter values (e.g., FUZZ for fuzzing tools)</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Timeout (seconds)</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.paramspiderTimeout}
                    onChange={(e) => updateField('paramspiderTimeout', parseInt(e.target.value) || 120)}
                    min={10}
                  />
                  <span className={styles.fieldHint}>Per-domain query timeout</span>
                </div>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  )
}
