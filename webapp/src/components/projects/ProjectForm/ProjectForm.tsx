'use client'

import { useState, useEffect, useCallback } from 'react'
import { Save, X, Loader2, AlertTriangle, Download, ShieldAlert, Zap, Bookmark, FolderOpen } from 'lucide-react'
import type { Project } from '@prisma/client'
import { validateProjectForm } from '@/lib/validation'
import { isHardBlockedDomain } from '@/lib/hard-guardrail'
import { useProject } from '@/providers/ProjectProvider'
import { useAlertModal, useToast } from '@/components/ui'
import styles from './ProjectForm.module.css'

// Import sections
import { TargetSection } from './sections/TargetSection'
import { ScanModulesSection } from './sections/ScanModulesSection'
import { NaabuSection } from './sections/NaabuSection'
import { MasscanSection } from './sections/MasscanSection'
import { NmapSection } from './sections/NmapSection'
import { HttpxSection } from './sections/HttpxSection'
import { NucleiSection } from './sections/NucleiSection'
import { KatanaSection } from './sections/KatanaSection'
import { HakrawlerSection } from './sections/HakrawlerSection'
import { JsluiceSection } from './sections/JsluiceSection'
import { FfufSection } from './sections/FfufSection'
import { GauSection } from './sections/GauSection'
import { ParamSpiderSection } from './sections/ParamSpiderSection'
import { KiterunnerSection } from './sections/KiterunnerSection'
import { ArjunSection } from './sections/ArjunSection'
import { CveLookupSection } from './sections/CveLookupSection'
import { MitreSection } from './sections/MitreSection'
import { SecurityChecksSection } from './sections/SecurityChecksSection'
import { GithubSection } from './sections/GithubSection'
import { TrufflehogSection } from './sections/TrufflehogSection'
import { AgentBehaviourSection } from './sections/AgentBehaviourSection'
import { AttackSkillsSection } from './sections/AttackSkillsSection'
import { ShodanSection } from './sections/ShodanSection'
import { UrlscanSection } from './sections/UrlscanSection'
import { SubdomainDiscoverySection } from './sections/SubdomainDiscoverySection'
import { ToolMatrixSection } from './sections/ToolMatrixSection'
import { GvmScanSection } from './sections/GvmScanSection'
import { CypherFixSettingsSection } from './sections/CypherFixSettingsSection'
import { RoeSection } from './sections/RoeSection'
import { OsintEnrichmentSection } from './sections/OsintEnrichmentSection'
import { JsReconSection } from './sections/JsReconSection'
import { ReconPresetModal } from './ReconPresetModal'
import { SavePresetModal } from './SavePresetModal'
import { UserPresetDrawer } from './UserPresetDrawer'
import { getPresetById, type ReconPreset } from '@/lib/recon-presets'

type ProjectFormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface ConflictResult {
  hasConflict: boolean
  conflictType: 'full_scan_exists' | 'full_scan_requested' | 'subdomain_overlap' | null
  conflictingProject: {
    id: string
    name: string
    targetDomain: string
    subdomainList: string[]
  } | null
  overlappingSubdomains: string[]
  message: string | null
}

interface ProjectFormProps {
  initialData?: Partial<ProjectFormData> & { id?: string }
  onSubmit: (data: ProjectFormData & { roeFile?: File | null }) => Promise<void>
  onCancel: () => void
  isSubmitting?: boolean
  mode: 'create' | 'edit'
  /** When set (e.g. from /projects/[id]/settings URL), ensures child sections always get a stable project id */
  projectIdFromRoute?: string
}

const TAB_GROUPS = [
  {
    label: 'Scope',
    style: 'tabGroupScope',
    tabs: [
      { id: 'roe', label: 'RoE' },
    ],
  },
  {
    label: 'Recon Pipeline',
    style: 'tabGroupRecon',
    tabs: [
      { id: 'preset', label: 'Recon Preset' },
      { id: 'target', label: 'Target & Modules' },
      { id: 'discovery', label: 'Discovery & OSINT' },
      { id: 'port', label: 'Port Scanning' },
      { id: 'http', label: 'HTTP Probing' },
      { id: 'resource', label: 'Resource Enum' },
      { id: 'jsrecon', label: 'JS Recon' },
      { id: 'vuln', label: 'Vulnerability Scanning' },
      { id: 'cve', label: 'CVE & MITRE' },
      { id: 'security', label: 'Security Checks' },
    ],
  },
  {
    label: '',
    style: 'tabGroupOther',
    tabs: [
      { id: 'integrations', label: 'Other Scans', wide: true },
    ],
  },
  {
    label: 'AI Agent',
    style: 'tabGroupAgent',
    tabs: [
      { id: 'agent', label: 'Agent Behaviour' },
      { id: 'toolmatrix', label: 'Tool Matrix' },
      { id: 'attack', label: 'Agent Skills' },
    ],
  },
  {
    label: 'Remediation',
    style: 'tabGroupRemediation',
    tabs: [
      { id: 'cypherfix', label: 'CypherFix' },
    ],
  },
] as const

type TabId = typeof TAB_GROUPS[number]['tabs'][number]['id']

// Minimal fallback defaults - only required fields
// Full defaults are fetched from /api/projects/defaults (served by recon backend)
const MINIMAL_DEFAULTS: Partial<ProjectFormData> = {
  name: '',
  description: '',
  targetDomain: '',
  subdomainList: [],
  ipMode: false,
  targetIps: [],
  scanModules: ['domain_discovery', 'port_scan', 'http_probe', 'resource_enum', 'vuln_scan'],
}

// Fetch defaults from the recon backend (single source of truth)
async function fetchDefaults(): Promise<Partial<ProjectFormData>> {
  try {
    const response = await fetch('/api/projects/defaults')
    if (!response.ok) {
      console.warn('Failed to fetch defaults, using minimal fallback')
      return MINIMAL_DEFAULTS
    }
    const defaults = await response.json()
    // Merge with minimal defaults to ensure required fields exist
    return { ...MINIMAL_DEFAULTS, ...defaults }
  } catch (error) {
    console.warn('Error fetching defaults:', error)
    return MINIMAL_DEFAULTS
  }
}

export function ProjectForm({
  initialData,
  onSubmit,
  onCancel,
  isSubmitting = false,
  mode,
  projectIdFromRoute,
}: ProjectFormProps) {
  const { alertError, alertWarning } = useAlertModal()
  const toast = useToast()
  const [activeTab, setActiveTab] = useState<TabId>('target')
  const [isLoadingDefaults, setIsLoadingDefaults] = useState(mode === 'create')
  const [formData, setFormData] = useState<ProjectFormData>(() => ({
    ...MINIMAL_DEFAULTS,
    ...initialData
  } as ProjectFormData))

  // Recon Preset
  const [isPresetModalOpen, setIsPresetModalOpen] = useState(false)
  const [appliedPreset, setAppliedPreset] = useState<ReconPreset | null>(() => {
    if (initialData?.reconPresetId) {
      return getPresetById(initialData.reconPresetId as string) ?? null
    }
    return null
  })

  // User Presets
  const [isSavePresetModalOpen, setIsSavePresetModalOpen] = useState(false)
  const [isUserPresetDrawerOpen, setIsUserPresetDrawerOpen] = useState(false)

  // Domain conflict checking
  const [conflict, setConflict] = useState<ConflictResult | null>(null)
  const [isCheckingConflict, setIsCheckingConflict] = useState(false)

  // Guardrail block modal
  const [guardrailError, setGuardrailError] = useState<string | null>(null)

  // RoE document file (held in memory until project creation)
  const [roeFile, setRoeFile] = useState<File | null>(null)

  // GitHub Access Token check (stored in Global Settings, not project)
  const { userId } = useProject()
  const [hasGithubToken, setHasGithubToken] = useState(false)

  useEffect(() => {
    if (!userId) return
    fetch(`/api/users/${userId}/settings`)
      .then(r => r.ok ? r.json() : null)
      .then(settings => {
        if (settings) setHasGithubToken(!!settings.githubAccessToken)
      })
      .catch(() => setHasGithubToken(false))
  }, [userId])

  // Prefer URL param on settings page so wordlist upload etc. always get a real id.
  // In create mode, generate a stable ID upfront so uploads (JS Recon, FFuf wordlists)
  // can use it immediately — the same ID is sent to the backend on save.
  const [generatedId] = useState(() =>
    typeof crypto !== 'undefined' && crypto.randomUUID ? crypto.randomUUID().replace(/-/g, '').slice(0, 25) : ''
  )
  const projectId =
    projectIdFromRoute ?? (initialData as { id?: string } | undefined)?.id ?? (mode === 'create' ? generatedId : undefined)

  // Check for domain conflicts (IP mode skips — tenant-scoped constraints allow overlap)
  const checkConflict = useCallback(async () => {
    // No conflict check needed for IP mode
    if (formData.ipMode) {
      setConflict(null)
      return
    }

    if (!(formData.targetDomain || '').trim()) {
      setConflict(null)
      return
    }

    setIsCheckingConflict(true)
    try {
      const response = await fetch('/api/projects/check-conflict', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targetDomain: formData.targetDomain || '',
          subdomainList: formData.subdomainList || [],
          ipMode: false,
          excludeProjectId: mode === 'edit' ? projectId : undefined,
        }),
      })

      if (response.ok) {
        const result: ConflictResult = await response.json()
        setConflict(result.hasConflict ? result : null)
      }
    } catch (error) {
      console.error('Failed to check conflict:', error)
    } finally {
      setIsCheckingConflict(false)
    }
  }, [formData.targetDomain, formData.subdomainList, formData.ipMode, mode, projectId])

  // Debounced conflict check when form data changes
  useEffect(() => {
    const timer = setTimeout(() => {
      checkConflict()
    }, 500)

    return () => clearTimeout(timer)
  }, [checkConflict])

  // Fetch defaults from backend on mount (only for create mode)
  useEffect(() => {
    if (mode === 'create') {
      fetchDefaults().then(defaults => {
        setFormData(prev => ({ ...defaults, ...prev, ...initialData } as ProjectFormData))
        setIsLoadingDefaults(false)
      })
    }
  }, [mode, initialData])

  const updateField = <K extends keyof ProjectFormData>(
    field: K,
    value: ProjectFormData[K]
  ) => {
    setFormData(prev => ({ ...prev, [field]: value }))
  }

  const updateMultipleFields = (fields: Partial<ProjectFormData>) => {
    setFormData(prev => ({ ...prev, ...fields }))
  }

  const applyPreset = useCallback(async (preset: ReconPreset) => {
    // Only apply the preset's own parameters (recon pipeline fields only).
    // User-entered fields (name, targetDomain, etc.) are preserved because
    // preset.parameters only contains recon-relevant keys.
    setFormData(prev => ({ ...prev, ...preset.parameters }))
    setAppliedPreset(preset)
    setIsPresetModalOpen(false)
    toast.success(`Recon preset "${preset.name}" applied`, 'Preset Applied')
  }, [toast])

  const handleLoadUserPreset = useCallback((settings: Record<string, unknown>) => {
    setFormData(prev => ({ ...prev, ...settings } as ProjectFormData))
    // Sync recon preset badge
    if (settings.reconPresetId) {
      setAppliedPreset(getPresetById(settings.reconPresetId as string) ?? null)
    } else {
      setAppliedPreset(null)
    }
  }, [])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    if (!formData.name.trim()) {
      alertWarning('Project name is required')
      return
    }

    if (!formData.ipMode && !formData.targetDomain.trim()) {
      alertWarning('Target domain is required')
      return
    }

    // Run field validation
    const validationErrors = validateProjectForm(formData as unknown as Record<string, unknown>)
    if (validationErrors.length > 0) {
      alertWarning('Validation errors:\n' + validationErrors.map(e => `- ${e.message}`).join('\n'))
      return
    }

    // Hard guardrail: block government/public domains before hitting API
    if (!formData.ipMode && formData.targetDomain) {
      const hardCheck = isHardBlockedDomain(formData.targetDomain)
      if (hardCheck.blocked) {
        setGuardrailError(hardCheck.reason)
        return
      }
    }

    // Block submission if there's a conflict
    if (conflict?.hasConflict) {
      alertError('Cannot save project: ' + conflict.message)
      return
    }

    try {
      // Attach roeFile and pre-generated ID to form data for submission
      const submitData = {
        ...formData,
        reconPresetId: appliedPreset?.id ?? formData.reconPresetId ?? null,
        ...(roeFile ? { roeFile } : {}),
        ...(mode === 'create' && projectId ? { id: projectId } : {}),
      }
      await onSubmit(submitData)
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to save project'
      if (message.toLowerCase().includes('guardrail') || message.toLowerCase().includes('permanently blocked')) {
        // Extract the reason from guardrail error messages
        const reason = message
          .replace(/^Target blocked by guardrail:\s*/i, '')
          .replace(/^Target permanently blocked:\s*/i, '')
        setGuardrailError(reason || message)
      } else {
        alertError(message)
      }
    }
  }

  // Determine if form can be submitted
  const canSubmit = !isSubmitting && !isLoadingDefaults && !conflict?.hasConflict && !isCheckingConflict

  return (
    <form onSubmit={handleSubmit} className={styles.form}>
      <div className={styles.header}>
        <h1 className={styles.title}>
          {mode === 'create' ? 'Create New Project' : 'Project Settings'}
          {appliedPreset && (
            <span className={styles.presetBadge}>Started from: {appliedPreset.name}</span>
          )}
        </h1>
        <div className={styles.actions}>
          <button
            type="button"
            className="secondaryButton"
            onClick={onCancel}
            disabled={isSubmitting}
            title="Discard all unsaved changes and return to the previous page"
          >
            <X size={14} />
            Cancel
          </button>
          <button
            type="button"
            className="secondaryButton"
            onClick={() => setIsUserPresetDrawerOpen(true)}
            disabled={isSubmitting || isLoadingDefaults}
            title="Load a previously saved preset to apply all its settings to this project (target and subdomain fields are preserved)"
          >
            <FolderOpen size={14} />
            Load Preset
          </button>
          <button
            type="button"
            className="secondaryButton"
            onClick={() => setIsSavePresetModalOpen(true)}
            disabled={isSubmitting || isLoadingDefaults}
            title="Save the current project settings as a reusable preset (everything except target domain, subdomains, and IP list)"
          >
            <Bookmark size={14} />
            Save as Preset
          </button>
          {mode === 'edit' && projectId && (
            <button
              type="button"
              className="secondaryButton"
              onClick={() => window.open(`/api/projects/${projectId}/export`)}
              title="Download a full project backup as a ZIP file including settings, conversations, graph data, reports, and artifacts"
            >
              <Download size={14} />
              Export
            </button>
          )}
          <button
            type="submit"
            className="primaryButton"
            disabled={!canSubmit}
            title={mode === 'create' ? 'Create the project with the current settings and start working' : 'Save all changes to the project settings'}
          >
            {isLoadingDefaults ? (
              <>
                <Loader2 size={14} className={styles.spinner} />
                Loading...
              </>
            ) : isCheckingConflict ? (
              <>
                <Loader2 size={14} className={styles.spinner} />
                Checking...
              </>
            ) : (
              <>
                <Save size={14} />
                {isSubmitting ? 'Saving...' : 'Save Project'}
              </>
            )}
          </button>
        </div>
      </div>

      {/* Domain conflict warning banner */}
      {conflict?.hasConflict && (
        <div className={styles.conflictBanner}>
          <AlertTriangle size={20} className={styles.conflictIcon} />
          <div className={styles.conflictContent}>
            <div className={styles.conflictTitle}>Domain Conflict Detected</div>
            <div className={styles.conflictMessage}>{conflict.message}</div>
            {conflict.conflictingProject && (
              <div className={styles.conflictProject}>
                Conflicting project: <strong>{conflict.conflictingProject.name}</strong>
                {conflict.overlappingSubdomains.length > 0 && (
                  <> (subdomains: {conflict.overlappingSubdomains.join(', ')})</>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {isLoadingDefaults ? (
        <div className={styles.loadingContainer}>
          <Loader2 size={24} className={styles.spinner} />
          <p>Loading configuration defaults...</p>
        </div>
      ) : (
        <>
          <div className={styles.tabs}>
            {TAB_GROUPS.map((group, gi) => (
              <div key={gi} className={group.style ? styles[group.style] : styles.tabGroup}>
                {group.label && (
                  <span className={styles.tabGroupLabel}>{group.label}</span>
                )}
                <div className={styles.tabGroupTabs}>
                  {group.tabs.map(tab => (
                    <button
                      key={tab.id}
                      type="button"
                      className={`tab ${activeTab === tab.id ? 'tabActive' : ''} ${styles.compactTab} ${'wide' in tab && tab.wide ? styles.wideTab : ''} ${tab.id === 'preset' ? styles.presetTab : ''}`}
                      onClick={() => {
                        if (tab.id === 'preset') {
                          setIsPresetModalOpen(true)
                        } else {
                          setActiveTab(tab.id)
                        }
                      }}
                    >
                      {tab.id === 'preset' && <Zap size={15} className={styles.presetIcon} />}
                      {tab.label}
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>

          <div className={styles.content}>
            {activeTab === 'roe' && (
          <RoeSection
            data={formData}
            updateField={updateField}
            updateMultipleFields={updateMultipleFields}
            mode={mode}
            onFileSelected={setRoeFile}
          />
        )}

        {activeTab === 'target' && (
          <>
            <TargetSection data={formData} updateField={updateField} mode={mode} />
            <ScanModulesSection data={formData} updateField={updateField} />
          </>
        )}

        {activeTab === 'discovery' && (
          <>
            <SubdomainDiscoverySection data={formData} updateField={updateField} />
            <ShodanSection data={formData} updateField={updateField} />
            <UrlscanSection data={formData} updateField={updateField} />
            <OsintEnrichmentSection data={formData} updateField={updateField} />
          </>
        )}

        {activeTab === 'port' && (
          <>
            {!formData.naabuEnabled && !formData.masscanEnabled && (
              <div className={styles.shodanWarning}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                <span>Both port scanners are disabled. The recon pipeline will skip port scanning entirely &mdash; downstream modules (HTTP probe, vulnerability scanning) require open ports to function and will produce no results.</span>
              </div>
            )}
            <NaabuSection data={formData} updateField={updateField} />
            <NmapSection data={formData} updateField={updateField} />
            <MasscanSection data={formData} updateField={updateField} />
          </>
        )}

        {activeTab === 'http' && (
          <HttpxSection data={formData} updateField={updateField} />
        )}

        {activeTab === 'resource' && (
          <>
            <KatanaSection data={formData} updateField={updateField} />
            <HakrawlerSection data={formData} updateField={updateField} />
            <JsluiceSection data={formData} updateField={updateField} />
            <FfufSection data={formData} updateField={updateField} projectId={projectId} mode={mode} />
            <GauSection data={formData} updateField={updateField} />
            <ParamSpiderSection data={formData} updateField={updateField} />
            <KiterunnerSection data={formData} updateField={updateField} />
            <ArjunSection data={formData} updateField={updateField} />
          </>
        )}

        {activeTab === 'jsrecon' && (
          <JsReconSection data={formData} updateField={updateField} projectId={projectId} mode={mode} />
        )}

        {activeTab === 'vuln' && (
          <NucleiSection data={formData} updateField={updateField} />
        )}

        {activeTab === 'cve' && (
          <>
            <CveLookupSection data={formData} updateField={updateField} />
            <MitreSection data={formData} updateField={updateField} />
          </>
        )}

        {activeTab === 'security' && (
          <SecurityChecksSection data={formData} updateField={updateField} />
        )}

        {activeTab === 'integrations' && (
          <>
            <GvmScanSection data={formData} updateField={updateField} />
            <GithubSection data={formData} updateField={updateField} hasGithubToken={hasGithubToken} />
            <TrufflehogSection data={formData} updateField={updateField} hasGithubToken={hasGithubToken} />
          </>
        )}

        {activeTab === 'agent' && (
          <AgentBehaviourSection data={formData} updateField={updateField} />
        )}

        {activeTab === 'toolmatrix' && (
          <ToolMatrixSection data={formData} updateField={updateField} />
        )}

        {activeTab === 'attack' && (
          <AttackSkillsSection data={formData} updateField={updateField} />
        )}

        {activeTab === 'cypherfix' && (
          <CypherFixSettingsSection data={formData} updateField={updateField} />
        )}
          </div>
        </>
      )}

      {/* Recon Preset modal */}
      <ReconPresetModal
        isOpen={isPresetModalOpen}
        onClose={() => setIsPresetModalOpen(false)}
        onSelect={applyPreset}
        onLoadUserPreset={handleLoadUserPreset}
        currentPresetId={appliedPreset?.id}
        userId={userId}
        model={(formData.agentOpenaiModel as string) || 'claude-opus-4-6'}
      />

      {/* User Preset: Save modal */}
      <SavePresetModal
        isOpen={isSavePresetModalOpen}
        onClose={() => setIsSavePresetModalOpen(false)}
        formData={formData as unknown as Record<string, unknown>}
        userId={userId}
      />

      {/* User Preset: Load drawer */}
      <UserPresetDrawer
        isOpen={isUserPresetDrawerOpen}
        onClose={() => setIsUserPresetDrawerOpen(false)}
        onLoad={handleLoadUserPreset}
        userId={userId}
      />

      {/* Guardrail block modal */}
      {guardrailError && (
        <div className={styles.guardrailOverlay} onClick={() => setGuardrailError(null)}>
          <div className={styles.guardrailModal} onClick={(e) => e.stopPropagation()}>
            <div className={styles.guardrailIconWrapper}>
              <ShieldAlert size={32} />
            </div>
            <h2 className={styles.guardrailTitle}>Target Blocked</h2>
            <p className={styles.guardrailMessage}>{guardrailError}</p>
            <p className={styles.guardrailHint}>
              This target appears to be a well-known public service that you are unlikely authorized to test.
              Please use a domain or IP range you own or have explicit permission to scan.
            </p>
            <button
              type="button"
              className={styles.guardrailButton}
              onClick={() => setGuardrailError(null)}
            >
              Understood
            </button>
          </div>
        </div>
      )}
    </form>
  )
}

export default ProjectForm
