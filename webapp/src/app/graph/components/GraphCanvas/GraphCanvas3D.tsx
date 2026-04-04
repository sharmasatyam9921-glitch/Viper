'use client'

import { useRef, useEffect, useCallback, useMemo } from 'react'
import dynamic from 'next/dynamic'
import { GraphData, GraphNode, GraphLink } from '../../types'
import { getNodeColor, getNodeSize, getGlowLevel } from '../../utils'
import { getLinkColor, getLinkWidth3D, getParticleCount, getParticleWidth, getParticleColor, getParticleSpeed } from '../../utils/linkHelpers'
import {
  LINK_SIZES,
  BASE_SIZES,
  BACKGROUND_COLORS,
  SELECTION_COLORS,
  CHAIN_SESSION_COLORS,
  GOAL_FINDING_COLORS,
  ANIMATION_CONFIG,
  THREE_CONFIG,
} from '../../config'
import { getPerformanceTier, TIER_CONFIG, getAdaptiveForceConfig } from '../../config/graph'
import { hasHighSeverityNodes, isGoalFinding } from '../../utils/nodeHelpers'
import { useAnimationFrame } from '../../hooks'

const ForceGraph3D = dynamic(() => import('react-force-graph-3d'), {
  ssr: false,
})

interface GraphCanvas3DProps {
  data: GraphData
  width: number
  height: number
  showLabels: boolean
  selectedNode: GraphNode | null
  onNodeClick: (node: GraphNode) => void
  isDark?: boolean
  activeChainId?: string
  themeVersion?: number
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  externalGraphRef?: React.MutableRefObject<any>
}

// ── Shared geometry for dot-level LOD (created once, never disposed) ──
let SHARED_DOT_GEO: any = null
function getSharedDotGeo() {
  if (!SHARED_DOT_GEO) {
    const THREE = require('three')
    SHARED_DOT_GEO = new THREE.SphereGeometry(1, 4, 4)
  }
  return SHARED_DOT_GEO
}

// ── Dispose all geometries + materials in a group ──
function disposeGroup(group: any) {
  group.traverse((child: any) => {
    if (child.geometry && child.geometry !== SHARED_DOT_GEO) {
      child.geometry.dispose()
    }
    if (child.material) {
      if (Array.isArray(child.material)) {
        child.material.forEach((m: any) => m.dispose())
      } else {
        child.material.dispose()
      }
    }
    // SpriteText has a dispose method for its canvas texture
    if (typeof child.dispose === 'function' && child !== group) {
      child.dispose()
    }
  })
}

// ── Build a full-detail node group ──
function buildFullDetail(
  graphNode: GraphNode,
  sphereSegments: number,
  ringSegments: number,
  enableGlow: boolean,
  enableWireframe: boolean,
  enableLabels: boolean,
  labelColor: string,
): any {
  const THREE = require('three')
  const SpriteText = require('three-spritetext').default

  const group = new THREE.Group()
  const sphereSize = BASE_SIZES.node3D * getNodeSize(graphNode)
  const nodeColor = getNodeColor(graphNode)

  const isExploit = graphNode.type === 'ExploitGvm' || graphNode.type === 'ChainFinding'
  const isChainNode = graphNode.type === 'AttackChain' || graphNode.type === 'ChainStep' || graphNode.type === 'ChainDecision' || graphNode.type === 'ChainFailure'
  const isGoal = isGoalFinding(graphNode)

  // Effective color for chain/exploit nodes (inactive state by default)
  let effectiveColor: string
  if (isChainNode || isExploit) {
    if (isGoal) {
      effectiveColor = GOAL_FINDING_COLORS.inactive
    } else if (isExploit) {
      effectiveColor = CHAIN_SESSION_COLORS.inactiveFinding
    } else {
      effectiveColor = CHAIN_SESSION_COLORS.inactive
    }
  } else {
    effectiveColor = nodeColor
  }

  // Selection ring (always created, hidden by default -- toggled via mutation)
  const selectGeometry = new THREE.RingGeometry(
    sphereSize * THREE_CONFIG.selectionRingScale.inner,
    sphereSize * THREE_CONFIG.selectionRingScale.outer,
    ringSegments
  )
  const selectMaterial = new THREE.MeshBasicMaterial({
    color: SELECTION_COLORS.ring,
    transparent: true,
    opacity: THREE_CONFIG.selectionRingOpacity,
    side: THREE.DoubleSide,
  })
  const selectRing = new THREE.Mesh(selectGeometry, selectMaterial)
  selectRing.lookAt(0, 0, 1)
  selectRing.name = 'selectionRing'
  selectRing.visible = false
  group.add(selectRing)

  // Active chain ring (always created for chain/exploit nodes, hidden by default)
  if (isChainNode || isExploit) {
    const activeGeometry = new THREE.RingGeometry(
      sphereSize * 1.8,
      sphereSize * 2.0,
      6
    )
    const activeMaterial = new THREE.MeshBasicMaterial({
      color: CHAIN_SESSION_COLORS.activeRing,
      transparent: true,
      opacity: 0.7,
      side: THREE.DoubleSide,
    })
    const activeRing = new THREE.Mesh(activeGeometry, activeMaterial)
    activeRing.lookAt(0, 0, 1)
    activeRing.name = 'chainRing'
    activeRing.visible = false
    activeRing.userData.glowLevel = 'high'
    group.add(activeRing)
  }

  // Glow ring for high/critical severity
  const glowLevel = getGlowLevel(graphNode)
  if (enableGlow && glowLevel) {
    const glowColor = (isChainNode || isExploit) ? effectiveColor : nodeColor
    const glowGeometry = new THREE.RingGeometry(
      sphereSize * THREE_CONFIG.glowRingScale.inner,
      sphereSize * THREE_CONFIG.glowRingScale.outer,
      ringSegments
    )
    const glowMaterial = new THREE.MeshBasicMaterial({
      color: glowColor,
      transparent: true,
      opacity: THREE_CONFIG.glowRingOpacity,
      side: THREE.DoubleSide,
    })
    const glowRing = new THREE.Mesh(glowGeometry, glowMaterial)
    glowRing.lookAt(0, 0, 1)
    glowRing.name = 'glowRing'
    glowRing.userData.glowLevel = glowLevel
    group.add(glowRing)
  }

  // Main geometry
  let geometry: any
  if (isExploit) {
    geometry = new THREE.OctahedronGeometry(sphereSize * 1.2)
  } else if (isChainNode) {
    geometry = new THREE.DodecahedronGeometry(sphereSize * 1.1)
  } else {
    geometry = new THREE.SphereGeometry(sphereSize, sphereSegments, sphereSegments)
  }

  const isSpecialNode = isExploit || isChainNode
  const material = isSpecialNode
    ? new THREE.MeshLambertMaterial({
        color: effectiveColor,
        transparent: true,
        opacity: 0.12,
        emissive: effectiveColor,
        emissiveIntensity: 0.3,
        side: THREE.DoubleSide,
      })
    : new THREE.MeshLambertMaterial({
        color: nodeColor,
        transparent: true,
        opacity: THREE_CONFIG.nodeOpacity,
      })
  const mesh = new THREE.Mesh(geometry, material)
  mesh.name = 'mainMesh'
  group.add(mesh)

  // Wireframe for exploit nodes
  if (enableWireframe && isExploit) {
    const wireMaterial = new THREE.MeshBasicMaterial({
      color: effectiveColor,
      wireframe: true,
      transparent: true,
      opacity: 0.6,
    })
    const wireMesh = new THREE.Mesh(geometry, wireMaterial)
    wireMesh.name = 'wireframe'
    group.add(wireMesh)
  }

  // Wireframe for external domain nodes
  if (enableWireframe && graphNode.type === 'ExternalDomain') {
    const wireMaterial = new THREE.MeshBasicMaterial({
      color: nodeColor,
      wireframe: true,
      transparent: true,
      opacity: 0.5,
    })
    const wireMesh = new THREE.Mesh(geometry, wireMaterial)
    wireMesh.name = 'wireframe'
    group.add(wireMesh)
  }

  // Edge outline for chain nodes
  if (enableWireframe && isChainNode) {
    const edges = new THREE.EdgesGeometry(geometry, 15)
    const lineMaterial = new THREE.LineBasicMaterial({
      color: effectiveColor,
      transparent: true,
      opacity: 0.7,
    })
    const lineSegments = new THREE.LineSegments(edges, lineMaterial)
    lineSegments.name = 'edgeOutline'
    group.add(lineSegments)
  }

  // Label (always created, visibility toggled via mutation)
  if (enableLabels) {
    const sprite = new SpriteText(graphNode.name)
    sprite.color = labelColor
    sprite.textHeight = BASE_SIZES.label3D
    sprite.position.y = sphereSize + BASE_SIZES.label3D
    sprite.name = 'label'
    sprite.visible = true // toggled by showLabels mutation
    group.add(sprite)
  }

  // Store node metadata for mutation lookups
  group.userData.nodeId = graphNode.id
  group.userData.nodeType = graphNode.type
  group.userData.chainId = graphNode.properties?.chain_id
  group.userData.isChainNode = isChainNode
  group.userData.isExploit = isExploit
  group.userData.isGoal = isGoal
  group.userData.nodeColor = nodeColor
  group.userData.effectiveColor = effectiveColor

  return group
}

// ── Build a medium-detail group (simple sphere + label, colored) ──
function buildMediumDetail(graphNode: GraphNode, sphereSegments: number, enableLabels: boolean, labelColor: string): any {
  const THREE = require('three')
  const SpriteText = require('three-spritetext').default
  const group = new THREE.Group()
  const sphereSize = BASE_SIZES.node3D * getNodeSize(graphNode)
  const nodeColor = getNodeColor(graphNode)
  const geometry = new THREE.SphereGeometry(sphereSize, Math.max(sphereSegments - 2, 4), Math.max(sphereSegments - 2, 4))
  const material = new THREE.MeshLambertMaterial({ color: nodeColor, transparent: true, opacity: THREE_CONFIG.nodeOpacity })
  const mesh = new THREE.Mesh(geometry, material)
  group.add(mesh)

  // Label on medium LOD too so it's visible when zoomed out
  if (enableLabels) {
    const sprite = new SpriteText(graphNode.name)
    sprite.color = labelColor
    sprite.textHeight = BASE_SIZES.label3D
    sprite.position.y = sphereSize + BASE_SIZES.label3D
    sprite.name = 'label'
    group.add(sprite)
  }

  return group
}

// ── Build a dot-level group (shared geometry) ──
function buildDot(graphNode: GraphNode): any {
  const THREE = require('three')
  const group = new THREE.Group()
  const sphereSize = BASE_SIZES.node3D * getNodeSize(graphNode) * 0.5
  const nodeColor = getNodeColor(graphNode)
  const material = new THREE.MeshBasicMaterial({ color: nodeColor })
  const mesh = new THREE.Mesh(getSharedDotGeo(), material)
  mesh.scale.set(sphereSize, sphereSize, sphereSize)
  group.add(mesh)
  return group
}

export function GraphCanvas3D({
  data,
  width,
  height,
  showLabels,
  selectedNode,
  onNodeClick,
  isDark = true,
  activeChainId,
  themeVersion = 0,
  externalGraphRef,
}: GraphCanvas3DProps) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const graphRef = useRef<any>(null)

  // Sync internal ref to external ref (for parent component access)
  useEffect(() => {
    if (externalGraphRef) externalGraphRef.current = graphRef.current
  })
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const nodeCache = useRef<Map<string, any>>(new Map())
  const prevThemeVersion = useRef(themeVersion)

  // Performance tier based on node count
  const tier = useMemo(() => getPerformanceTier(data.nodes.length), [data.nodes.length])
  const tierConfig = useMemo(() => TIER_CONFIG[tier], [tier])
  const forceConfig = useMemo(() => getAdaptiveForceConfig(data.nodes.length), [data.nodes.length])
  // Use ref for labelColor so nodeThreeObject callback doesn't change ref on theme toggle
  // (theme change is handled by the themeVersion effect which disposes + refresh())
  const labelColorRef = useRef(isDark ? BACKGROUND_COLORS.dark.label : BACKGROUND_COLORS.light.label)
  labelColorRef.current = isDark ? BACKGROUND_COLORS.dark.label : BACKGROUND_COLORS.light.label

  // Slow down zoom and rotation speed for smoother navigation
  useEffect(() => {
    const applyControls = () => {
      const controls = graphRef.current?.controls()
      if (controls) {
        controls.zoomSpeed = 0.25   // default is 1.2
        controls.rotateSpeed = 0.5  // default is 1.0
        return true
      }
      return false
    }
    if (!applyControls()) {
      // ForceGraph3D loads dynamically -- retry after it mounts
      const timer = setTimeout(applyControls, 500)
      return () => clearTimeout(timer)
    }
  }, [data])

  // ── Dispose all cached nodes on unmount ──
  useEffect(() => {
    return () => {
      nodeCache.current.forEach(disposeGroup)
      nodeCache.current.clear()
    }
  }, [])

  // ── Theme change: clear cache + refresh to rebuild all nodes ──
  useEffect(() => {
    if (themeVersion === prevThemeVersion.current) return
    prevThemeVersion.current = themeVersion
    nodeCache.current.forEach(disposeGroup)
    nodeCache.current.clear()
    graphRef.current?.refresh()
  }, [themeVersion])

  // ── Memoized nodeThreeObject -- ONLY rebuilds when tier or labelColor changes ──
  const nodeThreeObject = useCallback((node: object) => {
    const graphNode = node as GraphNode

    const THREE = require('three')
    const lod = new THREE.LOD()

    // Full detail (closest)
    const fullGroup = buildFullDetail(
      graphNode,
      tierConfig.sphereSegments,
      tierConfig.ringSegments,
      tierConfig.enableGlow,
      tierConfig.enableWireframe,
      tierConfig.enableLabels,
      labelColorRef.current,
    )
    lod.addLevel(fullGroup, 0)

    // Medium detail
    const medGroup = buildMediumDetail(graphNode, tierConfig.sphereSegments, tierConfig.enableLabels, labelColorRef.current)
    lod.addLevel(medGroup, tierConfig.lodDistances[0])

    // Dot (farthest)
    const dotGroup = buildDot(graphNode)
    lod.addLevel(dotGroup, tierConfig.lodDistances[1])

    // Store node metadata on LOD for mutation lookups
    lod.userData = { ...fullGroup.userData }
    nodeCache.current.set(graphNode.id, lod)

    return lod
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tierConfig])


  // ── Selection + active chain: direct Three.js mutation (NO nodeThreeObject rebuild) ──
  const selectedNodeId = selectedNode?.id
  useEffect(() => {
    nodeCache.current.forEach((lod, nodeId) => {
      const ud = lod.userData
      const isSelected = nodeId === selectedNodeId
      const fullGroup = lod.levels?.[0]?.object
      if (!fullGroup) return

      const selRing = fullGroup.getObjectByName('selectionRing')
      if (selRing) selRing.visible = isSelected

      const chainRing = fullGroup.getObjectByName('chainRing')
      if (chainRing) {
        chainRing.visible = !!(activeChainId && ud.chainId === activeChainId)
      }

      if (ud.isChainNode || ud.isExploit) {
        const isInActiveChain = !!(activeChainId && ud.chainId === activeChainId)
        let newColor: string
        if (!isInActiveChain) {
          if (ud.isGoal) {
            newColor = isSelected ? GOAL_FINDING_COLORS.active : GOAL_FINDING_COLORS.inactive
          } else if (ud.isExploit) {
            newColor = isSelected ? CHAIN_SESSION_COLORS.inactiveSelected : CHAIN_SESSION_COLORS.inactiveFinding
          } else {
            newColor = isSelected ? CHAIN_SESSION_COLORS.inactiveSelected : CHAIN_SESSION_COLORS.inactive
          }
        } else {
          newColor = ud.nodeColor
        }
        const mainMesh = fullGroup.getObjectByName('mainMesh')
        if (mainMesh?.material) {
          mainMesh.material.color.set(newColor)
          if (mainMesh.material.emissive) mainMesh.material.emissive.set(newColor)
        }
      }
    })
  }, [selectedNodeId, activeChainId])

  // ── Labels: toggle visibility via mutation on ALL LOD levels ──
  useEffect(() => {
    nodeCache.current.forEach((lod) => {
      if (!lod.levels) return
      for (const level of lod.levels) {
        const label = level.object?.getObjectByName('label')
        if (label) label.visible = showLabels
      }
    })
  }, [showLabels])

  // ── Glow animation: iterate nodeCache, find rings by name ──
  const hasHighSeverity = hasHighSeverityNodes(data.nodes)

  useAnimationFrame(
    (time) => {
      nodeCache.current.forEach((lod) => {
        const fullGroup = lod.levels?.[0]?.object
        if (!fullGroup) return

        // Glow ring animation
        const glowRing = fullGroup.getObjectByName('glowRing')
        if (glowRing) {
          const level = glowRing.userData.glowLevel || 'high'
          const speed = level === 'critical' ? ANIMATION_CONFIG.criticalSpeed : ANIMATION_CONFIG.highSpeed
          const pulse = Math.sin(time * speed) * 0.15 + 1
          const opacity = Math.sin(time * speed) * 0.2 + 0.4
          glowRing.scale.set(pulse, pulse, 1)
          if (glowRing.material) glowRing.material.opacity = opacity
        }

        // Chain ring animation (if visible)
        const chainRing = fullGroup.getObjectByName('chainRing')
        if (chainRing?.visible) {
          const speed = ANIMATION_CONFIG.highSpeed
          const pulse = Math.sin(time * speed) * 0.15 + 1
          const opacity = Math.sin(time * speed) * 0.2 + 0.4
          chainRing.scale.set(pulse, pulse, 1)
          if (chainRing.material) chainRing.material.opacity = opacity
        }
      })
    },
    hasHighSeverity && tierConfig.enableGlow
  )

  // ── Reheat simulation + clean cache when data changes ──
  const prevNodeCount3DRef = useRef(0)
  useEffect(() => {
    const prevCount = prevNodeCount3DRef.current
    const newCount = data.nodes.length
    const isFirstRender = prevCount === 0
    const structureChanged = newCount !== prevCount
    prevNodeCount3DRef.current = newCount

    // Clean up removed nodes from cache
    const currentIds = new Set(data.nodes.map(n => n.id))
    nodeCache.current.forEach((_, id) => {
      if (!currentIds.has(id)) {
        nodeCache.current.delete(id)
      }
    })
    // Reheat simulation so new nodes get positioned by forces
    // Without this, new nodes (e.g. ChainStep during agent attack) stay at (0,0,0)
    // and links draw to the wrong position
    if (structureChanged && !isFirstRender) {
      const timer = setTimeout(() => {
        graphRef.current?.d3ReheatSimulation()
      }, ANIMATION_CONFIG.initDelay)
      return () => clearTimeout(timer)
    }
  }, [data])

  return (
    <ForceGraph3D
      ref={graphRef}
      graphData={data}
      nodeLabel={(node) => `${(node as GraphNode).name} (${(node as GraphNode).type})`}
      nodeColor={(node) => getNodeColor(node as GraphNode)}
      nodeRelSize={BASE_SIZES.node3D}
      nodeOpacity={THREE_CONFIG.nodeOpacity}
      linkLabel={(link) => (link as GraphLink).type}
      linkColor={(link) => getLinkColor(link as GraphLink, selectedNodeId)}
      linkWidth={(link) => getLinkWidth3D(link as GraphLink, selectedNodeId)}
      linkDirectionalParticles={tierConfig.enableParticles
        ? (link) => getParticleCount(link as GraphLink, selectedNodeId)
        : 0
      }
      linkDirectionalParticleWidth={tierConfig.enableParticles
        ? (link) => getParticleWidth(link as GraphLink, selectedNodeId)
        : undefined
      }
      linkDirectionalParticleColor={tierConfig.enableParticles
        ? (link) => getParticleColor(link as GraphLink, activeChainId)
        : undefined
      }
      linkDirectionalParticleSpeed={tierConfig.enableParticles
        ? (link) => getParticleSpeed(link as GraphLink)
        : undefined
      }
      linkDirectionalArrowLength={LINK_SIZES.arrowLength3D}
      linkDirectionalArrowRelPos={1}
      backgroundColor={isDark ? BACKGROUND_COLORS.dark.graph : BACKGROUND_COLORS.light.graph}
      width={width}
      height={height}
      cooldownTime={forceConfig.cooldownTime}
      cooldownTicks={forceConfig.cooldownTicks}
      warmupTicks={forceConfig.warmupTicks}
      onNodeClick={(node) => onNodeClick(node as GraphNode)}
      nodeThreeObject={nodeThreeObject}
    />
  )
}
