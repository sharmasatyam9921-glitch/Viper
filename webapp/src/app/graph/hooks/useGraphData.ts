import { useQuery } from '@tanstack/react-query'
import { GraphData } from '../types'

// Store last ETag and data outside component to survive re-renders
const etagStore = new Map<string, { etag: string; data: GraphData }>()

async function fetchGraphData(projectId: string): Promise<GraphData> {
  const stored = etagStore.get(projectId)
  const headers: Record<string, string> = {}

  if (stored?.etag) {
    headers['If-None-Match'] = `"${stored.etag}"`
  }

  const response = await fetch(`/api/graph?projectId=${projectId}`, { headers })

  // 304 Not Modified -- return previous data, skip JSON parse entirely
  if (response.status === 304) {
    if (stored?.data) return stored.data
    // Fallback: shouldn't happen, but refetch without ETag
    const fallback = await fetch(`/api/graph?projectId=${projectId}`)
    return fallback.json()
  }

  if (!response.ok) {
    throw new Error('Failed to fetch graph data')
  }

  // Extract ETag from response
  const newEtag = response.headers.get('etag')?.replace(/"/g, '') || ''

  const data: GraphData = await response.json()

  // Store for next conditional request
  if (newEtag) {
    etagStore.set(projectId, { etag: newEtag, data })
  }

  return data
}

interface UseGraphDataOptions {
  isReconRunning?: boolean
  isAgentRunning?: boolean
}

export function useGraphData(projectId: string | null, options?: UseGraphDataOptions) {
  const { isReconRunning = false, isAgentRunning = false } = options || {}

  const shouldPoll = isReconRunning || isAgentRunning

  const query = useQuery({
    queryKey: ['graph', projectId],
    queryFn: () => fetchGraphData(projectId!),
    enabled: !!projectId,
    // Poll every 5 seconds while recon or agent is running
    refetchInterval: shouldPoll ? 5000 : false,
    // Smarter stale time: during polling, data is nearly fresh; when idle, cache longer
    staleTime: shouldPoll ? 4000 : 30000,
    // Only re-render the component when data or error actually change
    notifyOnChangeProps: ['data', 'error', 'isLoading'],
  })

  return query
}
