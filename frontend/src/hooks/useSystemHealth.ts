import { useQuery } from 'react-query'
import { dashboardApi } from '../services/api'
import { SystemHealth } from '../types'

export const useSystemHealth = () => {
  return useQuery<SystemHealth>(
    'systemHealth',
    async () => {
      const response = await dashboardApi.getSystemHealth()
      return response.data
    },
    {
      refetchInterval: 30000, // Refresh every 30 seconds
      staleTime: 20000, // Consider data stale after 20 seconds
    }
  )
}