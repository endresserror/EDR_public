import axios from 'axios'

const API_BASE_URL = '/api/v1'

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
})

api.interceptors.response.use(
  (response) => response,
  (error) => {
    console.error('API Error:', error)
    return Promise.reject(error)
  }
)

export const dashboardApi = {
  getOverview: (hours: number = 24) => 
    api.get(`/dashboard/overview?hours=${hours}`),
  getAlertsTimeline: (hours: number = 24, granularity: string = 'hour') =>
    api.get(`/dashboard/alerts/timeline?hours=${hours}&granularity=${granularity}`),
  getDeviceTypes: () =>
    api.get('/dashboard/devices/types'),
  getNetworkTraffic: (hours: number = 24) =>
    api.get(`/dashboard/network/traffic?hours=${hours}`),
  getSecurityThreats: (hours: number = 24) =>
    api.get(`/dashboard/security/threats?hours=${hours}`),
  getSystemHealth: () =>
    api.get('/dashboard/system/health'),
}

export const alertsApi = {
  getAlerts: (params?: any) =>
    api.get('/alerts', { params }),
  getAlert: (id: number) =>
    api.get(`/alerts/${id}`),
  acknowledgeAlert: (id: number, acknowledgedBy: string = 'user') =>
    api.put(`/alerts/${id}/acknowledge`, { acknowledged_by: acknowledgedBy }),
  resolveAlert: (id: number, resolvedBy: string = 'user') =>
    api.put(`/alerts/${id}/resolve`, { resolved_by: resolvedBy }),
  markFalsePositive: (id: number, markedBy: string = 'user') =>
    api.put(`/alerts/${id}/false-positive`, { marked_by: markedBy }),
  getAlertStats: (hours: number = 24) =>
    api.get(`/alerts/stats/summary?hours=${hours}`),
}

export const devicesApi = {
  getDevices: (params?: any) =>
    api.get('/devices', { params }),
  getDevice: (id: number) =>
    api.get(`/devices/${id}`),
  updateDevice: (id: number, data: any) =>
    api.put(`/devices/${id}`, data),
  getDeviceStats: () =>
    api.get('/devices/stats/summary'),
  getActivityTimeline: (hours: number = 24) =>
    api.get(`/devices/activity/timeline?hours=${hours}`),
}

export const sessionsApi = {
  getSessions: (params?: any) =>
    api.get('/sessions', { params }),
  getSession: (id: number) =>
    api.get(`/sessions/${id}`),
  getSessionStats: (hours: number = 24) =>
    api.get(`/sessions/stats/summary?hours=${hours}`),
  getTopTalkers: (limit: number = 10, hours: number = 24) =>
    api.get(`/sessions/top/talkers?limit=${limit}&hours=${hours}`),
}

export const rulesApi = {
  getRules: (params?: any) =>
    api.get('/rules', { params }),
  getRule: (id: number) =>
    api.get(`/rules/${id}`),
  createRule: (data: any) =>
    api.post('/rules', data),
  updateRule: (id: number, data: any) =>
    api.put(`/rules/${id}`, data),
  deleteRule: (id: number) =>
    api.delete(`/rules/${id}`),
  enableRule: (id: number) =>
    api.put(`/rules/${id}/enable`),
  disableRule: (id: number) =>
    api.put(`/rules/${id}/disable`),
  getRuleStats: () =>
    api.get('/rules/stats/summary'),
}

export const logsApi = {
  getLogs: (params?: any) =>
    api.get('/logs', { params }),
  getLog: (id: number) =>
    api.get(`/logs/${id}`),
  createLog: (data: any) =>
    api.post('/logs', data),
  getLogStats: (hours: number = 24) =>
    api.get(`/logs/stats/summary?hours=${hours}`),
  cleanupLogs: (days: number = 30, dryRun: boolean = false) =>
    api.delete(`/logs/cleanup?days=${days}&dry_run=${dryRun}`),
  getComponents: () =>
    api.get('/logs/components/list'),
  exportCsv: (params?: any) =>
    api.get('/logs/export/csv', { params, responseType: 'blob' }),
  exportJson: (params?: any) =>
    api.get('/logs/export/json', { params, responseType: 'blob' }),
}

export default api