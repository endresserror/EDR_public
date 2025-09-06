export interface Device {
  id: number
  mac_address: string
  ip_address: string
  hostname?: string
  device_type?: string
  manufacturer?: string
  model?: string
  firmware_version?: string
  is_active: boolean
  last_seen?: string
  first_seen?: string
  trust_score: number
  description?: string
  created_at: string
  updated_at: string
}

export interface Alert {
  id: number
  title: string
  description?: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  status: 'open' | 'acknowledged' | 'resolved' | 'false_positive'
  source_ip?: string
  destination_ip?: string
  source_port?: number
  destination_port?: number
  protocol?: string
  device_id?: number
  rule_id?: number
  raw_data?: string
  is_acknowledged: boolean
  acknowledged_by?: string
  acknowledged_at?: string
  created_at: string
  updated_at: string
  device?: Device
  rule?: ThreatRule
}

export interface NetworkSession {
  id: number
  session_id: string
  source_ip: string
  destination_ip: string
  source_port?: number
  destination_port?: number
  protocol: string
  bytes_sent: number
  bytes_received: number
  packets_sent: number
  packets_received: number
  duration?: number
  is_encrypted: boolean
  is_suspicious: boolean
  device_id?: number
  start_time?: string
  end_time?: string
  created_at: string
  device?: Device
}

export interface ThreatRule {
  id: number
  name: string
  description?: string
  rule_type: 'signature' | 'anomaly' | 'behavioral' | 'reputation' | 'custom'
  rule_content: string
  severity: string
  is_enabled: boolean
  confidence: number
  tags?: string
  mitre_attack_id?: string
  created_by?: string
  created_at?: string
  updated_at?: string
}

export interface SystemLog {
  id: number
  level: 'debug' | 'info' | 'warning' | 'error' | 'critical'
  component: string
  message: string
  details?: string
  ip_address?: string
  user_agent?: string
  created_at: string
}

export interface DashboardOverview {
  time_period_hours: number
  system_health: {
    status: 'healthy' | 'warning' | 'critical'
    error_logs_count: number
    uptime_hours: number
  }
  devices: {
    total: number
    active: number
    inactive: number
    new_devices: number
  }
  security: {
    total_alerts: number
    critical_alerts: number
    unresolved_alerts: number
    alert_rate_per_hour: number
  }
  network: {
    total_sessions: number
    suspicious_sessions: number
    total_traffic_bytes: number
    traffic_rate_mbps: number
  }
  generated_at: string
}

export interface SystemHealth {
  overall_status: 'healthy' | 'warning' | 'critical'
  status_message: string
  recent_errors_1h: number
  total_errors_24h: number
  component_health: {
    [component: string]: {
      status: 'healthy' | 'warning' | 'critical'
      recent_errors: number
    }
  }
  last_check: string
}