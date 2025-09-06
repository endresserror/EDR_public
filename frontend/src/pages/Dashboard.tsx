import React, { useState } from 'react'
import { Row, Col, Card, Statistic, Select, Spin, Alert, Typography, Space, Tag } from 'antd'
import { ArrowUpOutlined, ArrowDownOutlined, ShieldOutlined, LaptopOutlined, GlobalOutlined, WarningOutlined } from '@ant-design/icons'
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, PieChart, Pie, Cell, BarChart, Bar, ResponsiveContainer } from 'recharts'
import { useQuery } from 'react-query'
import dayjs from 'dayjs'

import { dashboardApi } from '../services/api'
import { DashboardOverview } from '../types'

const { Title } = Typography
const { Option } = Select

const Dashboard: React.FC = () => {
  const [timeRange, setTimeRange] = useState(24)

  const { data: overview, isLoading: overviewLoading } = useQuery<DashboardOverview>(
    ['dashboardOverview', timeRange],
    () => dashboardApi.getOverview(timeRange).then(res => res.data),
    { refetchInterval: 30000 }
  )

  const { data: alertsTimeline, isLoading: alertsTimelineLoading } = useQuery(
    ['alertsTimeline', timeRange],
    () => dashboardApi.getAlertsTimeline(timeRange, 'hour').then(res => res.data),
    { refetchInterval: 60000 }
  )

  const { data: deviceTypes, isLoading: deviceTypesLoading } = useQuery(
    'deviceTypes',
    () => dashboardApi.getDeviceTypes().then(res => res.data),
    { refetchInterval: 300000 } // 5 minutes
  )

  const { data: networkTraffic, isLoading: networkTrafficLoading } = useQuery(
    ['networkTraffic', timeRange],
    () => dashboardApi.getNetworkTraffic(timeRange).then(res => res.data),
    { refetchInterval: 60000 }
  )

  const { data: securityThreats, isLoading: securityThreatsLoading } = useQuery(
    ['securityThreats', timeRange],
    () => dashboardApi.getSecurityThreats(timeRange).then(res => res.data),
    { refetchInterval: 30000 }
  )

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'healthy': return '#52c41a'
      case 'warning': return '#faad14'
      case 'critical': return '#ff4d4f'
      default: return '#8c8c8c'
    }
  }

  const COLORS = ['#1890ff', '#52c41a', '#faad14', '#ff4d4f', '#722ed1', '#13c2c2', '#eb2f96']

  if (overviewLoading) {
    return <div className="loading-container"><Spin size="large" /></div>
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
        <Title level={2}>Dashboard Overview</Title>
        <Select
          value={timeRange}
          onChange={setTimeRange}
          style={{ width: 200 }}
        >
          <Option value={1}>Last Hour</Option>
          <Option value={24}>Last 24 Hours</Option>
          <Option value={72}>Last 3 Days</Option>
          <Option value={168}>Last Week</Option>
        </Select>
      </div>

      {/* System Health Alert */}
      {overview?.system_health?.status !== 'healthy' && (
        <Alert
          message="System Health Warning"
          description={`System is in ${overview?.system_health?.status} state with ${overview?.system_health?.error_logs_count} error logs`}
          type={overview?.system_health?.status === 'critical' ? 'error' : 'warning'}
          showIcon
          style={{ marginBottom: '24px' }}
        />
      )}

      {/* Key Metrics */}
      <Row gutter={[16, 16]} style={{ marginBottom: '24px' }}>
        <Col xs={24} sm={12} md={6}>
          <Card className="metric-card">
            <Statistic
              title="Total Devices"
              value={overview?.devices?.total || 0}
              prefix={<LaptopOutlined />}
              valueStyle={{ color: '#1890ff' }}
            />
            <div style={{ marginTop: '8px' }}>
              <Tag color="green">{overview?.devices?.active || 0} Active</Tag>
              <Tag color="red">{overview?.devices?.inactive || 0} Inactive</Tag>
            </div>
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card className="metric-card">
            <Statistic
              title="Security Alerts"
              value={overview?.security?.total_alerts || 0}
              prefix={<WarningOutlined />}
              valueStyle={{ color: overview?.security?.critical_alerts ? '#ff4d4f' : '#52c41a' }}
            />
            <div style={{ marginTop: '8px' }}>
              <Tag color="red">{overview?.security?.critical_alerts || 0} Critical</Tag>
              <Tag color="orange">{overview?.security?.unresolved_alerts || 0} Open</Tag>
            </div>
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card className="metric-card">
            <Statistic
              title="Network Sessions"
              value={overview?.network?.total_sessions || 0}
              prefix={<GlobalOutlined />}
              valueStyle={{ color: '#52c41a' }}
            />
            <div style={{ marginTop: '8px' }}>
              <Tag color="orange">{overview?.network?.suspicious_sessions || 0} Suspicious</Tag>
            </div>
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card className="metric-card">
            <Statistic
              title="System Health"
              value={overview?.system_health?.status || 'Unknown'}
              prefix={<ShieldOutlined />}
              valueStyle={{ color: getStatusColor(overview?.system_health?.status || 'unknown') }}
            />
            <div style={{ marginTop: '8px' }}>
              <Tag color={overview?.system_health?.error_logs_count === 0 ? 'green' : 'red'}>
                {overview?.system_health?.error_logs_count || 0} Errors
              </Tag>
            </div>
          </Card>
        </Col>
      </Row>

      {/* Charts Row 1 */}
      <Row gutter={[16, 16]} style={{ marginBottom: '24px' }}>
        <Col xs={24} lg={16}>
          <Card title="Alerts Timeline" className="chart-container">
            {alertsTimelineLoading ? (
              <div className="loading-container"><Spin /></div>
            ) : (
              <ResponsiveContainer width="100%" height={300}>
                <LineChart data={alertsTimeline?.timeline || []}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#303030" />
                  <XAxis 
                    dataKey="time" 
                    stroke="#8c8c8c"
                    tickFormatter={(time) => dayjs(time).format('HH:mm')}
                  />
                  <YAxis stroke="#8c8c8c" />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#1f1f1f', border: '1px solid #303030' }}
                    labelFormatter={(time) => dayjs(time).format('YYYY-MM-DD HH:mm')}
                  />
                  <Legend />
                  <Line 
                    type="monotone" 
                    dataKey="total" 
                    stroke="#1890ff" 
                    strokeWidth={2}
                    name="Total Alerts"
                  />
                </LineChart>
              </ResponsiveContainer>
            )}
          </Card>
        </Col>
        <Col xs={24} lg={8}>
          <Card title="Device Types Distribution" className="chart-container">
            {deviceTypesLoading ? (
              <div className="loading-container"><Spin /></div>
            ) : (
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={deviceTypes?.distribution || []}
                    cx="50%"
                    cy="50%"
                    outerRadius={80}
                    fill="#8884d8"
                    dataKey="count"
                    nameKey="label"
                    label={({ label, percentage }) => `${label} (${percentage}%)`}
                  >
                    {(deviceTypes?.distribution || []).map((entry: any, index: number) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#1f1f1f', border: '1px solid #303030' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            )}
          </Card>
        </Col>
      </Row>

      {/* Charts Row 2 */}
      <Row gutter={[16, 16]} style={{ marginBottom: '24px' }}>
        <Col xs={24} lg={12}>
          <Card title="Network Protocol Distribution" className="chart-container">
            {networkTrafficLoading ? (
              <div className="loading-container"><Spin /></div>
            ) : (
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={networkTraffic?.protocol_distribution || []}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#303030" />
                  <XAxis dataKey="protocol" stroke="#8c8c8c" />
                  <YAxis stroke="#8c8c8c" />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#1f1f1f', border: '1px solid #303030' }}
                  />
                  <Bar dataKey="session_count" fill="#1890ff" />
                </BarChart>
              </ResponsiveContainer>
            )}
          </Card>
        </Col>
        <Col xs={24} lg={12}>
          <Card title="Top Network Talkers" className="chart-container">
            {networkTrafficLoading ? (
              <div className="loading-container"><Spin /></div>
            ) : (
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={networkTraffic?.top_talkers?.slice(0, 5) || []}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#303030" />
                  <XAxis dataKey="ip_address" stroke="#8c8c8c" />
                  <YAxis stroke="#8c8c8c" />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#1f1f1f', border: '1px solid #303030' }}
                    formatter={(value) => [`${(value as number / 1024 / 1024).toFixed(2)} MB`, 'Total Traffic']}
                  />
                  <Bar dataKey="total_bytes" fill="#52c41a" />
                </BarChart>
              </ResponsiveContainer>
            )}
          </Card>
        </Col>
      </Row>

      {/* Recent Critical Alerts */}
      {securityThreats?.critical_alerts?.length > 0 && (
        <Row>
          <Col span={24}>
            <Card title="Recent Critical Alerts" className="chart-container">
              <Space direction="vertical" style={{ width: '100%' }}>
                {securityThreats.critical_alerts.slice(0, 5).map((alert: any) => (
                  <div 
                    key={alert.id}
                    style={{ 
                      padding: '12px', 
                      border: '1px solid #ff4d4f', 
                      borderRadius: '6px',
                      background: 'rgba(255, 77, 79, 0.1)'
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div>
                        <strong>{alert.title}</strong>
                        <br />
                        <small>
                          {alert.source_ip} → {alert.destination_ip} | 
                          Status: {alert.status} | 
                          {dayjs(alert.created_at).format('YYYY-MM-DD HH:mm:ss')}
                        </small>
                      </div>
                      <Tag color="red">Critical</Tag>
                    </div>
                  </div>
                ))}
              </Space>
            </Card>
          </Col>
        </Row>
      )}
    </div>
  )
}

export default Dashboard