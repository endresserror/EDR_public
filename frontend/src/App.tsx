import React from 'react'
import { Routes, Route } from 'react-router-dom'
import { Layout, Menu, Typography, Space, Badge } from 'antd'
import {
  DashboardOutlined,
  AlertOutlined,
  LaptopOutlined,
  GlobalOutlined,
  SettingOutlined,
  FileTextOutlined,
  ShieldOutlined
} from '@ant-design/icons'
import { Link, useLocation } from 'react-router-dom'

import Dashboard from './pages/Dashboard'
import Alerts from './pages/Alerts'
import Devices from './pages/Devices'
import NetworkSessions from './pages/NetworkSessions'
import ThreatRules from './pages/ThreatRules'
import SystemLogs from './pages/SystemLogs'
import Settings from './pages/Settings'

import { useSystemHealth } from './hooks/useSystemHealth'

const { Header, Sider, Content } = Layout
const { Title } = Typography

const App: React.FC = () => {
  const location = useLocation()
  const { data: systemHealth } = useSystemHealth()
  
  const menuItems = [
    {
      key: '/',
      icon: <DashboardOutlined />,
      label: <Link to="/">Dashboard</Link>,
    },
    {
      key: '/alerts',
      icon: <AlertOutlined />,
      label: <Link to="/alerts">Alerts</Link>,
    },
    {
      key: '/devices',
      icon: <LaptopOutlined />,
      label: <Link to="/devices">Devices</Link>,
    },
    {
      key: '/sessions',
      icon: <GlobalOutlined />,
      label: <Link to="/sessions">Network Sessions</Link>,
    },
    {
      key: '/rules',
      icon: <ShieldOutlined />,
      label: <Link to="/rules">Threat Rules</Link>,
    },
    {
      key: '/logs',
      icon: <FileTextOutlined />,
      label: <Link to="/logs">System Logs</Link>,
    },
    {
      key: '/settings',
      icon: <SettingOutlined />,
      label: <Link to="/settings">Settings</Link>,
    },
  ]

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'healthy':
        return '#52c41a'
      case 'warning':
        return '#faad14'
      case 'critical':
        return '#ff4d4f'
      default:
        return '#8c8c8c'
    }
  }

  return (
    <Layout className="app-layout">
      <Header className="app-header">
        <div className="app-logo">
          <ShieldOutlined style={{ fontSize: '24px', marginRight: '12px' }} />
          IoT EDR System
        </div>
        <Space>
          {systemHealth && (
            <Badge
              color={getStatusColor(systemHealth.overall_status)}
              text={`System ${systemHealth.overall_status}`}
            />
          )}
        </Space>
      </Header>
      
      <Layout>
        <Sider
          width={180}
          style={{
            background: '#ffffff',
            borderRight: '2px solid #000000',
            minHeight: 'calc(100vh - 64px)',
          }}
        >
          <Menu
            mode="inline"
            selectedKeys={[location.pathname]}
            style={{
              background: '#ffffff',
              border: 'none',
              paddingTop: '10px',
              fontFamily: 'monospace',
              fontSize: '12px',
            }}
            items={menuItems}
          />
        </Sider>
        
        <Content className="app-content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/devices" element={<Devices />} />
            <Route path="/sessions" element={<NetworkSessions />} />
            <Route path="/rules" element={<ThreatRules />} />
            <Route path="/logs" element={<SystemLogs />} />
            <Route path="/settings" element={<Settings />} />
          </Routes>
        </Content>
      </Layout>
    </Layout>
  )
}

export default App