import React from 'react'
import { Card, Typography, Space, Descriptions, Tag } from 'antd'
import { ShieldOutlined, DatabaseOutlined, GlobalOutlined, SettingOutlined } from '@ant-design/icons'

const { Title } = Typography

const Settings: React.FC = () => {
  return (
    <div>
      <Title level={2}>System Settings</Title>
      
      <Space direction="vertical" size="large" style={{ width: '100%' }}>
        {/* System Information */}
        <Card 
          title={
            <Space>
              <ShieldOutlined />
              System Information
            </Space>
          }
        >
          <Descriptions bordered column={2}>
            <Descriptions.Item label="Application Name">IoT EDR System</Descriptions.Item>
            <Descriptions.Item label="Version">1.0.0</Descriptions.Item>
            <Descriptions.Item label="Status">
              <Tag color="green">Running</Tag>
            </Descriptions.Item>
            <Descriptions.Item label="Uptime">24 hours 35 minutes</Descriptions.Item>
            <Descriptions.Item label="Database">SQLite</Descriptions.Item>
            <Descriptions.Item label="Log Level">INFO</Descriptions.Item>
          </Descriptions>
        </Card>

        {/* Network Configuration */}
        <Card 
          title={
            <Space>
              <GlobalOutlined />
              Network Configuration
            </Space>
          }
        >
          <Descriptions bordered column={2}>
            <Descriptions.Item label="Network Interface">eth0</Descriptions.Item>
            <Descriptions.Item label="Capture Filter">None</Descriptions.Item>
            <Descriptions.Item label="Packet Buffer Size">1024 packets</Descriptions.Item>
            <Descriptions.Item label="Dashboard Host">0.0.0.0</Descriptions.Item>
            <Descriptions.Item label="Dashboard Port">8000</Descriptions.Item>
            <Descriptions.Item label="Max Concurrent Connections">1000</Descriptions.Item>
          </Descriptions>
        </Card>

        {/* Security Settings */}
        <Card 
          title={
            <Space>
              <ShieldOutlined />
              Security Settings
            </Space>
          }
        >
          <Descriptions bordered column={2}>
            <Descriptions.Item label="Trusted Networks">
              <div>
                <Tag color="blue">192.168.1.0/24</Tag>
                <Tag color="blue">10.0.0.0/8</Tag>
              </div>
            </Descriptions.Item>
            <Descriptions.Item label="Monitored Ports">
              <div>
                <Tag>22</Tag> <Tag>23</Tag> <Tag>80</Tag> <Tag>443</Tag> 
                <Tag>8080</Tag> <Tag>1883</Tag> <Tag>5683</Tag>
              </div>
            </Descriptions.Item>
          </Descriptions>
        </Card>

        {/* Data Retention */}
        <Card 
          title={
            <Space>
              <DatabaseOutlined />
              Data Retention
            </Space>
          }
        >
          <Descriptions bordered column={2}>
            <Descriptions.Item label="Alert Retention">90 days</Descriptions.Item>
            <Descriptions.Item label="Log Retention">30 days</Descriptions.Item>
            <Descriptions.Item label="Session Data Retention">7 days</Descriptions.Item>
            <Descriptions.Item label="Device Data Retention">Indefinite</Descriptions.Item>
          </Descriptions>
        </Card>

        {/* System Features */}
        <Card 
          title={
            <Space>
              <SettingOutlined />
              System Features
            </Space>
          }
        >
          <Descriptions bordered column={2}>
            <Descriptions.Item label="Real-time Monitoring">
              <Tag color="green">Enabled</Tag>
            </Descriptions.Item>
            <Descriptions.Item label="Packet Analysis">
              <Tag color="green">Enabled</Tag>
            </Descriptions.Item>
            <Descriptions.Item label="Threat Detection">
              <Tag color="green">Enabled</Tag>
            </Descriptions.Item>
            <Descriptions.Item label="Device Profiling">
              <Tag color="green">Enabled</Tag>
            </Descriptions.Item>
            <Descriptions.Item label="Alert System">
              <Tag color="green">Enabled</Tag>
            </Descriptions.Item>
            <Descriptions.Item label="Web Dashboard">
              <Tag color="green">Enabled</Tag>
            </Descriptions.Item>
          </Descriptions>
        </Card>

        {/* About */}
        <Card title="About">
          <p>
            IoT EDR (Endpoint Detection and Response) System is a comprehensive security solution 
            designed specifically for IoT device networks. It provides real-time monitoring, 
            threat detection, and incident response capabilities for home and small business IoT environments.
          </p>
          <p>
            The system monitors network traffic, analyzes device behavior, and detects potential 
            security threats using a combination of signature-based detection, anomaly detection, 
            and behavioral analysis techniques.
          </p>
          <Space>
            <Tag color="blue">Python</Tag>
            <Tag color="blue">FastAPI</Tag>
            <Tag color="blue">SQLAlchemy</Tag>
            <Tag color="blue">Scapy</Tag>
            <Tag color="blue">React</Tag>
            <Tag color="blue">TypeScript</Tag>
            <Tag color="blue">Ant Design</Tag>
          </Space>
        </Card>
      </Space>
    </div>
  )
}

export default Settings