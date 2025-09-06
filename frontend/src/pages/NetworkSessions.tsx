import React, { useState } from 'react'
import { Table, Card, Tag, Select, Space, Typography, Input } from 'antd'
import { useQuery } from 'react-query'
import dayjs from 'dayjs'

import { sessionsApi } from '../services/api'
import { NetworkSession } from '../types'

const { Title } = Typography
const { Option } = Select
const { Search } = Input

const NetworkSessions: React.FC = () => {
  const [selectedProtocol, setSelectedProtocol] = useState<string>('')
  const [selectedSuspicious, setSelectedSuspicious] = useState<string>('')
  const [sourceIpFilter, setSourceIpFilter] = useState<string>('')
  const [pageSize, setPageSize] = useState(20)

  const { data: sessions, isLoading } = useQuery(
    ['sessions', selectedProtocol, selectedSuspicious, sourceIpFilter],
    () => sessionsApi.getSessions({
      protocol: selectedProtocol || undefined,
      is_suspicious: selectedSuspicious === 'true' ? true : selectedSuspicious === 'false' ? false : undefined,
      source_ip: sourceIpFilter || undefined,
      hours: 168, // Last week
      limit: 1000
    }).then(res => res.data),
    { refetchInterval: 30000 }
  )

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }

  const getProtocolColor = (protocol: string) => {
    switch (protocol.toLowerCase()) {
      case 'tcp': return 'blue'
      case 'udp': return 'green'
      case 'icmp': return 'orange'
      case 'http': return 'cyan'
      case 'https': return 'purple'
      case 'ssh': return 'red'
      case 'dns': return 'gold'
      case 'mqtt': return 'magenta'
      case 'coap': return 'lime'
      default: return 'default'
    }
  }

  const columns = [
    {
      title: 'Protocol',
      dataIndex: 'protocol',
      key: 'protocol',
      width: 80,
      render: (protocol: string) => (
        <Tag color={getProtocolColor(protocol)}>{protocol}</Tag>
      ),
    },
    {
      title: 'Source',
      key: 'source',
      width: 150,
      render: (_: any, record: NetworkSession) => (
        <div>
          <div>{record.source_ip}</div>
          {record.source_port && <small>:{record.source_port}</small>}
        </div>
      ),
    },
    {
      title: 'Destination',
      key: 'destination',
      width: 150,
      render: (_: any, record: NetworkSession) => (
        <div>
          <div>{record.destination_ip}</div>
          {record.destination_port && <small>:{record.destination_port}</small>}
        </div>
      ),
    },
    {
      title: 'Duration',
      dataIndex: 'duration',
      key: 'duration',
      width: 80,
      render: (duration: number) => {
        if (!duration) return '-'
        if (duration < 60) return `${duration}s`
        if (duration < 3600) return `${Math.floor(duration / 60)}m ${duration % 60}s`
        return `${Math.floor(duration / 3600)}h ${Math.floor((duration % 3600) / 60)}m`
      },
      sorter: (a: NetworkSession, b: NetworkSession) => (a.duration || 0) - (b.duration || 0),
    },
    {
      title: 'Data Sent',
      dataIndex: 'bytes_sent',
      key: 'bytes_sent',
      width: 100,
      render: (bytes: number) => formatBytes(bytes),
      sorter: (a: NetworkSession, b: NetworkSession) => a.bytes_sent - b.bytes_sent,
    },
    {
      title: 'Data Received',
      dataIndex: 'bytes_received',
      key: 'bytes_received',
      width: 100,
      render: (bytes: number) => formatBytes(bytes),
      sorter: (a: NetworkSession, b: NetworkSession) => a.bytes_received - b.bytes_received,
    },
    {
      title: 'Packets',
      key: 'packets',
      width: 80,
      render: (_: any, record: NetworkSession) => (
        <div>
          <div>↑{record.packets_sent}</div>
          <div>↓{record.packets_received}</div>
        </div>
      ),
    },
    {
      title: 'Flags',
      key: 'flags',
      width: 100,
      render: (_: any, record: NetworkSession) => (
        <Space direction="vertical" size="small">
          {record.is_encrypted && <Tag color="green" size="small">Encrypted</Tag>}
          {record.is_suspicious && <Tag color="red" size="small">Suspicious</Tag>}
        </Space>
      ),
    },
    {
      title: 'Start Time',
      dataIndex: 'start_time',
      key: 'start_time',
      width: 160,
      render: (date: string) => date ? dayjs(date).format('YYYY-MM-DD HH:mm:ss') : '-',
      sorter: (a: NetworkSession, b: NetworkSession) => {
        if (!a.start_time || !b.start_time) return 0
        return dayjs(a.start_time).unix() - dayjs(b.start_time).unix()
      },
      defaultSortOrder: 'descend' as const,
    },
  ]

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
        <Title level={2}>Network Sessions</Title>
        <Space>
          <Search
            placeholder="Search by source IP"
            style={{ width: 200 }}
            value={sourceIpFilter}
            onChange={(e) => setSourceIpFilter(e.target.value)}
            allowClear
          />
          <Select
            placeholder="Filter by Protocol"
            style={{ width: 120 }}
            allowClear
            value={selectedProtocol || undefined}
            onChange={setSelectedProtocol}
          >
            <Option value="TCP">TCP</Option>
            <Option value="UDP">UDP</Option>
            <Option value="ICMP">ICMP</Option>
            <Option value="HTTP">HTTP</Option>
            <Option value="HTTPS">HTTPS</Option>
            <Option value="SSH">SSH</Option>
            <Option value="DNS">DNS</Option>
            <Option value="MQTT">MQTT</Option>
            <Option value="CoAP">CoAP</Option>
          </Select>
          <Select
            placeholder="Filter by Status"
            style={{ width: 150 }}
            allowClear
            value={selectedSuspicious || undefined}
            onChange={setSelectedSuspicious}
          >
            <Option value="true">Suspicious</Option>
            <Option value="false">Normal</Option>
          </Select>
        </Space>
      </div>

      <Card>
        <Table
          columns={columns}
          dataSource={sessions || []}
          rowKey="id"
          loading={isLoading}
          pagination={{
            pageSize,
            showSizeChanger: true,
            showQuickJumper: true,
            showTotal: (total, range) => `${range[0]}-${range[1]} of ${total} sessions`,
            onShowSizeChange: (_, size) => setPageSize(size),
          }}
          rowClassName={(record) => record.is_suspicious ? 'session-suspicious' : ''}
          scroll={{ x: 1200 }}
        />
      </Card>
    </div>
  )
}

export default NetworkSessions