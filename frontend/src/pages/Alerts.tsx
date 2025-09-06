import React, { useState } from 'react'
import { Table, Card, Button, Tag, Select, Space, Typography, Modal, message, Spin } from 'antd'
import { EyeOutlined, CheckOutlined, CloseOutlined, ExclamationCircleOutlined } from '@ant-design/icons'
import { useQuery, useMutation, useQueryClient } from 'react-query'
import dayjs from 'dayjs'

import { alertsApi } from '../services/api'
import { Alert } from '../types'

const { Title } = Typography
const { Option } = Select
const { confirm } = Modal

const Alerts: React.FC = () => {
  const [selectedSeverity, setSelectedSeverity] = useState<string>('')
  const [selectedStatus, setSelectedStatus] = useState<string>('')
  const [pageSize, setPageSize] = useState(20)
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null)
  const [detailModalVisible, setDetailModalVisible] = useState(false)

  const queryClient = useQueryClient()

  const { data: alerts, isLoading } = useQuery(
    ['alerts', selectedSeverity, selectedStatus],
    () => alertsApi.getAlerts({
      severity: selectedSeverity || undefined,
      status: selectedStatus || undefined,
      hours: 168, // Last week
      limit: 1000
    }).then(res => res.data),
    { refetchInterval: 30000 }
  )

  const acknowledgeMutation = useMutation(
    (id: number) => alertsApi.acknowledgeAlert(id, 'dashboard-user'),
    {
      onSuccess: () => {
        message.success('Alert acknowledged successfully')
        queryClient.invalidateQueries('alerts')
      },
      onError: () => {
        message.error('Failed to acknowledge alert')
      }
    }
  )

  const resolveMutation = useMutation(
    (id: number) => alertsApi.resolveAlert(id, 'dashboard-user'),
    {
      onSuccess: () => {
        message.success('Alert resolved successfully')
        queryClient.invalidateQueries('alerts')
      },
      onError: () => {
        message.error('Failed to resolve alert')
      }
    }
  )

  const falsePositiveMutation = useMutation(
    (id: number) => alertsApi.markFalsePositive(id, 'dashboard-user'),
    {
      onSuccess: () => {
        message.success('Alert marked as false positive')
        queryClient.invalidateQueries('alerts')
      },
      onError: () => {
        message.error('Failed to mark alert as false positive')
      }
    }
  )

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'red'
      case 'high': return 'orange' 
      case 'medium': return 'gold'
      case 'low': return 'green'
      default: return 'default'
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'open': return 'red'
      case 'acknowledged': return 'orange'
      case 'resolved': return 'green'
      case 'false_positive': return 'gray'
      default: return 'default'
    }
  }

  const handleAcknowledge = (alert: Alert) => {
    confirm({
      title: 'Acknowledge Alert',
      content: `Are you sure you want to acknowledge "${alert.title}"?`,
      icon: <ExclamationCircleOutlined />,
      onOk: () => acknowledgeMutation.mutate(alert.id),
    })
  }

  const handleResolve = (alert: Alert) => {
    confirm({
      title: 'Resolve Alert',
      content: `Are you sure you want to resolve "${alert.title}"?`,
      icon: <CheckOutlined />,
      onOk: () => resolveMutation.mutate(alert.id),
    })
  }

  const handleFalsePositive = (alert: Alert) => {
    confirm({
      title: 'Mark as False Positive',
      content: `Are you sure you want to mark "${alert.title}" as false positive?`,
      icon: <CloseOutlined />,
      onOk: () => falsePositiveMutation.mutate(alert.id),
    })
  }

  const handleViewDetails = (alert: Alert) => {
    setSelectedAlert(alert)
    setDetailModalVisible(true)
  }

  const columns = [
    {
      title: 'Severity',
      dataIndex: 'severity',
      key: 'severity',
      width: 100,
      render: (severity: string) => (
        <Tag color={getSeverityColor(severity)}>{severity.toUpperCase()}</Tag>
      ),
      filters: [
        { text: 'Critical', value: 'critical' },
        { text: 'High', value: 'high' },
        { text: 'Medium', value: 'medium' },
        { text: 'Low', value: 'low' },
      ],
    },
    {
      title: 'Title',
      dataIndex: 'title',
      key: 'title',
      ellipsis: true,
    },
    {
      title: 'Source IP',
      dataIndex: 'source_ip',
      key: 'source_ip',
      width: 120,
    },
    {
      title: 'Destination IP',
      dataIndex: 'destination_ip',
      key: 'destination_ip',
      width: 120,
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      width: 120,
      render: (status: string) => (
        <Tag color={getStatusColor(status)}>{status.replace('_', ' ').toUpperCase()}</Tag>
      ),
    },
    {
      title: 'Created',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 160,
      render: (date: string) => dayjs(date).format('YYYY-MM-DD HH:mm:ss'),
      sorter: (a: Alert, b: Alert) => dayjs(a.created_at).unix() - dayjs(b.created_at).unix(),
      defaultSortOrder: 'descend' as const,
    },
    {
      title: 'Actions',
      key: 'actions',
      width: 200,
      render: (_: any, record: Alert) => (
        <Space>
          <Button
            size="small"
            icon={<EyeOutlined />}
            onClick={() => handleViewDetails(record)}
          >
            Details
          </Button>
          {record.status === 'open' && (
            <Button
              size="small"
              icon={<ExclamationCircleOutlined />}
              onClick={() => handleAcknowledge(record)}
              loading={acknowledgeMutation.isLoading}
            >
              Ack
            </Button>
          )}
          {(record.status === 'open' || record.status === 'acknowledged') && (
            <Button
              size="small"
              type="primary"
              icon={<CheckOutlined />}
              onClick={() => handleResolve(record)}
              loading={resolveMutation.isLoading}
            >
              Resolve
            </Button>
          )}
          {(record.status === 'open' || record.status === 'acknowledged') && (
            <Button
              size="small"
              danger
              icon={<CloseOutlined />}
              onClick={() => handleFalsePositive(record)}
              loading={falsePositiveMutation.isLoading}
            >
              FP
            </Button>
          )}
        </Space>
      ),
    },
  ]

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
        <Title level={2}>Security Alerts</Title>
        <Space>
          <Select
            placeholder="Filter by Severity"
            style={{ width: 150 }}
            allowClear
            value={selectedSeverity || undefined}
            onChange={setSelectedSeverity}
          >
            <Option value="critical">Critical</Option>
            <Option value="high">High</Option>
            <Option value="medium">Medium</Option>
            <Option value="low">Low</Option>
          </Select>
          <Select
            placeholder="Filter by Status"
            style={{ width: 150 }}
            allowClear
            value={selectedStatus || undefined}
            onChange={setSelectedStatus}
          >
            <Option value="open">Open</Option>
            <Option value="acknowledged">Acknowledged</Option>
            <Option value="resolved">Resolved</Option>
            <Option value="false_positive">False Positive</Option>
          </Select>
        </Space>
      </div>

      <Card>
        <Table
          columns={columns}
          dataSource={alerts || []}
          rowKey="id"
          loading={isLoading}
          pagination={{
            pageSize,
            showSizeChanger: true,
            showQuickJumper: true,
            showTotal: (total, range) => `${range[0]}-${range[1]} of ${total} alerts`,
            onShowSizeChange: (_, size) => setPageSize(size),
          }}
          rowClassName={(record) => {
            switch (record.severity) {
              case 'critical': return 'alert-critical'
              case 'high': return 'alert-high'
              case 'medium': return 'alert-medium'
              case 'low': return 'alert-low'
              default: return ''
            }
          }}
        />
      </Card>

      {/* Alert Detail Modal */}
      <Modal
        title="Alert Details"
        open={detailModalVisible}
        onCancel={() => setDetailModalVisible(false)}
        footer={null}
        width={800}
      >
        {selectedAlert && (
          <div>
            <Space direction="vertical" style={{ width: '100%' }}>
              <div>
                <strong>Title:</strong> {selectedAlert.title}
              </div>
              <div>
                <strong>Description:</strong> {selectedAlert.description}
              </div>
              <div>
                <strong>Severity:</strong> <Tag color={getSeverityColor(selectedAlert.severity)}>{selectedAlert.severity.toUpperCase()}</Tag>
              </div>
              <div>
                <strong>Status:</strong> <Tag color={getStatusColor(selectedAlert.status)}>{selectedAlert.status.replace('_', ' ').toUpperCase()}</Tag>
              </div>
              <div>
                <strong>Source:</strong> {selectedAlert.source_ip}:{selectedAlert.source_port}
              </div>
              <div>
                <strong>Destination:</strong> {selectedAlert.destination_ip}:{selectedAlert.destination_port}
              </div>
              <div>
                <strong>Protocol:</strong> {selectedAlert.protocol}
              </div>
              <div>
                <strong>Created:</strong> {dayjs(selectedAlert.created_at).format('YYYY-MM-DD HH:mm:ss')}
              </div>
              {selectedAlert.acknowledged_at && (
                <div>
                  <strong>Acknowledged:</strong> {dayjs(selectedAlert.acknowledged_at).format('YYYY-MM-DD HH:mm:ss')} by {selectedAlert.acknowledged_by}
                </div>
              )}
              {selectedAlert.device && (
                <div>
                  <strong>Device:</strong> {selectedAlert.device.hostname || selectedAlert.device.ip_address} ({selectedAlert.device.mac_address})
                </div>
              )}
              {selectedAlert.raw_data && (
                <div>
                  <strong>Raw Data:</strong>
                  <pre style={{ background: '#000', padding: '12px', borderRadius: '4px', maxHeight: '200px', overflow: 'auto' }}>
                    {JSON.stringify(JSON.parse(selectedAlert.raw_data), null, 2)}
                  </pre>
                </div>
              )}
            </Space>
          </div>
        )}
      </Modal>
    </div>
  )
}

export default Alerts