import React, { useState } from 'react'
import { Table, Card, Tag, Select, Space, Typography, Button, message, Modal } from 'antd'
import { DeleteOutlined, ExclamationCircleOutlined, DownloadOutlined } from '@ant-design/icons'
import { useQuery, useMutation, useQueryClient } from 'react-query'
import dayjs from 'dayjs'

import { logsApi } from '../services/api'
import { SystemLog } from '../types'

const { Title } = Typography
const { Option } = Select
const { confirm } = Modal

const SystemLogs: React.FC = () => {
  const [selectedLevel, setSelectedLevel] = useState<string>('')
  const [selectedComponent, setSelectedComponent] = useState<string>('')
  const [pageSize, setPageSize] = useState(50)

  const queryClient = useQueryClient()

  const { data: logs, isLoading } = useQuery(
    ['logs', selectedLevel, selectedComponent],
    () => logsApi.getLogs({
      level: selectedLevel || undefined,
      component: selectedComponent || undefined,
      hours: 168, // Last week
      limit: 1000
    }).then(res => res.data),
    { refetchInterval: 30000 }
  )

  const { data: components } = useQuery(
    'logComponents',
    () => logsApi.getComponents().then(res => res.data),
    { staleTime: 300000 } // 5 minutes
  )

  const cleanupLogsMutation = useMutation(
    ({ days, dryRun }: { days: number, dryRun: boolean }) => logsApi.cleanupLogs(days, dryRun),
    {
      onSuccess: (response) => {
        const data = response.data
        if (data.deleted_count !== undefined) {
          message.success(`Deleted ${data.deleted_count} old log entries`)
          queryClient.invalidateQueries('logs')
        } else {
          message.info(`Would delete ${data.would_delete_count} old log entries`)
        }
      },
      onError: () => {
        message.error('Failed to cleanup logs')
      }
    }
  )

  const getLogLevelColor = (level: string) => {
    switch (level) {
      case 'critical': return 'red'
      case 'error': return 'red'
      case 'warning': return 'orange'
      case 'info': return 'blue'
      case 'debug': return 'green'
      default: return 'default'
    }
  }

  const getLogLevelIcon = (level: string) => {
    switch (level) {
      case 'critical': return '🔴'
      case 'error': return '❌'
      case 'warning': return '⚠️'
      case 'info': return 'ℹ️'
      case 'debug': return '🐛'
      default: return '📝'
    }
  }

  const handleCleanupLogs = (dryRun: boolean = false) => {
    const actionText = dryRun ? 'preview cleanup' : 'cleanup'
    confirm({
      title: `Log Cleanup ${dryRun ? 'Preview' : ''}`,
      content: `Are you sure you want to ${actionText} logs older than 30 days?`,
      icon: <ExclamationCircleOutlined />,
      onOk: () => cleanupLogsMutation.mutate({ days: 30, dryRun }),
    })
  }

  const handleExportCsv = async () => {
    try {
      const params = {
        level: selectedLevel || undefined,
        component: selectedComponent || undefined,
        hours: 168,
        limit: 10000
      }
      const response = await logsApi.exportCsv(params)
      
      const blob = new Blob([response.data], { type: 'text/csv' })
      const url = window.URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `system-logs-${dayjs().format('YYYY-MM-DD-HH-mm-ss')}.csv`
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      window.URL.revokeObjectURL(url)
      
      message.success('Logs exported as CSV successfully')
    } catch (error) {
      message.error('Failed to export logs as CSV')
    }
  }

  const handleExportJson = async () => {
    try {
      const params = {
        level: selectedLevel || undefined,
        component: selectedComponent || undefined,
        hours: 168,
        limit: 10000
      }
      const response = await logsApi.exportJson(params)
      
      const blob = new Blob([response.data], { type: 'application/json' })
      const url = window.URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `system-logs-${dayjs().format('YYYY-MM-DD-HH-mm-ss')}.json`
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      window.URL.revokeObjectURL(url)
      
      message.success('Logs exported as JSON successfully')
    } catch (error) {
      message.error('Failed to export logs as JSON')
    }
  }

  const columns = [
    {
      title: 'Level',
      dataIndex: 'level',
      key: 'level',
      width: 100,
      render: (level: string) => (
        <Tag color={getLogLevelColor(level)} icon={getLogLevelIcon(level)}>
          {level.toUpperCase()}
        </Tag>
      ),
    },
    {
      title: 'Component',
      dataIndex: 'component',
      key: 'component',
      width: 150,
      render: (component: string) => (
        <Tag color="blue">{component}</Tag>
      ),
    },
    {
      title: 'Message',
      dataIndex: 'message',
      key: 'message',
      ellipsis: true,
      render: (message: string) => (
        <span style={{ fontFamily: 'monospace' }}>{message}</span>
      ),
    },
    {
      title: 'IP Address',
      dataIndex: 'ip_address',
      key: 'ip_address',
      width: 120,
      render: (ip: string) => ip || '-',
    },
    {
      title: 'Timestamp',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 180,
      render: (date: string) => dayjs(date).format('YYYY-MM-DD HH:mm:ss.SSS'),
      sorter: (a: SystemLog, b: SystemLog) => dayjs(a.created_at).unix() - dayjs(b.created_at).unix(),
      defaultSortOrder: 'descend' as const,
    },
  ]

  const expandedRowRender = (record: SystemLog) => {
    return (
      <div style={{ margin: 0, padding: '16px', background: '#1f1f1f', borderRadius: '4px' }}>
        <Space direction="vertical" style={{ width: '100%' }}>
          {record.details && (
            <div>
              <strong>Details:</strong>
              <pre style={{ 
                background: '#000', 
                padding: '8px', 
                borderRadius: '4px', 
                marginTop: '4px',
                fontSize: '12px',
                lineHeight: '1.4'
              }}>
                {record.details}
              </pre>
            </div>
          )}
          {record.user_agent && (
            <div>
              <strong>User Agent:</strong> 
              <span style={{ fontFamily: 'monospace', fontSize: '12px', marginLeft: '8px' }}>
                {record.user_agent}
              </span>
            </div>
          )}
          <div style={{ fontSize: '12px', color: '#8c8c8c' }}>
            <strong>Log ID:</strong> {record.id} | 
            <strong> Full Timestamp:</strong> {dayjs(record.created_at).format('YYYY-MM-DD HH:mm:ss.SSS')}
          </div>
        </Space>
      </div>
    )
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
        <Title level={2}>System Logs</Title>
        <Space>
          <Select
            placeholder="Filter by Level"
            style={{ width: 120 }}
            allowClear
            value={selectedLevel || undefined}
            onChange={setSelectedLevel}
          >
            <Option value="critical">Critical</Option>
            <Option value="error">Error</Option>
            <Option value="warning">Warning</Option>
            <Option value="info">Info</Option>
            <Option value="debug">Debug</Option>
          </Select>
          <Select
            placeholder="Filter by Component"
            style={{ width: 180 }}
            allowClear
            value={selectedComponent || undefined}
            onChange={setSelectedComponent}
          >
            {components?.components?.map((component: string) => (
              <Option key={component} value={component}>{component}</Option>
            ))}
          </Select>
          <Button
            icon={<ExclamationCircleOutlined />}
            onClick={() => handleCleanupLogs(true)}
            loading={cleanupLogsMutation.isLoading}
          >
            Preview Cleanup
          </Button>
          <Button
            danger
            icon={<DeleteOutlined />}
            onClick={() => handleCleanupLogs(false)}
            loading={cleanupLogsMutation.isLoading}
          >
            Cleanup Old Logs
          </Button>
          <Button
            icon={<DownloadOutlined />}
            onClick={handleExportCsv}
            style={{ backgroundColor: '#ffffff', borderColor: '#000000', color: '#000000' }}
          >
            Export CSV
          </Button>
          <Button
            icon={<DownloadOutlined />}
            onClick={handleExportJson}
            style={{ backgroundColor: '#ffffff', borderColor: '#000000', color: '#000000' }}
          >
            Export JSON
          </Button>
        </Space>
      </div>

      <Card>
        <Table
          columns={columns}
          dataSource={logs || []}
          rowKey="id"
          loading={isLoading}
          pagination={{
            pageSize,
            showSizeChanger: true,
            showQuickJumper: true,
            showTotal: (total, range) => `${range[0]}-${range[1]} of ${total} logs`,
            onShowSizeChange: (_, size) => setPageSize(size),
          }}
          expandable={{
            expandedRowRender,
            expandRowByClick: true,
            rowExpandable: (record) => Boolean(record.details || record.user_agent),
          }}
          rowClassName={(record) => {
            switch (record.level) {
              case 'critical':
              case 'error':
                return 'log-error'
              case 'warning':
                return 'log-warning'
              default:
                return ''
            }
          }}
          size="small"
        />
      </Card>
    </div>
  )
}

export default SystemLogs