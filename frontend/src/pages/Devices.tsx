import React, { useState } from 'react'
import { Table, Card, Button, Tag, Select, Space, Typography, Modal, Form, Input, Slider, message } from 'antd'
import { EyeOutlined, EditOutlined, WifiOutlined } from '@ant-design/icons'
import { useQuery, useMutation, useQueryClient } from 'react-query'
import dayjs from 'dayjs'

import { devicesApi } from '../services/api'
import { Device } from '../types'

const { Title } = Typography
const { Option } = Select

const Devices: React.FC = () => {
  const [selectedDeviceType, setSelectedDeviceType] = useState<string>('')
  const [selectedStatus, setSelectedStatus] = useState<string>('')
  const [pageSize, setPageSize] = useState(20)
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null)
  const [detailModalVisible, setDetailModalVisible] = useState(false)
  const [editModalVisible, setEditModalVisible] = useState(false)
  const [form] = Form.useForm()

  const queryClient = useQueryClient()

  const { data: devices, isLoading } = useQuery(
    ['devices', selectedDeviceType, selectedStatus],
    () => devicesApi.getDevices({
      device_type: selectedDeviceType || undefined,
      is_active: selectedStatus === 'active' ? true : selectedStatus === 'inactive' ? false : undefined,
      limit: 1000
    }).then(res => res.data),
    { refetchInterval: 30000 }
  )

  const updateDeviceMutation = useMutation(
    ({ id, data }: { id: number, data: any }) => devicesApi.updateDevice(id, data),
    {
      onSuccess: () => {
        message.success('Device updated successfully')
        queryClient.invalidateQueries('devices')
        setEditModalVisible(false)
        form.resetFields()
      },
      onError: () => {
        message.error('Failed to update device')
      }
    }
  )

  const getDeviceTypeColor = (deviceType: string) => {
    switch (deviceType) {
      case 'camera': return 'red'
      case 'smart_speaker': return 'blue'
      case 'smart_tv': return 'purple'
      case 'smart_plug': return 'green'
      case 'sensor': return 'orange'
      case 'thermostat': return 'cyan'
      case 'light_bulb': return 'yellow'
      case 'router': return 'magenta'
      case 'hub': return 'lime'
      case 'printer': return 'gold'
      case 'nas': return 'volcano'
      default: return 'default'
    }
  }

  const getDeviceTypeLabel = (deviceType: string) => {
    return deviceType?.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()) || 'Unknown'
  }

  const getTrustScoreColor = (score: number) => {
    if (score >= 0.8) return '#52c41a'
    if (score >= 0.6) return '#faad14'
    if (score >= 0.4) return '#fa8c16'
    return '#ff4d4f'
  }

  const handleViewDetails = (device: Device) => {
    setSelectedDevice(device)
    setDetailModalVisible(true)
  }

  const handleEditDevice = (device: Device) => {
    setSelectedDevice(device)
    form.setFieldsValue({
      device_type: device.device_type,
      description: device.description,
      trust_score: device.trust_score
    })
    setEditModalVisible(true)
  }

  const handleUpdateDevice = (values: any) => {
    if (!selectedDevice) return
    updateDeviceMutation.mutate({
      id: selectedDevice.id,
      data: values
    })
  }

  const columns = [
    {
      title: 'Status',
      dataIndex: 'is_active',
      key: 'is_active',
      width: 80,
      render: (isActive: boolean) => (
        <WifiOutlined style={{ color: isActive ? '#52c41a' : '#8c8c8c', fontSize: '16px' }} />
      ),
    },
    {
      title: 'Device Type',
      dataIndex: 'device_type',
      key: 'device_type',
      width: 120,
      render: (deviceType: string) => (
        <Tag color={getDeviceTypeColor(deviceType)}>
          {getDeviceTypeLabel(deviceType)}
        </Tag>
      ),
    },
    {
      title: 'IP Address',
      dataIndex: 'ip_address',
      key: 'ip_address',
      width: 120,
    },
    {
      title: 'MAC Address',
      dataIndex: 'mac_address',
      key: 'mac_address',
      width: 140,
      render: (mac: string) => (
        <code style={{ fontSize: '12px' }}>{mac}</code>
      ),
    },
    {
      title: 'Hostname',
      dataIndex: 'hostname',
      key: 'hostname',
      ellipsis: true,
      render: (hostname: string) => hostname || '-',
    },
    {
      title: 'Manufacturer',
      dataIndex: 'manufacturer',
      key: 'manufacturer',
      width: 120,
      render: (manufacturer: string) => manufacturer || '-',
    },
    {
      title: 'Trust Score',
      dataIndex: 'trust_score',
      key: 'trust_score',
      width: 100,
      render: (score: number) => (
        <span style={{ color: getTrustScoreColor(score), fontWeight: 'bold' }}>
          {(score * 100).toFixed(0)}%
        </span>
      ),
      sorter: (a: Device, b: Device) => a.trust_score - b.trust_score,
    },
    {
      title: 'Last Seen',
      dataIndex: 'last_seen',
      key: 'last_seen',
      width: 160,
      render: (date: string) => date ? dayjs(date).format('YYYY-MM-DD HH:mm:ss') : '-',
      sorter: (a: Device, b: Device) => {
        if (!a.last_seen || !b.last_seen) return 0
        return dayjs(a.last_seen).unix() - dayjs(b.last_seen).unix()
      },
      defaultSortOrder: 'descend' as const,
    },
    {
      title: 'Actions',
      key: 'actions',
      width: 120,
      render: (_: any, record: Device) => (
        <Space>
          <Button
            size="small"
            icon={<EyeOutlined />}
            onClick={() => handleViewDetails(record)}
          />
          <Button
            size="small"
            icon={<EditOutlined />}
            onClick={() => handleEditDevice(record)}
          />
        </Space>
      ),
    },
  ]

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
        <Title level={2}>Network Devices</Title>
        <Space>
          <Select
            placeholder="Filter by Type"
            style={{ width: 150 }}
            allowClear
            value={selectedDeviceType || undefined}
            onChange={setSelectedDeviceType}
          >
            <Option value="camera">Camera</Option>
            <Option value="smart_speaker">Smart Speaker</Option>
            <Option value="smart_tv">Smart TV</Option>
            <Option value="smart_plug">Smart Plug</Option>
            <Option value="sensor">Sensor</Option>
            <Option value="thermostat">Thermostat</Option>
            <Option value="light_bulb">Light Bulb</Option>
            <Option value="router">Router</Option>
            <Option value="hub">Hub</Option>
            <Option value="printer">Printer</Option>
            <Option value="nas">NAS</Option>
          </Select>
          <Select
            placeholder="Filter by Status"
            style={{ width: 150 }}
            allowClear
            value={selectedStatus || undefined}
            onChange={setSelectedStatus}
          >
            <Option value="active">Active</Option>
            <Option value="inactive">Inactive</Option>
          </Select>
        </Space>
      </div>

      <Card>
        <Table
          columns={columns}
          dataSource={devices || []}
          rowKey="id"
          loading={isLoading}
          pagination={{
            pageSize,
            showSizeChanger: true,
            showQuickJumper: true,
            showTotal: (total, range) => `${range[0]}-${range[1]} of ${total} devices`,
            onShowSizeChange: (_, size) => setPageSize(size),
          }}
          rowClassName={(record) => record.is_active ? '' : 'device-inactive'}
        />
      </Card>

      {/* Device Detail Modal */}
      <Modal
        title="Device Details"
        open={detailModalVisible}
        onCancel={() => setDetailModalVisible(false)}
        footer={null}
        width={800}
      >
        {selectedDevice && (
          <div>
            <Space direction="vertical" style={{ width: '100%' }}>
              <div>
                <strong>Device Type:</strong> <Tag color={getDeviceTypeColor(selectedDevice.device_type || '')}>{getDeviceTypeLabel(selectedDevice.device_type || '')}</Tag>
              </div>
              <div>
                <strong>IP Address:</strong> {selectedDevice.ip_address}
              </div>
              <div>
                <strong>MAC Address:</strong> <code>{selectedDevice.mac_address}</code>
              </div>
              <div>
                <strong>Hostname:</strong> {selectedDevice.hostname || 'N/A'}
              </div>
              <div>
                <strong>Manufacturer:</strong> {selectedDevice.manufacturer || 'Unknown'}
              </div>
              <div>
                <strong>Model:</strong> {selectedDevice.model || 'Unknown'}
              </div>
              <div>
                <strong>Firmware Version:</strong> {selectedDevice.firmware_version || 'Unknown'}
              </div>
              <div>
                <strong>Status:</strong> {selectedDevice.is_active ? <Tag color="green">Active</Tag> : <Tag color="red">Inactive</Tag>}
              </div>
              <div>
                <strong>Trust Score:</strong> 
                <span style={{ color: getTrustScoreColor(selectedDevice.trust_score), fontWeight: 'bold', marginLeft: '8px' }}>
                  {(selectedDevice.trust_score * 100).toFixed(0)}%
                </span>
              </div>
              <div>
                <strong>First Seen:</strong> {selectedDevice.first_seen ? dayjs(selectedDevice.first_seen).format('YYYY-MM-DD HH:mm:ss') : 'N/A'}
              </div>
              <div>
                <strong>Last Seen:</strong> {selectedDevice.last_seen ? dayjs(selectedDevice.last_seen).format('YYYY-MM-DD HH:mm:ss') : 'N/A'}
              </div>
              <div>
                <strong>Description:</strong> {selectedDevice.description || 'No description'}
              </div>
            </Space>
          </div>
        )}
      </Modal>

      {/* Edit Device Modal */}
      <Modal
        title="Edit Device"
        open={editModalVisible}
        onCancel={() => {
          setEditModalVisible(false)
          form.resetFields()
        }}
        onOk={() => form.submit()}
        confirmLoading={updateDeviceMutation.isLoading}
      >
        <Form
          form={form}
          layout="vertical"
          onFinish={handleUpdateDevice}
        >
          <Form.Item
            label="Device Type"
            name="device_type"
            rules={[{ required: true, message: 'Please select device type' }]}
          >
            <Select placeholder="Select device type">
              <Option value="unknown">Unknown</Option>
              <Option value="camera">Camera</Option>
              <Option value="smart_speaker">Smart Speaker</Option>
              <Option value="smart_tv">Smart TV</Option>
              <Option value="smart_plug">Smart Plug</Option>
              <Option value="sensor">Sensor</Option>
              <Option value="thermostat">Thermostat</Option>
              <Option value="light_bulb">Light Bulb</Option>
              <Option value="router">Router</Option>
              <Option value="hub">Hub</Option>
              <Option value="printer">Printer</Option>
              <Option value="nas">NAS</Option>
            </Select>
          </Form.Item>
          
          <Form.Item
            label="Trust Score"
            name="trust_score"
            rules={[{ required: true, message: 'Please set trust score' }]}
          >
            <Slider
              min={0}
              max={1}
              step={0.1}
              marks={{
                0: '0%',
                0.2: '20%',
                0.4: '40%',
                0.6: '60%',
                0.8: '80%',
                1: '100%'
              }}
            />
          </Form.Item>
          
          <Form.Item
            label="Description"
            name="description"
          >
            <Input.TextArea
              placeholder="Device description..."
              rows={3}
            />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  )
}

export default Devices