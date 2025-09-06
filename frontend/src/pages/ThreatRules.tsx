import React, { useState } from 'react'
import { Table, Card, Button, Tag, Select, Space, Typography, Modal, Form, Input, Switch, Slider, message } from 'antd'
import { EyeOutlined, EditOutlined, DeleteOutlined, PlusOutlined, PlayCircleOutlined, PauseCircleOutlined } from '@ant-design/icons'
import { useQuery, useMutation, useQueryClient } from 'react-query'
import dayjs from 'dayjs'

import { rulesApi } from '../services/api'
import { ThreatRule } from '../types'

const { Title } = Typography
const { Option } = Select
const { TextArea } = Input
const { confirm } = Modal

const ThreatRules: React.FC = () => {
  const [selectedRuleType, setSelectedRuleType] = useState<string>('')
  const [selectedStatus, setSelectedStatus] = useState<string>('')
  const [pageSize, setPageSize] = useState(20)
  const [selectedRule, setSelectedRule] = useState<ThreatRule | null>(null)
  const [detailModalVisible, setDetailModalVisible] = useState(false)
  const [editModalVisible, setEditModalVisible] = useState(false)
  const [createModalVisible, setCreateModalVisible] = useState(false)
  const [form] = Form.useForm()
  const [createForm] = Form.useForm()

  const queryClient = useQueryClient()

  const { data: rules, isLoading } = useQuery(
    ['rules', selectedRuleType, selectedStatus],
    () => rulesApi.getRules({
      rule_type: selectedRuleType || undefined,
      is_enabled: selectedStatus === 'enabled' ? true : selectedStatus === 'disabled' ? false : undefined,
      limit: 1000
    }).then(res => res.data),
    { refetchInterval: 60000 }
  )

  const updateRuleMutation = useMutation(
    ({ id, data }: { id: number, data: any }) => rulesApi.updateRule(id, data),
    {
      onSuccess: () => {
        message.success('Rule updated successfully')
        queryClient.invalidateQueries('rules')
        setEditModalVisible(false)
        form.resetFields()
      },
      onError: () => {
        message.error('Failed to update rule')
      }
    }
  )

  const createRuleMutation = useMutation(
    (data: any) => rulesApi.createRule(data),
    {
      onSuccess: () => {
        message.success('Rule created successfully')
        queryClient.invalidateQueries('rules')
        setCreateModalVisible(false)
        createForm.resetFields()
      },
      onError: () => {
        message.error('Failed to create rule')
      }
    }
  )

  const deleteRuleMutation = useMutation(
    (id: number) => rulesApi.deleteRule(id),
    {
      onSuccess: () => {
        message.success('Rule deleted successfully')
        queryClient.invalidateQueries('rules')
      },
      onError: () => {
        message.error('Failed to delete rule')
      }
    }
  )

  const enableRuleMutation = useMutation(
    (id: number) => rulesApi.enableRule(id),
    {
      onSuccess: () => {
        message.success('Rule enabled')
        queryClient.invalidateQueries('rules')
      },
      onError: () => {
        message.error('Failed to enable rule')
      }
    }
  )

  const disableRuleMutation = useMutation(
    (id: number) => rulesApi.disableRule(id),
    {
      onSuccess: () => {
        message.success('Rule disabled')
        queryClient.invalidateQueries('rules')
      },
      onError: () => {
        message.error('Failed to disable rule')
      }
    }
  )

  const getRuleTypeColor = (ruleType: string) => {
    switch (ruleType) {
      case 'signature': return 'red'
      case 'anomaly': return 'orange'
      case 'behavioral': return 'blue'
      case 'reputation': return 'purple'
      case 'custom': return 'green'
      default: return 'default'
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'red'
      case 'high': return 'orange'
      case 'medium': return 'gold'
      case 'low': return 'green'
      default: return 'default'
    }
  }

  const handleViewDetails = (rule: ThreatRule) => {
    setSelectedRule(rule)
    setDetailModalVisible(true)
  }

  const handleEditRule = (rule: ThreatRule) => {
    setSelectedRule(rule)
    form.setFieldsValue({
      name: rule.name,
      description: rule.description,
      rule_content: rule.rule_content,
      severity: rule.severity,
      is_enabled: rule.is_enabled,
      confidence: rule.confidence,
      tags: rule.tags
    })
    setEditModalVisible(true)
  }

  const handleDeleteRule = (rule: ThreatRule) => {
    confirm({
      title: 'Delete Rule',
      content: `Are you sure you want to delete "${rule.name}"?`,
      icon: <DeleteOutlined />,
      okText: 'Delete',
      okType: 'danger',
      onOk: () => deleteRuleMutation.mutate(rule.id),
    })
  }

  const handleToggleRule = (rule: ThreatRule) => {
    if (rule.is_enabled) {
      disableRuleMutation.mutate(rule.id)
    } else {
      enableRuleMutation.mutate(rule.id)
    }
  }

  const handleUpdateRule = (values: any) => {
    if (!selectedRule) return
    updateRuleMutation.mutate({
      id: selectedRule.id,
      data: values
    })
  }

  const handleCreateRule = (values: any) => {
    createRuleMutation.mutate(values)
  }

  const columns = [
    {
      title: 'Status',
      dataIndex: 'is_enabled',
      key: 'is_enabled',
      width: 80,
      render: (isEnabled: boolean) => (
        <Tag color={isEnabled ? 'green' : 'red'}>
          {isEnabled ? 'Enabled' : 'Disabled'}
        </Tag>
      ),
    },
    {
      title: 'Name',
      dataIndex: 'name',
      key: 'name',
      ellipsis: true,
    },
    {
      title: 'Type',
      dataIndex: 'rule_type',
      key: 'rule_type',
      width: 120,
      render: (ruleType: string) => (
        <Tag color={getRuleTypeColor(ruleType)}>
          {ruleType?.replace('_', ' ').toUpperCase()}
        </Tag>
      ),
    },
    {
      title: 'Severity',
      dataIndex: 'severity',
      key: 'severity',
      width: 100,
      render: (severity: string) => (
        <Tag color={getSeverityColor(severity)}>{severity?.toUpperCase()}</Tag>
      ),
    },
    {
      title: 'Confidence',
      dataIndex: 'confidence',
      key: 'confidence',
      width: 100,
      render: (confidence: number) => `${confidence}%`,
      sorter: (a: ThreatRule, b: ThreatRule) => a.confidence - b.confidence,
    },
    {
      title: 'Created',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 160,
      render: (date: string) => date ? dayjs(date).format('YYYY-MM-DD HH:mm:ss') : '-',
      sorter: (a: ThreatRule, b: ThreatRule) => {
        if (!a.created_at || !b.created_at) return 0
        return dayjs(a.created_at).unix() - dayjs(b.created_at).unix()
      },
      defaultSortOrder: 'descend' as const,
    },
    {
      title: 'Actions',
      key: 'actions',
      width: 200,
      render: (_: any, record: ThreatRule) => (
        <Space>
          <Button
            size="small"
            icon={<EyeOutlined />}
            onClick={() => handleViewDetails(record)}
          />
          <Button
            size="small"
            icon={<EditOutlined />}
            onClick={() => handleEditRule(record)}
          />
          <Button
            size="small"
            icon={record.is_enabled ? <PauseCircleOutlined /> : <PlayCircleOutlined />}
            onClick={() => handleToggleRule(record)}
            loading={enableRuleMutation.isLoading || disableRuleMutation.isLoading}
          />
          <Button
            size="small"
            danger
            icon={<DeleteOutlined />}
            onClick={() => handleDeleteRule(record)}
            loading={deleteRuleMutation.isLoading}
          />
        </Space>
      ),
    },
  ]

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
        <Title level={2}>Threat Detection Rules</Title>
        <Space>
          <Select
            placeholder="Filter by Type"
            style={{ width: 150 }}
            allowClear
            value={selectedRuleType || undefined}
            onChange={setSelectedRuleType}
          >
            <Option value="signature">Signature</Option>
            <Option value="anomaly">Anomaly</Option>
            <Option value="behavioral">Behavioral</Option>
            <Option value="reputation">Reputation</Option>
            <Option value="custom">Custom</Option>
          </Select>
          <Select
            placeholder="Filter by Status"
            style={{ width: 150 }}
            allowClear
            value={selectedStatus || undefined}
            onChange={setSelectedStatus}
          >
            <Option value="enabled">Enabled</Option>
            <Option value="disabled">Disabled</Option>
          </Select>
          <Button
            type="primary"
            icon={<PlusOutlined />}
            onClick={() => setCreateModalVisible(true)}
          >
            Create Rule
          </Button>
        </Space>
      </div>

      <Card>
        <Table
          columns={columns}
          dataSource={rules || []}
          rowKey="id"
          loading={isLoading}
          pagination={{
            pageSize,
            showSizeChanger: true,
            showQuickJumper: true,
            showTotal: (total, range) => `${range[0]}-${range[1]} of ${total} rules`,
            onShowSizeChange: (_, size) => setPageSize(size),
          }}
        />
      </Card>

      {/* Rule Detail Modal */}
      <Modal
        title="Rule Details"
        open={detailModalVisible}
        onCancel={() => setDetailModalVisible(false)}
        footer={null}
        width={800}
      >
        {selectedRule && (
          <div>
            <Space direction="vertical" style={{ width: '100%' }}>
              <div>
                <strong>Name:</strong> {selectedRule.name}
              </div>
              <div>
                <strong>Description:</strong> {selectedRule.description}
              </div>
              <div>
                <strong>Type:</strong> <Tag color={getRuleTypeColor(selectedRule.rule_type)}>{selectedRule.rule_type?.replace('_', ' ').toUpperCase()}</Tag>
              </div>
              <div>
                <strong>Severity:</strong> <Tag color={getSeverityColor(selectedRule.severity)}>{selectedRule.severity?.toUpperCase()}</Tag>
              </div>
              <div>
                <strong>Status:</strong> <Tag color={selectedRule.is_enabled ? 'green' : 'red'}>{selectedRule.is_enabled ? 'Enabled' : 'Disabled'}</Tag>
              </div>
              <div>
                <strong>Confidence:</strong> {selectedRule.confidence}%
              </div>
              <div>
                <strong>Tags:</strong> {selectedRule.tags || 'None'}
              </div>
              <div>
                <strong>MITRE ATT&CK ID:</strong> {selectedRule.mitre_attack_id || 'None'}
              </div>
              <div>
                <strong>Created By:</strong> {selectedRule.created_by || 'System'}
              </div>
              <div>
                <strong>Created:</strong> {selectedRule.created_at ? dayjs(selectedRule.created_at).format('YYYY-MM-DD HH:mm:ss') : 'N/A'}
              </div>
              <div>
                <strong>Rule Content:</strong>
                <pre style={{ background: '#000', padding: '12px', borderRadius: '4px', maxHeight: '200px', overflow: 'auto' }}>
                  {JSON.stringify(JSON.parse(selectedRule.rule_content), null, 2)}
                </pre>
              </div>
            </Space>
          </div>
        )}
      </Modal>

      {/* Edit Rule Modal */}
      <Modal
        title="Edit Rule"
        open={editModalVisible}
        onCancel={() => {
          setEditModalVisible(false)
          form.resetFields()
        }}
        onOk={() => form.submit()}
        confirmLoading={updateRuleMutation.isLoading}
        width={800}
      >
        <Form
          form={form}
          layout="vertical"
          onFinish={handleUpdateRule}
        >
          <Form.Item
            label="Name"
            name="name"
            rules={[{ required: true, message: 'Please enter rule name' }]}
          >
            <Input placeholder="Rule name" />
          </Form.Item>
          
          <Form.Item
            label="Description"
            name="description"
          >
            <TextArea placeholder="Rule description" rows={3} />
          </Form.Item>
          
          <Form.Item
            label="Severity"
            name="severity"
            rules={[{ required: true, message: 'Please select severity' }]}
          >
            <Select placeholder="Select severity">
              <Option value="low">Low</Option>
              <Option value="medium">Medium</Option>
              <Option value="high">High</Option>
              <Option value="critical">Critical</Option>
            </Select>
          </Form.Item>
          
          <Form.Item
            label="Enabled"
            name="is_enabled"
            valuePropName="checked"
          >
            <Switch />
          </Form.Item>
          
          <Form.Item
            label="Confidence (%)"
            name="confidence"
          >
            <Slider
              min={0}
              max={100}
              step={5}
              marks={{
                0: '0%',
                25: '25%',
                50: '50%',
                75: '75%',
                100: '100%'
              }}
            />
          </Form.Item>
          
          <Form.Item
            label="Tags"
            name="tags"
          >
            <Input placeholder="Comma-separated tags" />
          </Form.Item>
        </Form>
      </Modal>

      {/* Create Rule Modal */}
      <Modal
        title="Create New Rule"
        open={createModalVisible}
        onCancel={() => {
          setCreateModalVisible(false)
          createForm.resetFields()
        }}
        onOk={() => createForm.submit()}
        confirmLoading={createRuleMutation.isLoading}
        width={800}
      >
        <Form
          form={createForm}
          layout="vertical"
          onFinish={handleCreateRule}
          initialValues={{
            rule_type: 'custom',
            severity: 'medium',
            is_enabled: true,
            confidence: 50,
          }}
        >
          <Form.Item
            label="Name"
            name="name"
            rules={[{ required: true, message: 'Please enter rule name' }]}
          >
            <Input placeholder="Rule name" />
          </Form.Item>
          
          <Form.Item
            label="Description"
            name="description"
            rules={[{ required: true, message: 'Please enter description' }]}
          >
            <TextArea placeholder="Rule description" rows={3} />
          </Form.Item>
          
          <Form.Item
            label="Rule Type"
            name="rule_type"
            rules={[{ required: true, message: 'Please select rule type' }]}
          >
            <Select placeholder="Select rule type">
              <Option value="signature">Signature</Option>
              <Option value="anomaly">Anomaly</Option>
              <Option value="behavioral">Behavioral</Option>
              <Option value="reputation">Reputation</Option>
              <Option value="custom">Custom</Option>
            </Select>
          </Form.Item>
          
          <Form.Item
            label="Rule Content (JSON)"
            name="rule_content"
            rules={[{ required: true, message: 'Please enter rule content' }]}
          >
            <TextArea 
              placeholder="JSON rule configuration"
              rows={8}
            />
          </Form.Item>
          
          <Form.Item
            label="Severity"
            name="severity"
            rules={[{ required: true, message: 'Please select severity' }]}
          >
            <Select placeholder="Select severity">
              <Option value="low">Low</Option>
              <Option value="medium">Medium</Option>
              <Option value="high">High</Option>
              <Option value="critical">Critical</Option>
            </Select>
          </Form.Item>
          
          <Form.Item
            label="Confidence (%)"
            name="confidence"
          >
            <Slider
              min={0}
              max={100}
              step={5}
              marks={{
                0: '0%',
                25: '25%',
                50: '50%',
                75: '75%',
                100: '100%'
              }}
            />
          </Form.Item>
          
          <Form.Item
            label="Tags"
            name="tags"
          >
            <Input placeholder="Comma-separated tags" />
          </Form.Item>
          
          <Form.Item
            label="MITRE ATT&CK ID"
            name="mitre_attack_id"
          >
            <Input placeholder="e.g., T1055" />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  )
}

export default ThreatRules