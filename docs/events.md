# 事件表

每个事件必填 kind、peer、session、source、evidence，data 为对象。
source: synthetic / instrumentation / pcap / probe。

| kind | data | 含义 |
|---|---|---|
| session_start | 无 | 控制器确认新会话 |
| auth_accepted | akm: psk/sae | 认证路径确认 |
| assoc_accepted | pmf: bool | AP 接受关联 |
| handshake_started/completed | 无 | 抽象握手阶段 |
| key_installed | key_id, slot, counters_reset | 安装生效 |
| key_deleted | slot | 密钥删除 |
| port_authorized/revoked | 无 | 数据端口授权变化 |
| work_pending/cleared | work_id | 待处理资源变化 |
| disassociated/deauthenticated | 无 | AP 内部确认断开 |
| cleanup_checkpoint | 无 | 恢复期限后的检查点 |
| encrypt_new | key_id, nonce_domain, nonce | 新用户数据加密 |
| link_retry | 无 | 重传已有密文 |

抓包/探测来源仅存为观测，不执行上述内部状态转换。未知内部事件拒绝解析。

新增事件字段及路径以 [state-machine.md](state-machine.md) 为准。history 的 before/after 已扩展为完整组合状态；report.state_fields 指明字段顺序，消费者不可再按旧的四字段元组解析。
