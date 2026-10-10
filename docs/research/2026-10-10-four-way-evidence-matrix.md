# WPA2 四次握手：条款、上下文与证据对应表

## 本轮阅读
对 IEEE 802.11-2024 印刷页 3073、12.7.6.7 的图 12-51 进行渲染并逐项核对。此图是样例消息流，不能替代 12.7.6 各消息处理规定与 12.7.10 认证方状态机。图中安装操作与消息先后关系不构成无线可观察的完成证据。

## 对应表
| 阶段 | 必须关联的上下文 | 预期语义与边界 | 当前入口 | 证明缺口 |
|---|---|---|---|---|
| M1 | AP/STA、关联 epoch、AKM、PMK、exchange_id、ANonce | 开始对应交换；不能由无 MIC 的 M1 更新已验证接收计数器 | handshake_message(message=1) | 抽象模型不计算 nonce/PMK 派生关系 |
| M2 | 同一交换、SNonce、关联请求 RSNE、M1 计数器 | AP 验证 MIC 和协商一致性；看到 M2 不等于 AP 接受 | handshake_message(message=2) | 需插桩确认校验结果；pcap 只作 observation |
| M3 | 同一交换、ANonce、AP RSNE、加密 Key Data、GTK RSC | 不能把重传当成新密钥或重置数据计数器的理由 | handshake_message(message=3)、key_installed | 当前抽象事件不完整表达所有 KDE 和协商约束 |
| M4 | 本交换发送过的 M3 计数器历史、有效 MIC、会话已接受响应下界 | 可对应较早的一次 M3；不能仅要求等于最后一次发送计数器 | handshake_message(message=4) | 收到帧与内部接受须独立关联 |
| 密钥安装 | 稳定材料身份、槽位、关联、实际 MAC 操作完成 | 槽位变化不等于材料变化；删除不清除材料使用历史 | key_installed、key_deleted | 主模型安装事件依赖适配器语义，尚未统一完成事件契约 |
| 握手完成 | 交换及消息历史 | 详细交换需到接受 M4；无线 M4 不证明 AP 完成 | handshake_completed | 当前模型报告异常后仍保留实现所声称的状态；这不是标准认可状态 |
| 端口开放 | 关联、完成握手、已安装 PTK | 缺少任一条件输出 EARLY_AUTHORIZATION | port_authorized | 尚需真实端口和密钥插桩联合证据 |
| 用户数据接受 | 材料、SA/TID 域、接收计数器、授权状态 | MIC 成功、ACK、抓到密文均不能单独证明业务数据接受 | data_accepted、rx_counter_configured | 未接入目标 AP 内部采集器 |

## 阅读与实现原则
NDSS 2026 WCDCAnalyzer 的研究对象为 Wi-Fi Direct/EasyConnect/EasyMesh；本轮重访官方摘要关于协议分解与组合推理的说明，仅借鉴“明确子协议接口假设”的方法，不把其结论视为 WPA2 四次握手证明。本表明确列出跨模块交接需要的上下文。
来源：https://www.ndss-symposium.org/ndss-paper/wcdcanalyzer-scalable-security-analysis-of-wi-fi-certified-device-connectivity-protocols/

## 下一项真实缺口
统一主模型密钥安装/删除的完成证据契约，并确认适配器没有把请求事件转换为完成事件。先检查现有生产者和格式，再修改，避免只改消费者破坏既有证据输入。没有进行平台测试、CLI 执行或无线实验。
