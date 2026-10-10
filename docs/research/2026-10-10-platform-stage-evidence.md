# 平台核心：WPA2 阶段证据覆盖

2026-10-10。按用户最新要求，停止扩展实验客户端，暂不运行测试，建设平台核心。

新增 src/wifiseclab/stage_evidence.py，定义初始 WPA2-PSK/CCMP 范围下认证、关联、四次握手、授权、受保护数据和清理六阶段的事件需求。接入 APModel.report()['stage_evidence']，因此现有离线 CLI 报告自动包含该视图。history 新增 source 字段，按 peer/session/source 分组；不同会话、终端或 synthetic/instrumentation 的事件不拼成一个完整阶段。清理需要断开事件之一及撤权、删钥、检查点。

此视图只回答需要的事件种类是否出现，状态名为 required_event_kinds_seen/incomplete，不称 passed。发生顺序、M1–M4 各消息、密码校验、密钥槽和具体清理状态仍由模型/专用分析器判断；有违规事件同样可能被计入出现，因此不能把完整覆盖作为正确行为证明。外部 pcap/probe 不进入内部 history，也不填补内部阶段证据。

该契约仅对应近期初始 WPA2 范围；重协商、PMKSA 缓存、FT 等尚需独立契约，不用初始建链要求误判合法保留状态。WPA3/transition 报告暂不提供此视图。

已更新 roadmap 和 reading-log.md。本轮未运行任何测试或执行改动后的模块，代码尚未验证；未改实验客户端、未发包。下一步围绕共用场景编排与证据输入继续建设，暂不回到客户端实现。
