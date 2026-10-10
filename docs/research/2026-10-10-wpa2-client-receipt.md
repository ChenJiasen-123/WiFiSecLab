# 自构造 WPA2 客户端端点回执

2026-10-10。检查 encrypted_evidence.verify_capture 和 data_evidence.correlate_data 的端点契约后，修改 tools/hwsim/hwsim_custom_client.py：在发送自构造加密 UDP 前创建独立 udp-client.json，保存 role、挑战 token、固定实验端点、started_at 和初始失败标志。仅 DataSession.verified_response 为真时更新 success/application_payload_verified，同时记录 finished_at。

端点地址来自现有 DataSession/LabCcmpUplink 的隔离实验配置，不是发现或推测出的真实网络地址。成功表示自定义客户端验证了匹配 token 的加密响应，不表示内核 UDP 客户端、连续授权、固件密钥安装或安全符合性。client.json 继续是调试/流程报告，udp-client.json 是正式端点记录。

若发送/接收抛异常，初始文件缺 finished_at 且 success=false；正式关联器应拒绝，不能补造结束时间和成功。当前未新增统一异常报告包装，失败原因仍需结合进程输出。后续还需验证该独立记录的序列化与正式分析器集成。

客户端语法检查通过，底层 DataSession 5 项测试通过。初次独立测试缺 src 模块路径，设置 PYTHONPATH 后重跑通过。未执行 Linux/hwsim 客户端、未现场发包，也未据此声称端到端路径已通过。

剩余直接任务：冻结捕获后生成最终 SHA256 绑定；将前置快照规范化为正式分析器输入，同时保留原始采样元数据；生成 data-metadata.json 并运行正式离线分析。随后补断开清理阶段与边界场景。
