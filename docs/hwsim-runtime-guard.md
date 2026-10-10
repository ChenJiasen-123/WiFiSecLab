# 自定义 hwsim 运行上下文加固

新增 runtime_guard.py；自定义实验使用 ClockAnchor 将同主机 pcap realtime 映射至单调时钟，认证/关联前后及每次提交、监听轮询检查时钟关系和本次 AP/tcpdump 的 pidfd。进程退出或时钟关系异常会毒化上下文，不能恢复旧会话。hwsim_custom_client 成功条件也要求 runner 正常终止及提交完整，构造过 M4 本身不再足够。

实际正常实验：exit 0，M2/M4 各一帧，最终抓包 RSNE 绑定的 MIC 四报文路径验证成功、无上下文异常，AP 授权快照为真。

实际故障实验：hwsim_custom_smoke --stop-capture-after 0.5，只停止本次拥有的抓包进程。M4 已构造、提交两次且 AP 快照授权，但 runner 停在 receive_error，client 与 harness 均 exit 1。证据位于 hwsim-custom-capture-fault/evidence。这个测试证明抓包退出不会被先前成功握手掩盖，不代表所有故障路径已覆盖。

218 项测试通过，包括生产者退出后恢复仍不可复用、采样错误、墙钟跳变和单调时钟倒退。时钟异常仅通过内存测试模拟，未修改用户或远程系统时间。

实验后确认 hwsim 卸载、命名空间为空、实体网卡为 managed。未使用实体网卡发包。上一份 hwsim-custom-handshake.md 中“实时 harness 未采用 ClockAnchor/producer 保护”的限制本轮已处理，其余限制仍成立：不是生产物理适配器验证，自定义 STA 尚无加密数据收发，完整标准/文献精读及更多状态边界仍待继续。
