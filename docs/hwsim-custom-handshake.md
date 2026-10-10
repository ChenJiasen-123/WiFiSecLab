# 自定义握手 Linux hwsim 实时验证

项目新增 tools/hwsim/hwsim_custom_smoke.py 和 tools/hwsim/hwsim_custom_client.py。前者创建两个独立虚拟 PHY 和命名空间、自建 PSK/CCMP AP，后者调用项目现有 run_sequence、admitted_session、CaptureTransport、run_handshake 来实时构造认证、关联、M2 和 M4。运行前拒绝已有 hwsim/实验命名空间；检查 PHY 驱动，只允许 mac80211_hwsim。只清理本次创建的命名空间及模块。

真实实验先发现：普通 monitor 收到成功认证/关联响应，但 hostapd 日志显示 ack=0，没有启动 M1。启用虚拟接口 active monitor 后握手成功。Linux 官方定义该模式会 ACK 发往自身 MAC 的帧：https://kernel.org/doc/html/v4.16/driver-api/80211/cfg80211.html 。此发现不等于实体网卡支持 active monitor，也未修改实体适配器配置。

最终版本再次实际运行：认证/关联成功；项目构造并提交 M2、M4 各一帧；最终 air.pcap 经独立分析，四报文 MIC 和 RSNE 绑定均通过，context_anomalies 为空；hostapd 的该 STA 快照出现 AUTH/ASSOC/AUTHORIZED。client_exit_code 与 harness exit_code 均为 0。报告位于 hwsim-custom-verification/handshake-analysis.json，原始证据在 evidence/。

214 项单元测试通过。两次成功运行之后均只读确认 hwsim 已卸载、实验命名空间为空、实体网卡仍为 managed 模式。

范围和缺口：这是 hwsim 的专用实验 harness，没有跑生产 PhysicalRadioAdapter 路径。临时实时 harness 使用同主机 realtime 进行会话时限，未采用生产 ClockAnchor；时钟跳变处理与 capture producer 失效保护仍需加固。仅观察 AP 控制端授权采样，不证明固件密钥身份或持续状态。自定义 STA 尚未安装 TK、实现加密数据发包，因此此前标准 supplicant 的 UDP 往返不能冒充本轮自定义握手的数据面完成。全标准和近 30 年论文精读、SAE/FT/PMF、边界测试及自主测试调度仍未完成。
