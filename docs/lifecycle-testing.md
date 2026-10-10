# 真实进程生命周期测试

在 Kali 项目根目录执行 `sudo python3 tools/hwsim/hwsim_lifecycle.py`。

脚本启动隔离的 hwsim AP/STA，以双方状态、hostapd station flags 和 PMF 状态验证连接、断开与重连。控制器会话编号只用于组织轨迹，不能证明实现内部创建了新会话。

最新的内核密钥证据、报告语义与限制见 [key-lifecycle-evidence.md](key-lifecycle-evidence.md)。结果保存在 reports/lifecycle-*。物理无线网卡不参与本测试。
