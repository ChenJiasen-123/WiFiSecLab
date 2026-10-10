# 物理双网卡执行与当前链路

## 已实现的执行入口

`src/wifiseclab/physical.py` 提供 PhysicalRadioAdapter：

1. 根据 USB 身份、驱动及信道能力绑定 AR9271 为 injector、MT7612U 为 listener。
2. 拒绝已连接、存在额外虚拟接口或临时接口名称冲突的无线电，避免影响现有会话。
3. 创建 wslabtx、wslabrx 两个临时监听模式接口，设置同一 2.4 GHz 信道。
4. 先启动 MT7612U 上的 tcpdump，确认 pcap 文件头就绪后才允许发送。
5. AF_PACKET 原始套接字只绑定 AR9271 的 wslabtx，提交一帧带 radiotap 的 802.11 管理帧或数据帧。
6. 结束抓包，检查独立 pcap 中是否有相同帧，输出动作 SHA256、原始帧、捕获帧数、匹配数及清理错误。
7. 正常结束、Python 异常、Ctrl+C 或 CLI SIGTERM 时停止抓包并删除自己创建的接口。SIGKILL/断电无法运行清理；原 managed 接口不删除，测试选定的 PHY 信道不做额外回调。

Linux/root 环境执行；目录必须不存在：

```bash
# 仅被动抓包
sudo python3 tools/radio/physical_radio.py --channel 6 --duration 3 --output reports/physical-passive-001
# 提交一次实验帧；文件必须为不含 radiotap/FCS 的二进制 802.11 帧
sudo python3 tools/radio/physical_radio.py --channel 6 --duration 3 --frame experiment-frame.bin --output reports/physical-send-001
```

默认不发包。指定 --frame 时仅提交一次；时长上限 60 秒。退出码 0 表示捕获/清理正常（发送模式还需有匹配观测），1 表示本轮未找到匹配帧、结果未知，2 表示捕获或清理报告错误；启动异常退出非零并保留诊断。

输出 `air.pcap`、`capture.log`、`physical-report.json`。提交成功只表明内核接受数据；独立捕获匹配表明监听卡观测到相应帧，不自动证明 AP 接受或状态变化。严格匹配与管理帧语义匹配分别计数；语义匹配允许 Duration、Retry、序列号被改写，其他字段与片段编号必须匹配。FCS 由 radiotap 标志明确指示后校验、剥离，不猜测四字节尾部。坏 FCS 被排除，未提供 FCS 则记录不可验证。重复相同帧的多次动作无法仅凭匹配分别归因。tools/radio/physical_radio.py 会暂停并恢复 NetworkManager 管理以避免后台扫描干扰。热点探测/认证帧的自动构造及响应关联已由 tools/protocol/hotspot.py 提供，详见 hotspot-testing.md；完整重放计划和 PHY 速率控制尚未实现。

## 本轮验证

61 项单元测试通过，覆盖角色错配、编号变化、单帧发送接口约束、捕获前禁止发送、pcap 匹配和损坏、部分初始化失败后的清理及已有输出目录保护。

在 100.97.21.95 上运行实际新适配器：信道 6 被动测试捕获 163 帧；单帧测试发送一个带随机 SSID 标识的普通 Probe Request，监听卡共捕获 175 帧，其中一帧与发送帧字节匹配。两轮均无清理错误，结束后只剩原 wlan0/wlan1 managed 接口。此结果只验证该信道上的这类帧，不代表任意无线帧或所有信道都验证过。

## 当前功能链路

物理链：实验帧文件 → 硬件角色/信道校验 → 双监听模式接口 → 独立抓包启动 → AR9271 单帧提交 → MT7612U 抓包 → 帧匹配/证据报告 → 清理。

模型链：合成或插桩事件 JSON → Event.parse → APModel 状态与性质检查 → 候选异常/覆盖率报告。

hwsim 链：模拟 AP/STA → hostapd/wpa_supplicant → 连接/断开/重连 → 控制状态快照、内核密钥调用返回、pcap → 生命周期/密钥证据报告。

物理链已贯通到独立空口观测。物理捕获到真实 AP 内部状态之间尚未接通：需要真实 AP 的日志/控制接口/插桩、目标和会话关联、可重复 reset，以及按协议构建实验动作。不能直接把 pcap 转成 key_installed、data_accepted 等内部接受事件，也不能依据本轮发包声称发现漏洞。
