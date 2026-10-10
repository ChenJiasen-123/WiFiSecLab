# 手机热点实验正式入口

所有实验逻辑现已纳入 WiFiSecLab，不依赖聊天目录的 work 脚本、SSH 密码、固定 IP 或特定手机名称。Linux 实验机安装项目后可使用 `wifiseclab-hotspot`；未安装时，在项目目录使用 `python3 tools/protocol/hotspot.py`。只依赖 Python 标准库，不需要 Scapy。现场执行需 root、iw、ip、tcpdump；若机器安装并使用 NetworkManager，还需要 nmcli 可正常查询状态。

## 发现热点（被动）

```bash
sudo python3 tools/protocol/hotspot.py discover --ssid '你的热点名称' --output reports/hotspot-discover-001
# 已知信道时只监听该信道，缩短测试时间
sudo python3 tools/protocol/hotspot.py discover --ssid '你的热点名称' --channels 10 --duration 3 --output reports/hotspot-discover-002
```

默认扫描 1..11 信道，每信道 2 秒，两卡始终设置为相同信道。按 SSID 筛选广播和探测响应，输出 BSSID、帧计数、声明的信道、RSN 加密/AKM 套件、PMF 能力。当前标准库解析器不输出信号强度；需要时可在原始 radiotap 抓包中查看。不支持这两块卡组合的 5 GHz/信道 12、13 实验。

## 离线构造请求（不发包）

```bash
python3 tools/protocol/hotspot.py build --kind auth --ssid '你的热点名称' --bssid 12:34:56:78:9a:bc --output reports/auth-request-001
python3 tools/protocol/hotspot.py build --kind probe --ssid '你的热点名称' --bssid 12:34:56:78:9a:bc --output reports/probe-request-001
```

输出 request.bin 与 request.json。auth 是 Open System 算法 0、事务序号 1、状态码 0；probe 是携带指定 SSID 的普通广播探测请求。默认生成独立的本地管理单播源 MAC；可用 `--source` 指定。二进制不含 radiotap/FCS，可作为 physical_radio.py 的 --frame 输入。

## 单次主动实验

先使用 discover 获取当前 BSSID 和信道，再执行：

```bash
sudo python3 tools/protocol/hotspot.py probe --ssid '你的热点名称' --bssid 12:34:56:78:9a:bc --channel 10 --output reports/hotspot-probe-001
sudo python3 tools/protocol/hotspot.py auth --ssid '你的热点名称' --bssid 12:34:56:78:9a:bc --channel 10 --output reports/hotspot-auth-001
```

两种入口均先独立抓包 2 秒，确认同名、同 BSSID、同信道的 Beacon；auth 还要求无解析错误且广播包含 WPA2-PSK AKM。目标不匹配时不发包并报告 preflight_confirmed=false。通过后只调用发送一次，默认监听 4 秒。无线驱动可能自动重传，这与程序主动提交次数分开记录。--duration 控制响应窗口或发现时每个信道的驻留时间，上限 30 秒。

输出 air.pcap、capture.log、request.bin（主动实验）、physical-report.json 和 hotspot-report.json。输出目录必须不存在，以保留历史证据。响应按目标源/BSSID、本次请求源 MAC、SSID（probe）或认证算法及事务序号（auth）、捕获顺序和时间窗进行关联。报告中的 packet_index 从 1 开始，指向该目录的 air.pcap。

认证响应 status_code=0 只表示 Open System 认证阶段成功，不是已关联、验证密码或建立密钥；不会生成 APModel 的内部 key_installed/data_accepted 等事件。WPA2 四次握手尚未实现。

## 自动执行认证与关联

```bash
sudo python3 tools/protocol/hotspot.py associate --ssid '你的热点名称' --bssid 12:34:56:78:9a:bc --channel 10 --output reports/hotspot-associate-001
```

预检热点后，从广播中选择传统 2.4 GHz 速率以及 WPA2 PSK/CCMP 套件；不复制整个 RSN 套件列表。不支持要求 PMF、SAE-only、TKIP group cipher 或未知 basic rate 的目标。以同一源 MAC 发认证请求，只有独立监听到请求及明确成功响应才发关联请求。拒绝、无响应、未观察到请求、矛盾状态码均停止；关联成功还检查传统 AID 的保留位及 1..2007 范围。每步一次程序提交，驱动可自行重传。

除原输出外，保存 authentication-request.bin、association-request.bin（执行到该步时），报告包含 sequence.steps，每步附现场及最终严格抓包复核证据。返回成功仅表示两步的成功响应都被关联观察到；不表示 AP 内部状态、密码、密钥安装、四次握手或数据授权已验证。新源 MAC 不证明 AP 已重置。整个流程最多等待两段 --duration，另加预检时间。

本轮验证：82 项测试通过，含正式 associate CLI 的模拟双步执行及认证拒绝后停止。尚未执行真实热点或 hwsim 的新关联链路；协议阅读进度与验证缺口见 research/reading-log.md。

## 离线复核

```bash
python3 tools/protocol/hotspot.py analyze --ssid '你的热点名称' --bssid 12:34:56:78:9a:bc --pcap reports/hotspot-auth-001/air.pcap --request reports/hotspot-auth-001/request.bin
```

离线分析不需要 Linux、root 或无线网卡。--request 可省略以仅分析热点广播。最终分析严格拒绝损坏/截断 pcap；现场预检只允许忽略尚未写完的尾部记录。报告分别记录逐字节匹配与语义匹配；管理帧语义匹配只允许 Duration、Retry 和序列号改写，保留片段编号，并严格匹配其他标志、地址、帧类型和内容。重传不代表多次独立实验。

## 接口管理与退出

抓包质量字段 `capture_quality` 分开统计原始记录数、进入分析的帧、驱动报告坏 FCS、软件校验失败及未提供 FCS。只在 radiotap 标志声明 FCS 时校验 CRC 并剥离；未声明时绝不猜测尾部。Snapshot 截包或元数据损坏使分析失败，即使记录本身写入完整。未完整解释的 padded 布局被排除。IE 截断或关键字段重复记录在 `invalid_management`，不能用于目标预检及响应判定。RSN 可选字段不完整、MFPR 无 MFPC 等错误会阻止主动认证预检。

上述改进后 Windows 上共 87 项测试通过；新改动尚未在 Kali 重跑。历史热点抓包仍识别到 8 个认证请求和 34 个响应，120 条记录都未提供 FCS，因此报告只能说明未验证 FCS，不能宣称 CRC 已通过。

NetworkGuard 按选中的接口动态记录 managed 状态及 UP/DOWN 标志。先确认两块无线电均未连接，再临时暂停 NetworkManager 管理、关闭原 managed 接口，以免后台扫描打断监听信道。PhysicalRadioAdapter 只创建并删除自己拥有的 wslabtx/wslabrx；结束后 NetworkGuard 恢复原 UP/DOWN 和 managed 状态。恢复某一步失败时继续尝试其余步骤，并把错误保留在报告中。并不强制固定 NetworkManager 恢复后选择的随机 MAC。

正常退出、异常、Ctrl+C、SIGTERM 会进入清理；SIGKILL 或断电无法执行清理。其他网络管理程序不在本模块控制范围。不会恢复或重置真实 AP 的内部会话。

现场命令退出码：0=发现目标或收到所需响应（auth 要求成功状态）；1=未发现、预检不符、未确认响应或认证被拒绝；2=执行、抓包、解析或恢复失败。离线 analyze 退出码 0 只说明分析完成，结论以 JSON 为准。

## 验证

76 项单元测试覆盖角色校验、帧构造、驱动改写与错误匹配、重传、过早/过晚/错误地址响应、认证拒绝、损坏 pcap、正式 CLI 的预检和单次发送、NetworkManager 部分失败与恢复。

使用先前真实手机热点认证抓包运行正式 analyze 入口：识别 8 个请求帧（7 个 Retry）、34 个响应帧（32 个 Retry），成功状态 0。源请求的序列号被驱动改写，逐字节匹配为 false、语义匹配为 true；不再将其误报为“未观测到请求”。

Windows 与 Kali 上的 76 项测试均通过。Kali 上直接运行项目 tools/protocol/hotspot.py discover（信道 10、3 秒）识别到 27 个 Beacon 和 10 个 Probe Response，提交帧数为 0，退出码 0，无抓包或恢复错误。
