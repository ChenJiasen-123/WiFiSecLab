# 隔离正常数据面验证

项目新增 tools/hwsim/hwsim_udp.py，hwsim_smoke.py 在成功连接后执行一次有界 UDP 请求响应。使用独立 hwsim AP/STA 命名空间、192.0.2.1/30 与 192.0.2.2/30 地址、每轮 128-bit 随机标记，服务端和客户端分别核对负载并记录时间。单次 socket 超时为 3 秒，没有自动无限重试。

Kali 实际结果：wpa2、wpa3、transition-psk、transition-sae 四个配置均连接成功且数据往返成功。实验代码为标准 hostapd/wpa_supplicant 连接；尚未替换为平台自定义 M2/M4 发送端。

证据存于 hwsim-data-verification/evidence，各配置包含 air.pcap、udp-server.json、udp-client.json、data-plane.json 及控制端快照。manifest.json 是本地取回后生成的 SHA-256 清单，用于后续核对文件，没有远程可信签名或防篡改证明。

193 项测试通过。错误随机标记不能被判为成功；短标记在创建 socket 前被拒绝。

该结果证明正常端点间应用负载往返，不证明客户端隔离、固件密钥身份、密钥重装防护或所有 AP 状态正确。实验后只读确认 hwsim 已卸载、实验命名空间为空、实体网卡仍为 managed 模式。本轮没有使用实体网卡发送测试帧。

后续仍需：自定义握手 Linux 路径、将数据面证据与准确会话绑定、更多标准和文献精读以及边界状态验证。
