# SSID 防御与 2024 标准条件

本轮联网读 SSID Confusion（WiSec 2024）4.2–4.3、5.1（含 .1–.4）、5.2–5.3、6–7 对应全文文字；图表未视觉核对，不计整篇全部精读。
来源：https://papers.mathyvanhoef.com/wisec2024.pdf

防御的关键是身份检查发生在数据交换之前。事后失去 Beacon 而断开不证明此前没有错误交付。参考 Beacon 的验证还关联 BIGTK 更新、隐藏 SSID 和初次身份来源。论文的实验版本和结果不直接证明当前实现状态。

复核 IEEE 802.11-2024 12.7.6.6，印刷页 3072（PDF 第 3073 页）：双方 RSNXE 均指示 SSID protection 时，Supplicant 必须验证 M3 Key Data 存在 SSID element 且逐位等于 (Re)Association Request 的 SSID；失败须放弃握手并解除认证。此条件性规则不能解释为所有 WPA2 握手都自动认证 SSID，也不能仅根据 AP 单方能力位判定双方协商完成。该项是 Supplicant 的行为义务，AP 平台不能只凭看见 M3/M4 断言接收方执行了检查。

平台现状：Transcript 接受外部 PMK，但未审计其派生来源；基线仍不支持 RSNXE 扩展语义。报告新增 network_identity_validation，明确 unknown 及三个未建立的证明：PMK 来源、SSID protection 协商、认证 M3 SSID 绑定。未启用新 profile，未新建客户端。

后续应保留原始 SSID 字节及各阶段来源、关联实例、能力协商和认证后的 M3 证据，再按 AKM/PMK 来源分别裁决。显示名称不能替代逐字节比较。真实 AP 状态与客户端义务分别建模。

仅 AST 检查通过；未执行功能或无线测试。
