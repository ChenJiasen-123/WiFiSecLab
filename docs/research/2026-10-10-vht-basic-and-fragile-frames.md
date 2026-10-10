# VHT 运行约束与 Fragile Frames 阅读

## 标准范围

完整阅读 11.38.1 Basic VHT BSS functionality 对应文字，印刷页 2882–2886，止于 11.38.2。表 11-29、11-30、11-31（含续表）完成文本阅读，尚未视觉核对；页面邻接 DMG 表及后续 11.38.2/3 不计完整精读。21.3.14 已定位 3635 页，本轮尚未阅读。

## 对前轮编码结论的补充

标准区分支持能力与 BSS 运行参数。较窄 VHT PPDU 仍受主 20/40/80 信道约束；向对端发送带宽不得超出其宣告支持，MPDU 长度也受对端最大长度能力约束。离信道 TDLS 是明确例外，本轮不将基础设施路径结论泛化到 TDLS。

表 11-30/31 补充了只读 9.4.2.157 时容易遗漏的 Extended NSS 情况：当 160 或 80+80 的 NSS 支持少于 Max VHT NSS，相关中心信息可能通过 HT Operation CCFS2 而非 VHT CCFS1 表示。应联合读取 HT/VHT 信息及 NSS 前提。VHT CCFS1=0 不能独立证明整个 BSS 不使用 160/80+80；前轮表 9-317 的字段解释不等于完整运行状态判定。

这与固定版本 hostap get_tx_parameters 的 Extended NSS TODO 对应，但不能仅凭 TODO 判定实际漏洞；需审计调用前提及后续版本。平台尚无这一转换入口，本轮不增加简化推导器，保留现有 PHY 兼容未知项。

## 新论文阅读范围

Fragile Frames: Wi-Fi’s Fraught Fight Against FragAttacks，WiSec 2025，Siebe Devroe、Héloïse Gollier、Mathy Vanhoef。

来源：https://papers.mathyvanhoef.com/wisec2025.pdf

本轮精读摘要、1 Introduction、2.1–2.2；3–4 为工具返回的邻接文字，不标为完整精读，5–7 仍待读。图表尚未视觉核对。

论文再次表明“标准更新/厂商补丁存在”不等于防御已正确部署；A-MSDU 的实际保护、兼容性回退和解析上下文需分别评估。它讨论的 mesh 情况提示防御条件有拓扑范围，不能把基础设施单一 profile 的结果推广到 mesh。当前平台不实现论文攻击，不启动调查或实验。

## 对现有平台的审查结果

当前 ocv.py 对给定链路快照作条件比较，不从 VHT 元素推导；因此无需把 CCFS2 规则硬塞进 OCI 解析器。后续若接入 HT/VHT 派生快照，必须记录 HT/VHT/Extended NSS 全部输入及来源；未知前提不能默认关闭。另需独立记录允许接收 EAPOL、允许普通数据和允许桥接转发的状态，后续结合论文相关章节与标准受控端口条款继续核对。

本轮修改研究记录及接口文档，未测试、未访问目标 AP、未发包。
