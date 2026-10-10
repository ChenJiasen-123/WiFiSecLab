# BIP 重放及密钥上下文

## 精读范围
IEEE 802.11-2024 12.5.3.1–.6 全部对应文字，印刷页 2996–3003（PDF 第 2997–3004 页），止于 12.5.4。图 12-23–27、公式 12-1–4 只读提取文本，未视觉核对；S1G/BCE 公式不作为已验证实现依据。邻近 GCMP 文字不计完整章节。
联网复核 WiSec 2022 4.2.2 对应文字，未新增论文全文覆盖。
来源：https://papers.mathyvanhoef.com/wisec2022.pdf

## 规则及漏洞根因映射
IGTK 保护组地址 robust management；BIGTK 用于 Beacon；WUR 的 WTK/WIGTK 是另一个适用域。身份包含发送 STA 与 Key ID，不能单用数字槽位当密钥材料身份。IGTK/IPN 随新 GTK 的分发义务与 BIGTK 的可选更新不同。

接收方按 IGTK/BIGTK 维护 48 位重放计数器，初始化为认证分发的 KDE 中 IPN/BIPN。非 S1G 普通发送计数器对应新密钥初始化为 1 并严格递增。不能把接收初值一律设成 0，也不能把非零空中 IPN 当安装完成。QMF 另按 ACI 区分接收计数器；不使用 QMF 的 robust management 与 Beacon 的域也不同。

接收顺序：识别密钥及关联状态；重放预检查；按 cipher 构造 AAD/GMAC IV 并验证 MIC；成功后更新对应 replay counter。无效 MIC 不得推进有效接收计数器。观察到高 IPN 不证明接收方已接受，单纯捕获重复也不证明重放失效。

普通 BIP AAD 是屏蔽 Retry/Power Management/More Data 的 FC 和 A1/A2/A3，不包含 Sequence Control。Beacon Timestamp 有独立屏蔽规则；S1G/BCE 不得复用普通结构。BIP-CMAC-128 MIC 为 8 字节，CMAC-256 和 GMAC 两种为 16 字节。MME 位于帧 body 最后、FCS 之前，格式 9.4.2.53 待读，不能只凭尾部魔数自动认定。

新 IGTK/BIGTK 首次发送后，不再用旧密钥发送对应帧。有效 MIC 不防御持有组密钥的内部成员伪造；退出成员在更新前的密钥知识也是威胁前提，不能把完整性成功升级为唯一 AP 身份证明。

## 平台审计与实现前提
core/model.py management_accepted 当前仅覆盖 deauth/disassoc 的保护/完整性证据检查，没有 BIP 接收计数器分支；data_accepted 与 rx_counter_configured 不应未经适用性约束直接作为管理帧完整检查。现有 management_header 不解密、不认证，Protected 位也不是组 BIP 识别条件。

后续接收证据须携带：发送者/BSS、稳定材料 ID 与 Key ID 映射、IGTK/BIGTK 类型、cipher、QMF/ACI 或非 QMF 域、配置 IPN 完成证据、MIC 验证和真实接收效果。无线仅观察的事件仍不能更新 AP 内部账本。AP 发送与 non-AP 接收义务分别核对；不建客户端，不把客户端义务当 AP 的必然错误。

本轮无运行代码改动、无测试。先补读 MME 格式及关键图表，再设计有来源约束的接收事件。
