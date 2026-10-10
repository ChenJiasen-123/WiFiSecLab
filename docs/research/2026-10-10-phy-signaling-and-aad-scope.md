# PHY 信令论文检索与 CCMP 认证范围

## 2026 论文范围

Preamble Signaling in WLAN: Vulnerabilities, Attacks, and Countermeasures，Zhengguang Zhang、Marwan Krunz，IEEE TMC 25(7)，9962–9979，2026-07，DOI 10.1109/TMC.2026.3660297。

作者实验室出版列表及 Arizona 官方机构条目交叉核对了书目信息。仅完整阅读官方摘要，未取得可读全文，不记作精读完成，也不拿 2022 SIGTAM 会议版替代 2026 期刊版。

来源：

- https://experts.arizona.edu/en/publications/preamble-signaling-in-wlan-vulnerabilities-attacks-and-countermea/
- https://wicon.arizona.edu/publications/publications-year

摘要指出 SIG 信令可能通过错误检测但仍被篡改。对平台的推论是应区分错误检测、密码学完整性和实际解码结果；仅凭 MAC 抓包无法完整评估 PHY 信令。该推论不是对作者完整方法的复现。本轮不实现信号干扰或 PHY 攻击，全文仍待获取。

## 标准复核

复核 12.5.2.3.3 的 PV0 AAD 段（2988–2989），不是新增完整章节阅读；PV1 后续不计本轮精读。QC 的 A-MSDU Present 是否纳入 AAD 受双方 SPP 能力及 DMG 上下文影响，MIC 成功不能认证被掩码或排除的字段。PHY SIG 不在现有 MAC AAD 检查范围。

## 当前源码证据

检查 protocol/eapol.py：成功解包和内容解析后，完整 key_data_summary 已写入 packet，之后才判断 baseline_profile_supported。因此前轮 rsnxe_capabilities 会进入报告；无需再添加平行字段或重复传播。

检查 network/ccmp.py：baseline_data_aad 与 decrypt_unicast 拒绝 A-MSDU；解密结果已列出认证及排除字段，且不声称接收方接受。不能因为 M3 解析出 SPP 宣告就放开该分支；必须先建立双方协商、上下文及 AAD 的完整支持。本轮未修改算法或扩大 profile。

下一步仍以 WPA2 MAC/密钥链路为主，继续补齐 RSNXE 在握手内匹配与认证的条款；PHY 论文作为完整目标的阅读缺口保留。未执行测试、未访问 AP、未发包。
