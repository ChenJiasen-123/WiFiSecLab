# SSID Confusion 阅读与身份边界

原始来源：[Gollier 与 Vanhoef，WiSec 2024 作者版](https://papers.mathyvanhoef.com/wisec2024.pdf)，6 页，DOI 10.1145/3643833.3656126。通过在线 PDF 正文读完第 1–7 节及参考文献列表，未下载发布副本，未复现实验。作者版脚注明确修订 3.7.2 FILS 说明；不能只依据摘要或 Table 1 给所有配置下结论。

根因记录：SSID 身份未必进入认证上下文；复用凭据时，“密钥验证成功”和“连接了预期名称”可能分离。论文分别分析 PSK、SAE 两种派生方式、EAP、mesh、FT、FILS，不能统一称为所有 WPA2/3 均受影响。实测为四种客户端及指定协议配置，不能把作者推测当作全设备证明。防御讨论涉及连接前参考 Beacon 的认证、凭据隔离及协议绑定。

本项目使用外部给定 PMK 时，没有该 PMK 来自 SSID/passphrase 派生的证据；MIC 通过不能自动提升为 SSID 已认证。现有 RSNE 与 AP/STA 地址绑定也不包含这种名称认证。

落实的是本平台证据整理与输入一致性，不是论文攻击实现：

- discovery 保留同 BSSID 的所有非隐藏 SSID 字节，避免过滤“其他名称”后掩盖冲突；空/全零隐藏名称不算第二名称。
- 基线 Beacon/Probe Response 的 source 必须与 BSSID 一致；SSID 超长不作为有效配置。
- build_association 要求 profile.ssid 与目标完全一致，并拒绝 identity_conflict；校验发生在 exchange 回调前。
- 报告明确 ssid_authentication_confirmed=false。冲突也可能来自配置变化或抓包环境，不自动视为攻击或 AP 违规。

128 项测试通过，新增名称冲突、隐藏名称和 source/BSSID 不匹配测试，并扩充关联前拒绝错误配置的负例。本轮无现场发包或中间人实验。

未完成：认证后的名称证据、企业/SAE/FT/FILS 独立状态机、现行标准全文与近 30 年完整文献检索。阅读一篇不能代表系统综述完成。
