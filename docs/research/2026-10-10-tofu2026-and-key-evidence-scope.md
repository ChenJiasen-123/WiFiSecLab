# WiSec 2026 TOFU 阅读与密钥证据作用域

取得作者版 Secure Trust On First Use for Enterprise Wi-Fi: Design Guidelines and Linux Implementation，Rathan Appana、Mathy Vanhoef，WiSec 2026，DOI 10.1145/3765613.3811682，共 6 页。
来源：https://papers.mathyvanhoef.com/wisec2026.pdf
web 接口不可访问，urllib 成功取得 PDF。正文读摘要、1、2.1–2.2、3.1、3.2（含 .1–.8）、4.1、4.2.1–.2 全部对应文字。4.2 后续未读；图 1/表 1 仅文本，未视觉核对。不计全文精读。NordSec 2026 SSID/SA-Query 研究作者目录没有可见全文链接，仍只计书目。

论文观察区分初次证书决策、已知网络后续有效期检查、CA/leaf 轮换、外部身份和真实握手边界。其根因包含缺少标准化 TOFU 设计和持久信任后的有效期检查遗漏。实验限于论文设备/版本，不泛化到所有当前系统，TOFU 建议也不改写为 IEEE 802.11 必然义务。

与平台的关系：给定 PMK 成功、RSNE 一致或先前成功会话不能证明本次 Enterprise 服务器身份有效。AP Authenticator、AS 和 Supplicant 证据来源要分开。客户端信任弹窗、证书校验和 realm 选择不能只凭 AP 抓包推断。用户要求 WPA2 优先、不建客户端，故先记录未来 EAP 适用域，不把当前 PSK profile 扩展为 Enterprise。

同时审计 lifecycle/key_evidence.py：analyze 仅选择指定 peer 的 pairwise cfg80211 操作；即使返回成功，也未提供 IGTK/BIGTK 材料、协商 cipher、接收 IPN 初值或实际 MAC 效果。报告显式增加 evidence_scope、group_integrity_key_configuration_confirmed=false、integrity_key_replay_floor_confirmed=false。不把 pairwise key slot 或返回 0 注入 BIP verifier 作为完整密钥上下文。

后续先读完 2026 论文的设计/实现/评估，并补齐标准 Authenticator/AS/端口授权关系；BIP verifier 与真实采集接入仍需专门完整性密钥证据生产者。

仅 AST 语法检查，无导入、功能、无线或远端测试；无新增完整标准章节。
