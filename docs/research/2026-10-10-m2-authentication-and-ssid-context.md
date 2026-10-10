# M2 完整性与网络身份上下文

本轮复核当前 eapol.py 的判定顺序：M2 RSNE 格式及关联帧比较在 MIC 计算前执行，不匹配会提前返回。故字段相等/不等必须与密码学完整性证据区分，提前返回不能报告 MIC 无效。

增加 m2_rsne_payload_authenticated：仅给定 PMK 下该 M2 MIC 成功才为 true，其他路径 false 表示未建立证明；mic_valid 继续保留 None/false/true 三态。字段不认证观察到的关联请求，不证明 AP 已接收/处理，不改变异常裁决和支持范围。

阅读依据：IEEE 802.11-2024 12.7.6 的 M2/M3 RSNE、RSNXE 匹配及消息完整性规则（此前已读，关联页 3067、3068、3070、3072）；本轮未增加完整标准章节覆盖。

论文：Gollier / Vanhoef，SSID Confusion: Making Wi-Fi Clients Connect to the Wrong Network，WiSec 2024，DOI 10.1145/3643833.3656126。
来源：https://papers.mathyvanhoef.com/wisec2024.pdf
本轮联网复核摘要、引言及 2.1–2.4 对应文字；不计全文精读。根因是凭据认证不总能保证网络名称认证。论文区分 WPA1/2 家庭密码派生将 SSID 纳入 PMK，与 Enterprise EAP 的不同 PMK 来源，不能推广为所有 WPA2 都具有同等 SSID 绑定。由此，当前给定 PMK 的 MIC 成功也不能代替对 PMK 来源及目标网络身份的独立证据。未构造中继或攻击流程。

验证：仅 Python AST 语法检查通过；未执行导入、单元测试、抓包、发包或远端实验。尚缺真实 AP 处理证据与端到端裁决映射。
