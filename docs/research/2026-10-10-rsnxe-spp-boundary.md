# RSNXE SPP 宣告与协商边界

完整精读 9.4.2.240 对应文字（1431–1433），表 9-373 含续表文本已读，图/表尚未视觉核对。首四位编码能力字段字节数减一，SPP A-MSDU Capable 为 bit 14。能力宣告、双方协商和实际保护效果分开；结合已读 10.11，不将 PP A-MSDU 一律判作不合法。

阅读 2025-01-07 hostap 邮件补丁 8/8 的测试源码全文，关注其 AP/STA 能力位、实现标志和连通性检查覆盖范围。它不等于每种篡改、重放或密码学保护边界均已验证；未运行这些测试，也不宣称补丁当前已合入。
来源：https://lists.infradead.org/pipermail/hostap/2025-January/043260.html

现有 parse_m3_key_data 对 RSNXE 只记录存在，缺少能力字段内部长度一致性校验。新增 1..16 字节和低四位 n-1 校验，返回脱敏 SPP 宣告及 negotiation_confirmed=false。仍将 RSNXE 归为 baseline profile 不支持，不放宽执行路径。

CCMP 非聚合 profile 拒绝 A-MSDU 的错误提示原来暗示所有 A-MSDU 都需要 SPP，改为明确该 profile 不支持聚合。未改 AAD、解密或发包行为。宣告解析不证明 M3 MIC、匹配的协商上下文或 AP 已接受。

联网还检索到 2026 Preamble Signaling in WLAN 与 Wi-Fi MU-MIMO Has Fundamental Security Flaws 的官方机构条目；仅作后续候选，不计论文精读。本轮无新漏洞论文全文完成，只做 AST 语法检查，未测试、未访问 AP。
