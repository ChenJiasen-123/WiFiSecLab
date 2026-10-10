# 元素解析与本地分析边界

精读 IEEE 802.11-2024 10.28.6–10.28.9 全部对应文字（印刷页 2092–2093）；10.28.11 仅邻近开头，不计完整阅读。规则要求未知/保留元素及扩展 ID 被忽略后继续解析；不支持的 Vendor Specific 同样跳过。可扩展结构的额外字节处理依表 9-130 和结构定义，不能推广成所有超长字段一律非法。子元素编号局限于包含结构。

审计 network/hotspot.py elements：TLV 截断报错，未知元素遍历后仍继续，但 dict 首值视图会合并同 ID 的重复项。它不是全量有序 IE 解析器；尤其 Element ID 255 下多个扩展元素和 Vendor Specific 重复项不能用该视图完整表达。当前安全 profile 不支持扩展语义，未来支持前须引入按 (ID, extension) 和有序实例表示，避免误用 setdefault。

本轮把 RSNXE (244) 加入本地关键字段重复拒绝集合，并增加函数契约。此为分析器保守的上下文拒绝，不把所有重复元素判为标准违规；未改变未知元素继续遍历的行为，未启用 RSNXE profile。

文献：联网检索到作者目录新增 2026 NordSec Revisiting Wi-Fi Management Frame Attacks: Extended Device Evaluation of SSID Confusion and SA-Query Vulnerabilities。仅检索结果书目，作者正文页返回 429，未获取论文、不计精读，后续应优先取得该较新研究。作者入口：https://papers.mathyvanhoef.com/ 。本轮无新增漏洞论文正文阅读。

验证仅 AST 语法检查；未执行导入、功能测试或无线实验。
