# BA 窗口处理与近期文献定位（2026-10-10）

完成 10.25.6.6.2–6.6.3 对应文字阅读（2064–2067，止于 6.7 前），视觉核对 2064–2066 的普通窗口及 BAR 不等式，避免文本提取将上标或运算符丢失。普通协议采用半序列空间边界区分窗口前方和旧帧；SAR 使用 MPDU Modulo 相关边界，不能固定套 4096。此次未完成模序比较总则的交叉引用，不实现完整算法。

窗口中已有同序列数据则丢弃重复；窗口推进可将之前的完整 MSDU/A-MSDU 上交，不能只观察最新包；SAR 缺少 MPDU 的 MSDU 必须丢弃。BAR 推进条款明确区分受保护 BA，后者转引 10.25.7，尚未阅读；因此不可实现“所有 BAR 都推进窗口”。

代码规划新增 BA 必需上下文：协议身份、ADDBA 请求/响应绑定、协商窗口、序列模数、SAR、受保护模式和生命周期，并明确重排序模型未实现。此为执行器前置契约，不声称已有 BA 测试覆盖。

近期文献检索：

- Ack Spoofing Attack in IEEE 802.11 Infrastructure WLANs: Strategies, Detection and Mitigation，IET Networks，2025-10-24，DOI 10.1049/ntw2.70020。已读摘要及第 2 节 ACK 格式/操作背景对应段，尚未精读攻击、防御与评估。该文依赖仿真分析，不能把其防御适用性声明当成平台验证结果。
  https://ietresearch.onlinelibrary.wiley.com/doi/10.1049/ntw2.70020
- Characterizing Block Acknowledgment Window Reordering in Multi-Link Wi-Fi，2026。大学研究门户元数据及摘要已读，全文未读。属于重排序性能背景，不能作为漏洞证明；列入扩展 MLO 时的阅读队列。
  https://researchportal.ulisboa.pt/en/publications/characterizing-block-acknowledgment-window-reordering-in-multi-li/

仅 AST 检查，未运行平台测试、未发包。下一步读 10.25.7 受保护 BA，再从最新相关论文深入成因；现有 WPA2 基线尚未增加 BA 主动执行。
