# 组握手样例与 Supplicant 状态机入口

2026-10-10。补读 3079 的 12.7.7.5 续文，组握手 12.7.7 全部文字已覆盖（样例图 12-52 尚未视觉核验）。读 3085 的 12.7.9.1 与 3086 的 12.7.9.2/3；状态机图 12-53 暂未视觉核对，不根据提取图文字判断箭头。3080–3081 TDLS 只旁读、不登记完整精读，后续优先仍是 WPA2/AP 主线。

组握手样例说明 Supplicant 的回复与 AP 面向所有关联站的组密钥启用不是同一个事件；单个终端的 ACK 不能证明 AP 已完成所有组成员更新。样例里的密钥配置顺序是过程解释，必须与前面 shall/should 和具体模式结合。

Supplicant 密钥状态机本身不用超时/重试，恢复由外层 IEEE 802.1X 负责。这与四次/组握手的有界重试不矛盾：属于不同层次和角色。STAKEYSTART 收到 EAPOL 不意味着校验成功，MICVerified、PTKSAEstablished、TPTK/PTK、portValid 不能互相替代。TKIP michael failure 与 EAPOL MIC 无效是不同事件，不应对 CCMP 套 michael countermeasure。

对照现有平台：HandshakeSession 的 deadline 是本地资源/观察边界，不是证明 AP 的 IEEE802.1X 计时器值；APModel 是 auth/关联/握手/授权/密钥/清理的抽象组合，不是图 12-53 的逐状态实现。当前 stage_evidence 事件种类覆盖同样不能证明 MICVerified 或 PTKSAEstablished。rx_counter_configured 是内部配置断言，不能由组握手 ACK 推导。

论文映射继续使用已读的 USENIX2020 安装副作用建模与 CCS2018 跨机制安装历史，当前新读条款尚未完成相关过程，因此不凭入口图新增完整状态规则。下一步 12.7.9.4 StaProcessEAPOL-Key，读完过程后再检查现有分支实现及跨模式同类问题。

本轮完成阅读和层次审查，未新增功能代码、未运行测试、未扩展客户端、未发包。reading-log.md 已更新。
