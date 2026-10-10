# SA Query 上下文与证据契约

## 阅读范围
IEEE 802.11-2024：9.6.9.1–.3 全部文字（1725–1726），表 9-515 与图 9-1266/1267 仅文本；11.13 全部文字（2627–2629，止于 11.14）。邻近 11.12 文字已读，不计全部 PMF 机制。无图表视觉核对。
WiSec 2022 On the Robustness of Wi-Fi Deauthentication Countermeasures：摘要、1、2.1–2.2.3、3.1 全部对应文字；3.2.1 对应文字已读；其余不计精读。表 1 仅文本。本轮重点比较方法及上下文，不复现攻击。
来源：https://papers.mathyvanhoef.com/wisec2022.pdf
2026 NordSec 后续研究仅作者目录书目检索结果，仍未获取全文，不以 2022 替代较新文献完成项。

## 标准前提
SA Query 在协商 PMF 时须支持。响应请求前须分别判断：已关联或存在 PASN PTKSA；单播目的；不存在标准所述等待关联响应条件；OCV 激活且 peer 宣告 OCVC 时，OCI 存在并匹配。Response 的 transaction identifier 对应请求，不能凭帧类型判成功；组地址 Response 无效。非 AP/non-PCP 的 OCI 和信道切换超时义务须按角色区分。

收到某些未保护解除关联/认证帧后的启动 SA Query 及失败后的删除 SA/移入状态是 may；有效响应后继续 SA 是 should。不能把这些全部改写成 shall。计时单位为 TU，maximum/retry 来自具体参数，不从抓包空白自动推断 timeout 或删除。

Known STA Identification 可在同 AP 重关联时避免 SA Query/comeback delay：最近 PTK-KCK 的 MIC、timestamp 有效性和重复 timestamp 拒绝均有关。缺少 SA Query 不单独构成违规。PASN、S1G、PCP 均须保持适用域，当前基础设施 WPA2 基线不宣称覆盖它们。

## 论文与版本边界
2022 论文按地址类别、密钥是否安装、保护状态和双方 PMF 能力建立规则矩阵，说明仅看帧类型无法判断正确处理。论文引用旧版 12.6.19，不能把其编号或未定义分支原封不动迁入 2024；本版 12.6.19 已是不同主题，必须重新对应。论文实验版本结果也不证明当前版本仍存在问题。

## 当前源码缺口与下一步
审计 network/hotspot.py management：frame[1] & 0xc7 过滤包含 Protected 位 0x40，因此受保护单播管理帧不进入此解析器。disconnect_affects_peer 只判地址范围，不证明接收效果；association_gate 只是初始关联观察门。
后续须拆分可验证的管理帧头观察与认证后的 Action body：未解密时不可把密文解析成 category/transaction/OCI，也不能把 Protected 位当 MIC 成功。把请求集合绑定 peer/session、角色、时间及 transaction；记录 PMF 协商、PTKSA、关联待响应及 OCV 条件。捕获丢失、未见响应保持 unknown。AP 内部 SA/密钥删除仍需独立插桩完成证据。

本轮只阅读、源码审计和文档更新；未修改运行代码，未执行测试或无线操作。
