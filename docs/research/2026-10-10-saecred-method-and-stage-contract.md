# SAECRED 方法阅读与 WPA2 阶段证据契约

取得作者版 SAECRED: A State-Aware, Over-the-Air Protocol Testing Approach for Discovering Parsing Bugs in SAE Handshake Implementations of COTS Wi-Fi Access Points，IEEE S&P 2025，共 19 页。
来源：https://papers.mathyvanhoef.com/ieeesp2025.pdf
本轮读摘要、1 全文及 2 开头、2.1 全文；2.2 仅开头，不计全文。表 1 仅提取文本，符号未视觉核对，不据此比较工具能力。余下方法/算法/评估尚未读完，不计整篇精读。

关键思想：输入结构与协议状态是两个维度；状态触达依赖前置输入序列。黑盒推断状态不同于内部已知状态。执行时长之类代理覆盖可能把搜索引向 timeout，不能替代代码覆盖或正确状态证据。每个用例前复位、驱动的加密/上下文/重传/超时处理都有独立成本和正确性要求。论文使用 grammar/SyGuS 的细节本轮尚未精读，不提前实现或复制攻击流程。

源码审计 core/planning.py：现有 after 是计划依赖，并非真实 AP 已进入前态；没有 executor。给各 WPA2 stage 增加 state_evidence_contract，要求 case、association epoch、输入序列 hash 和观察窗口绑定；entry_state 保持 unproven，响应分 expected/unexpected/unknown，超时不证明状态迁移，执行时长不当代码覆盖。复位需范围匹配的证据，请求本身不证明完成。

这些是可审阅的执行契约，不是已实现的状态驱动调度/复位/分类器，不增加无线操作或自建客户端，也不把 SAE 具体状态直接迁入 WPA2。后续继续读论文的状态推断与 oracle，再设计实际调度接入。

无新增完整标准章节；仅 AST 语法检查，未运行计划 CLI、导入、测试或实验。
