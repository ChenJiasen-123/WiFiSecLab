# Block Ack Action 字段的上下文语义（2026-10-10）

精读 9.6.4.1–5 对应文字及表 9-465–469 文字（1648–1652），补读 9.4.1.11–13 文字及表 9-81（847–849）。尚未视觉核对表格/位图；12.2.7 Robust 管理帧完整前置要求待回查。

PBAC WinStart Update 属于 Block Ack Action，而不是 BAR 控制帧。其 Action 负载包括 Category、Action、Block Ack Parameter Set 和 Starting Sequence Control。Parameter Set 在 ADDBA 中包含能力、策略和缓冲大小，但在 PBAC 更新中只有 TID 有定义，其余子字段保留。不能复用同一字段结构后把保留位解释成新的窗口大小。起始序列控制的 Fragment Number 为零。

ADDBA 请求中的 Buffer Size=0 可表示无指导信息，成功响应的 Buffer Size 至少为一；两者方向语义不同。响应复制对应请求的 Dialog Token，正常请求非零而 unsolicited 扩展另有零值规则。仅 Token 相同不能替代 TA/RA/TID、协议实例和时间上下文。

表 9-81 将 Block Ack Action 类列为 Robust；这是类型分类，不表示已收到的帧必然通过保护验证或目标一定处于协商完成状态。现有 CCMP 验证器只支持普通数据，不能用于认证管理 Action。因此当前不新增伪 PBAC 支持：后续需完整读管理帧保护前置要求，再加入专门验证路径。

泛化检查项：同一字段按消息子类型解释；请求值与成功响应值分别约束；原始字段解析、密码学验证、协议实例匹配与状态更新分别记录。此轮以标准阅读为主，未新增执行代码、未测试、未发包。

下一步视觉核对相关表和位图，回查 12.2.7；然后将这些上下文条件用于 BA 协商观察层，而不是直接给目标 AP 状态下结论。
