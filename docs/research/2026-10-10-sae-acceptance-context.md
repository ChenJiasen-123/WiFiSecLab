# IEEE 802.11-2024 SAE：本地接受与对端完成

2026-10-10。补读印刷页 2983–2984（PDF 第 2984–2985 页），12.4.8.6.4–6.6：Committed 剩余分支、Confirmed、Accepted。文字已读，图 12-14 尚未视觉复核。

Confirmed 表示已发送 Commit 和 Confirm、已收到 Commit、等待对端 Confirm；通过对端 Confirm 的验证后进入 Accepted。Accepted 仍不保证对端收到本端最后的 Confirm，因此不能据本地认证成功推导双方完成。Accepted 中重复/过期 Confirm 的丢弃规则与有效新 Confirm 的应答规则不同，不可把所有重复报文当作失败。

代码 src/wifiseclab/model.py 的旧 confirmed 标签用于本地认证完成，容易与规范 Confirmed 混淆。已改为 accepted；Commit 接受阶段改称 commit_accepted，明确它是证据阶段，不冒充完整规范状态。新增独立 sae_exchange，避免四次握手 exchange 覆盖 SAE 交换绑定或 SAE 完成清空四次握手上下文。认证失败和去认证清除 SAE 临时交换标识。报告列出新字段及模型边界；历史快照元组增加一项，读取旧报告的消费者应按对应版本字段解释。

现有事件是实现插桩或合成输入的内部接受断言，没有新增真实 SAE 密码计算，也没有实现完整重传、Sc/Rc/Sync、token、组切换或双实例状态机。pcap/probe 来源继续只记录观察，不能推进内部认证。

针对本次变更的扩展模型测试 17 项通过，新增交换串扰与外部 Confirm 不推进认证的回归用例。未运行全套测试、未现场发包；此前全套 248 项是历史结果。后续继续读消息构造与 RSNA 生命周期，再决定适配器事件契约及双实例表示。
