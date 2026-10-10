# 暂存握手上下文替换（2026-10-10）

本轮解决上一轮记录的客户端限制。HandshakeSession 在 M4 构造前收到不同 ANonce 的可处理 M1 时，先成功构造 M2，再清除旧暂存分支并建立新分支；SNonce 在这次未完成握手内保持一致。相同 replay counter、不同 ANonce 不再被当作同一条 M1 重复直接忽略。M1 不会更新经过认证的 replay counter 下限。M3 必须匹配当前 ANonce、存在更早计数的 M1/M2 分支，并通过原有 MIC、密钥数据和 RSNE 验证，才构造 M4。

如果 M2 构造失败，旧上下文不被破坏。M4 构造之后仍拒绝自动启动新握手；响应预算和会话超时保持原约束。观察到 ANonce 变化不表示 AP 故障，不表示发送方已认证。攻击者仍可反复干扰暂存上下文或耗尽有限预算，本次不声称消除拒绝服务，也未实现攻击流量发生器。

离线验证：不同首条 ANonce 后正常分支恢复；替换后旧 M3 拒绝；未经认证的高计数不会阻止后续有效分支；无效 MIC 不推进状态；构造失败不清空旧分支；多次变化受响应预算限制。全量 231 项测试通过。本轮未连接远程主机或发出无线帧，未重新运行 hwsim，实体路径效果尚未验证。

来源：IEEE 802.11-2020 缓存文本第 12.7.2 与 12.7.6.2–5 节；前者约束 MIC 验证后的计数历史，后者包含 M1/M3 的 ANonce 一致性和 M3 验证规则。该版本条文中产生 SNonce 的表述仍需结合完整状态机核对，不宣称整个实现完全符合当前版标准。

上游源码交叉核对：https://chromium.googlesource.com/external/w1.fi/cgit/hostap/+/refs/heads/pending/src/rsn_supp/wpa.c 。本轮读取 M1 中 renew_snonce 控制及暂存 PTK 注释、M3 ANonce 比较与成功后的 SNonce 更新标记。pending 分支是可变参考，不能视作规范或完整安全证明。

历史论文：https://theory.stanford.edu/~changhua/fp09-he.pdf 。历史方案与当前实现有区别；本次采用有界单一当前 ANonce 上下文，不实现从任意 M3 的 ANonce 无条件恢复，也不无限缓存候选密钥。

本说明更新了上一轮 handshake-context-review.md 中关于无法恢复 ANonce 变化的限制；旧说明保留作为历史记录。总体标准精读、三十年文献研究、完整边界状态覆盖仍在进行。
