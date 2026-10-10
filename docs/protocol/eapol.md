# EAPOL 与四次握手分析

## 1. 功能定位

EAPOL 相关逻辑主要来自 src/wifiseclab/eapol.py 以及相关状态机工具。该模块负责处理：

- EAPOL 帧解析
- M1/M2/M3/M4 的语义检查
- MIC 与 key data 校验
- 非ce、counter 与 replay 约束
- 合法消息顺序与 AP/STA 角色上下文

## 2. 关键问题

该模块的目标不是单纯“识别包”，而是确认：

- 当前消息是否属于正确的握手阶段
- 是否与当前 session / exchange_id匹配
- 是否在合法上下文中解析和校验
- 是否出现 replay、重装、或上下文错乱

## 3. 主要检查项

- message 顺序必须满足合法四次握手轨迹
- M3 的 key data 与 RSNE 绑定需要进一步验证
- MIC 必须在对应 PMK / KCK / AKM 上下文下校验
- 同一接入上下文中的 replay counter 不应回退
- 事件必须绑定 session、peer 和 evidence 线索

## 4. 与状态机的关系

EAPOL 细节是“底层事实”，状态机则是“上层判定”。

也就是说：

- EAPOL 提供消息事实
- model.py 负责判定状态是否成立
- lifecycle.py 负责确认连接全生命周期是否一致

## 5. 技术边界

该模块不声称实现完整的 802.11 全协议栈，也不等同于已经证明真实 AP 已完成安全握手，而是把握手细节和状态判定拆开，用准确的上下文来补充安全证据。
