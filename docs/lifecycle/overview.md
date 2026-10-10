# 生命周期与状态证据

## 1. 功能定位

生命周期模型位于 src/wifiseclab/lifecycle.py，重点用于分析真实连接的状态转换过程，包括：

- 连接开始
- 中间认证与关联
- 完成授权
- 断开
- 清理残留上下文
- 重连与超时

## 2. 核心思想

生命周期分析的关键是：

- 不把“控制器报状态”直接当成“内部安全状态”
- 不把“断开”直接当成“已清理密钥和上下文”
- 不把“连接成功”直接当成“安全通道已完成”

## 3. 关键判定

在 Lifecyle 中，判断会检查：

- 对应的 peer 是否匹配
- station address 与 BSSID 是否绑定正确
- wpa_state 是否达到 COMPLETED
- pairwise/group cipher 是否符合要求
- AP 返回的 flags 是否显示 AUTH / ASSOC / AUTHORIZED
- PMF 是否满足 SAE 的要求
- 连接进入三个判断点：连接成功、断开、超时

## 4. 为什么这部分重要

这是连接状态与安全状态之间的桥接层。很多“看起来正常”的生命周期都会存在以下问题：

- 状态已切到 disconnected，但旧 key 仍存在
- session 还存在未清理的 pending task
- 端口授权过早发生
- 对应的 PMF 条件未满足

## 5. 结论边界

Lifecycle 模块提供的是“控制接口生命周期检查”，不是对全部 Wi‑Fi 实现的完整标准合规性验证。其主要作用是为研究层提供可审计的 lifecycle evidence。
