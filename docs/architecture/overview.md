# 架构概览：状态机与安全判定

## 1. 项目定位

本项目的核心不是一个网络服务，也不是一个商用无线客户端，而是一个 Wi‑Fi 安全状态审计框架。核心目标是：区分“看似成功的连接”与“真正符合安全语义的状态转换”。

## 2. 主要模块

### 2.1 状态机核心：src/wifiseclab/model.py

该文件定义了整个系统的关键抽象：

- Event：统一事件对象
- Peer：单个 STA 的安全上下文
- APModel：状态机核心
- Finding：候选性质违反记录

它负责分析事件序列，检查：

- 认证顺序是否正确
- 关联是否发生在合法认证之后
- 握手是否完整且按顺序推进
- 是否存在越权授权
- 是否出现 key reinstall / nonce reuse / residual context

### 2.2 生命周期与控制面：src/wifiseclab/lifecycle.py

该文件用于分析连接生命周期：

- READY
- CONNECTING
- CONNECTED
- DISCONNECTING
- DISCONNECTED
- RECONNECTING
- DONE

它关注的是控制面状态和真实连接状态之间的差异；它不假设日志信息即可证明内部安全状态。

### 2.3 协议细节：src/wifiseclab/eapol.py、wpa2_session.py

这些模块处理更细粒度的协议语义：

- EAPOL 事件
- M1/M2/M3/M4 消息
- MIC 校验
- key data 与 RSNE 上下文
- 重新关联与重协商时的状态约束

## 3. 设计原则

1. 观察到一个帧不等于内部状态已接受。
2. 看到一个 ACK 不等于端口授权。
3. 看到断开不等于清理成功。
4. 关键状态必须经过 trace 与上下文校验。
5. 安全判断以 evidence-binding 为中心，而不是以单点 observation 为中心。

## 4. 典型处理路径

```text
trace / pcap / synthetic event
        ↓
Event.parse()
        ↓
APModel.apply()
        ↓
peer state update
        ↓
finding / history / report
```

## 5. 结果输出

APModel.report() 输出如下内容：

- mode
- findings
- transition_count
- unconfirmed_observations
- history
- state_fields
- abstractions_used

这使得整个框架既可做研究分析，也可做自动审计输出。
