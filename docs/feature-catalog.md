# 功能目录与文档索引

本文档是功能级索引，用于说明每个关键功能对应的代码入口与技术说明文档。

## 1. 核心能力

| 关键能力 | 代码入口 | 对应文档 | 备注 |
| --- | --- | --- | --- |
| 状态机与安全判定 | src/wifiseclab/model.py | architecture/overview.md | 这是项目核心 |
| 生命周期检查 | src/wifiseclab/lifecycle.py | lifecycle/overview.md | 连接/断开/重连判定 |
| EAPOL 分析 | src/wifiseclab/eapol.py | protocol/eapol.md | M1-M4 与 MIC 校验 |
| WPA2/PSK 四次握手会话 | src/wifiseclab/wpa2_session.py | protocol/wpa2-session.md | 关键上下文与状态推进 |
| 热点/认证/关联路径 | src/wifiseclab/hotspot.py | network/hotspot.md | 探测、认证、关联 |
| 物理无线与网卡角色 | src/wifiseclab/physical.py | network/physical.md | 发送/监听分工 |
| hwsim 实验环境 | tools/*.py | experiments/hwsim-lab.md | 受控实验入口 |
| 数据加密与 PN | src/wifiseclab/data_session.py | lifecycle/data-session.md | 数据平面的证据 |
| key 生命周期与证据 | src/wifiseclab/key_evidence.py | lifecycle/key-evidence.md | key install / delete /
residue |
| 研究资料与背景 | docs/research/ | research/ | 文献与背景资料 |

## 2. 设计原则

1. 任何事件都必须绑定 peer / session / 证据来源。
2. 观察到的帧、ACK 或日志不能直接等同于真实内部状态。
3. 断开、授权和清理必须在独立事件中确认。
4. 关键安全状态必须在 trace 中被显式证明，而不是靠推断。

## 3. 文档阅读顺序

按能力阅读顺序推荐如下：

1. architecture/overview.md
2. protocol/eapol.md
3. lifecycle/overview.md
4. network/hotspot.md
5. experiments/hwsim-lab.md
6. research/

## 4. 关键结论

这个仓库的关键功能，不是“实现一套完整 Wi‑Fi 连接”，而是：

- 以事件流构建状态机
- 以证据绑定验证安全语义
- 以 trace 识别异常状态转换
- 以 lifecycle 和 hwsim 实验验证结论边界
