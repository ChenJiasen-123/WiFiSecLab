# 文档目录与项目结构说明

本文档是整个仓库的结构入口，用于把分散的研究材料、实验记录和实现代码归档到清晰的功能分层中。

## 1. 文档分层

- architecture/：项目整体架构、状态机与模块边界
- protocol/：EAPOL、握手、认证、关联与协议语义
- lifecycle/：连接、断开、重连、生命周期证明与证据
- network/：热点、无线探测、物理网卡与 hwsim 测试环境
- experiments/：复现实验、hwsim 抓包、运行时约束与验证记录
- research/：研究笔记、参考文献摘要与扩展分析

## 2. 代码主线

核心代码位于 src/wifiseclab/，主线逻辑如下：

1. 读取 trace / JSON 事件流
2. 进入 APModel 状态机
3. 检查认证、关联、握手、授权与清理阶段
4. 生成 findings、history 与 report
5. 对照 lifecycle 与实验证据进行复核

## 3. 核心功能索引

| 功能 | 代码入口 | 说明文档 |
| --- | --- | --- |
| 状态机与安全判定 | src/wifiseclab/model.py | architecture/overview.md |
| 连接生命周期 | src/wifiseclab/lifecycle.py | lifecycle/overview.md |
| EAPOL / 握手分析 | src/wifiseclab/eapol.py | protocol/eapol.md |
| WPA2 会话与密钥上下文 | src/wifiseclab/wpa2_session.py | protocol/wpa2-session.md |
| 热点与无线实验入口 | src/wifiseclab/hotspot.py | network/hotspot.md |
| hwsim 实验与验证 | tools/ 下脚本 | experiments/hwsim-lab.md |
| 研究笔记和背景材料 | docs/research/ | research/ |

## 4. 典型阅读顺序

推荐按下面顺序阅读：

1. architecture/overview.md
2. protocol/eapol.md
3. lifecycle/overview.md
4. network/hotspot.md
5. experiments/hwsim-lab.md
6. research/ 下相关笔记

## 5. 结构化目录

```text
WiFiSecLab/
├── README.md
├── run.py
├── pyproject.toml
├── src/
│   └── wifiseclab/
├── tools/
├── examples/
├── reports/
├── tests/
├── docs/
│   ├── README.md
│   ├── feature-catalog.md
│   ├── architecture/
│   ├── protocol/
│   ├── lifecycle/
│   ├── network/
│   ├── experiments/
│   └── research/
└── docs/roadmap.md
```

## 6. 项目定位

这个仓库更像是一个 Wi‑Fi 安全状态转换研究平台，而不是一个普通的连接工具。它的目标是把“表面成功”与“真实安全状态”区分开，并用 trace、事件、状态和证据对照机制来证明一个关联/握手/注销/重连是否真的满足安全语义。
