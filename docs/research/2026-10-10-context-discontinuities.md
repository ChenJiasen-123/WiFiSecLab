# 2026-10-10：未解释的握手上下文

实际阅读 [hostap authenticator 实现镜像](https://raw.githubusercontent.com/vanhoefm/hostap-wpa3/master/src/ap/wpa_auth.c) 接收相关段落，约 1018–1136、1258–1331 行。Request、组密钥和 pairwise 消息进入不同路径，Request 具有独立计数器检查。镜像实现不能代替现行标准。

检查本项目发现，未知 Key Information 模式此前直接返回，可能隐藏未解释的中间状态。现在记录 `unclassified_eapol_key_context` 并停止当前路径；明确识别 EAPOL-Key 后遇到不支持版本或 descriptor 也停止路径。不据此推定 AP 违规、消息非法或 AP 已重置。普通数据不会中断路径；新的 M1 可以建立独立路径。这是显式的分析能力限制，尚不是完整组密钥/Request 状态机。

验证覆盖 Request/Group/Error 模式插入、未知版本/descriptor、普通数据穿插及断点后独立握手恢复。102 项测试通过。已有 133653 WPA2 与 transition-psk 原始隔离抓包的 M2–M4 MIC 和路径仍通过。本轮无现场发包。

继续阅读 [KRACK 原论文](https://papers.mathyvanhoef.com/ccs2017.pdf) 缓存约 950–1130 行，即 4.3 余下部分、5.1–5.3（PDF 第 10–11 页）。结合前轮，第 4、5 节已读完；不宣称整篇及近 30 年综述完成。FT 的 nonce/MIC 会话绑定与密钥安装生命周期必须分别验证；论文观察到的历史实现安装时点不等同于当时标准要求。重传响应不能直接证明重复安装或计数器重置，需要密钥身份、安装事件及保护数据证据。

采用 [作者勘误](https://www.krackattacks.com/) 对第 4 节时序和 Figure 9 请求/响应标签的更正。本轮没有实现 FT 重放或强制漫游。历史实验影响范围不推广为今天全部设备。

未完成：现行 2024 标准全文、完整文献清单与精读、GTK 解包及 RSNE 校核、FT 状态机、跨来源密钥安装历史，以及内部状态 oracle 支持的完整自主实验。
