# ACK 欺骗论文：检测假设与平台证据（2026-10-10）

论文：Al-Wraikat 等，Ack Spoofing Attack in IEEE 802.11 Infrastructure WLANs: Strategies, Detection and Mitigation，IET Networks，2025-10-24，DOI 10.1049/ntw2.70020。
https://ietresearch.onlinelibrary.wiley.com/doi/10.1049/ntw2.70020

本轮读第 6 节检测/缓解正文、第 7 节实验设置和指标、第 7.1.1 前两种正常运行场景。未读完全部结果，伪代码图未视觉核对，不能声称全文精读完成。

作者用 AP 侧信号测量及 ACK 到达特征识别异常，并采用低速率复查。重要限制：相似 RSSI 情况不在该检测方法的识别范围；结果依赖选定的仿真场景。仿真采用非 QoS 数据、立即 ACK、固定调度和指定速率控制，并非所有 BA/MLO 设备的实测验证。在线参数表同时出现 5 GHz 与 2.412 GHz，需回查 PDF/仿真配置，暂不作为一致的频段设置引用。

对平台的推导（我们的设计判断，并非论文已证明）：监听网卡的 RSSI 是监听位置的测量，不能直接替代 AP 的 RSSI；抓包时间也不能直接替代 AP 内部 ACK 到达计时。任何此类检测都须保留测量主体、接口、时钟和缺失状态。不能把固定 RSSI 阈值用作密码学发送者认证或 AP 状态接受证明，更不能依此自动封禁目标。

现有 physical 报告和 stage_evidence 的保守证据边界无需放宽。本轮未加入 ACK 伪造/封禁逻辑，未修改执行代码。后续在证据采集层支持测量来源字段前，不新增基于 RSSI 的状态判定。

已记录评估限制及待核查参数；未运行测试或无线实验。
