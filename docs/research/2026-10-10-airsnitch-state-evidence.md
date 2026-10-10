# AirSnitch 阅读与状态证据范围

来源：AirSnitch: Demystifying and Breaking Client Isolation in Wi-Fi Networks，NDSS 2026，https://www.ndss-symposium.org/wp-content/uploads/2026-f1282-paper.pdf ，DOI 10.14722/ndss.2026.241282。

本轮阅读范围：正文 I–III 的架构、威胁模型及分层方法；VIII-C 防御、IX 相关研究和 X 结论。PDF 共 18 页，尚未逐节精读 IV–VII，也没有复现攻击。表格只读取文本，未完成图表逐项视觉核验。论文中的受测设备结论不能推广为所有设备当前均受影响。

主要成因：共享密钥的信任范围、隔离策略在交换与路由之间不一致、不同层的身份及转发表状态缺少可靠绑定。

对平台的推导（设计要求，不是论文原文）：握手 MIC、控制端授权快照、密钥安装事件、数据送达和隔离策略必须分别取证。快照只证明一个查询区间的采样状态，不能提升为持续授权。数据面需要自己控制的端点、每轮随机请求标记、明确时间窗口与实际响应；未收到响应应区分丢包、过滤、端点不可达和证据不足，不能直接判漏洞。拓扑应记录 BSSID、SSID、桥与 VLAN 的配置来源。

本轮代码：control_snapshot 增加 state_observation_interval、later_context_boundary_observed、continuous_authorization_confirmed。后者固定 false；后续断开不会抹去先前快照，也会明确出现在报告中。重放最新 hwsim 抓包：两个 PSK 配置均为授权快照有效、之后观察到上下文边界、持续授权未证明。191 项测试通过。

未进行新的无线实验。待完成自定义握手 Linux 路径、正常数据面验证及剩余文献/标准精读。
