# WPA2 数据时间证据修正与最新论文队列

2026-10-10。目标更新：漏洞文献从最新工作开始向历史回溯；WPA2 主链路仍是当前实现重点。

代码检查发现 tools/hwsim/hwsim_udp.py 服务端在绑定/等待前记录 started_at，早于 AP 数据前授权采样。correlate_data 要求数据区间开始不早于前置快照，这会使正常交换也无法关联。修正服务端单独保存 listening_started_at，成功收到数据报后记录 started_at/request_received_at；finished_at 仍记录处理结束。这里是应用收到数据报的采样时间，不是无线到达时间或精准固件事件。错误/超时保留失败，不生成成功接收时间。

新增 mock socket/clock 测试验证监听准备与数据收到时间分离，1 项通过。未运行真实 UDP/hwsim、未现场发包。最终捕获哈希重绑定、标准自定义客户端回执及报告打包仍待实现。

联网检索更新论文队列，继续候选 Secure Wi-Fi Ranging Today: Security and Adoption of IEEE 802.11az/bk，arXiv 2603.18687v1（2026-03-19）；作者机构 2026-09-04 页面称 ARES 2026 已展示。当前阅读仅覆盖摘要、引言和 2.1–2.2 的开头（至 PASN，secure LTF 及后文未读）。本轮不声称全球最新检索完整。

初读所得：保护管理帧和证明对端身份是分离问题；PASN 保护不应直接解释为完整数据连接。测距需物理层证据，现有帧与端口观察不能证明测距安全。以上为论文阅读所得，尚未独立核对其全部标准引用或实验。

来源：https://arxiv.org/html/2603.18687v1 ，https://www.esat.kuleuven.be/cosic/blog/secure-wi-fi-ranging-today-security-and-adoption-of-ieee-802-11az-bk/ 。图、公式未视觉核对，工件未运行，继续后文阅读。
