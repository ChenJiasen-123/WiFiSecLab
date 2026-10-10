# 认证观察链路集成边界验证

2026-10-10，直接检查现有 authentication.py、hotspot.py 与真实 pcap 测试夹具。本轮没有新增无线执行或密码协议能力。

新增两项通过实际 radiotap/pcap 读取入口的回归：同一捕获中包含本端 Open System 请求、其他 AP 的成功响应、目标 AP 的 SAE H2E Commit，确保观察列表保留身份、原始密码负载和 packet_index，但旧 Open System 请求不会因这些报文被判成功；另一项检查认证固定头截断仍保留可定位的 parse_error，不生成 status_code 或成功响应。

tests/test_hotspot.py 当前 16 项通过。测试是合成 pcap，覆盖捕获读取与共用观察输出的集成，不证明真实无线收发、SAE 校验、AP 状态合规或全平台通过。与前轮共用观察组件 3 项属于不同范围，未重新运行全套。

后续状态场景不能把 authentication_observations 直接视作目标响应：列表包含请求和其他 AP 报文，必须同时约束地址、事务、算法、当前运行与时间窗口。时间匹配仍不能证明密码接受，内部事件须独立取证。
