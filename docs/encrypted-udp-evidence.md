# 加密抓包与 UDP 证据整合

新增 udp_evidence.py 严格解析 IPv4 LLC/SNAP 和 UDP；encrypted_evidence.py 将 CCMP 已验证的无线单播负载与本轮端点记录、握手密钥、时间区间、请求/响应顺序绑定。hwsim_data_analyze.py 成功退出现在同时要求端点证据关联和加密抓包往返，只有端点日志成功而缺少加密帧时退出 1。

重放现有自有 hwsim 实验：WPA2 匹配包 44/46，transition-psk 匹配包 48/50。两组的 CCMP MIC、IP/UDP 校验和、地址/端口、随机负载及请求先于响应均通过。结果在 hwsim-data-verification/data-session-correlation.json。捕获未提供 FCS，报告保留 fcs_not_available；不将其当作 CRC 已验证。

210 项测试通过：长度、校验和、分片、零 UDP checksum 的区分、缺少响应、顺序颠倒、超出时间窗口、端点/标记错配以及未绑定日志不能升级为成功。后续仅调整可选 crypto 缺失时测试跳过路径，没有改变运行功能。

阅读：RFC 768 全部协议正文（3 页），关注 UDP 长度和伪首部校验和，https://www.rfc-editor.org/info/rfc768/ 。RFC 791 本轮只阅读首部校验和、分片与长度相关段落，未声称全文精读，https://www.rfc-editor.org/info/rfc791/ 。解析器限定无选项 IPv4、无分片和无尾部扩展；RFC 768 页面指出 UDP 有后续更新，本轮未实现 UDP options。IPv4 的 UDP 零校验和允许被解析，但显式标记未验证，不能误报为 checksum 已验证。

限制：离线调用者提供可信的分析报告/端点证据；命令按同一文件集重新生成这些证据。此功能验证采样的加密数据往返，不证明接收端重放策略、固件密钥安装、客户端隔离或所有边界状态正确。失败意味着所选格式下未获得充分证据，不是 AP 漏洞结论。未执行新无线实验。自定义实时握手验证、文献及标准精读仍未完成。
