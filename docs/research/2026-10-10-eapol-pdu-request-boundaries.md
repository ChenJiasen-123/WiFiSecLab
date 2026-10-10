# EAPOL PDU 边界及独立 Request 计数域

2026-10-10。精读 IEEE 802.11-2024 12.7.2 印刷页 3052–3056 的正文，图 12-35–37 此轮只读提取文字，未视觉确认，且 12.7.2 后续页尚未读完。旁读 3038 末尾关于 Pairwise/Group Request 的文字，不声称已完成 12.6.21。

## 新读规则

3052 要求 Key Data 后不能在 EAPOL Packet Body 中另有字节；3053 Note 2 允许承载 MSDU 在 Packet Body 之后存在额外字节。两个边界不同。3056 的 MIC 覆盖从 EAPOL 版本到 Key Data，包含声明的 PDU，不含外层 MSDU 尾部；长度不足仍是截断，Key Data Length 必须与声明包体一致。尾部允许存在不意味着任意内部长度矛盾合法，更不意味着第二个拼接 PDU 可以成为另一次握手输入。

3054 区分 Request、Error、Ack：Error 表示 TKIP Michael 失败报告，不能把它当 CCMP 的一般 MIC 错误，也不能把所有 Request 位都当主动请求新握手。Request 与 EAPOL-Start 不同；TDLS peer 不能互发这种 Request。3055 要求 Supplicant 的主动 Request 发送计数器与响应计数器分开，AP 的 Request 接收过滤也单独维护。正常发送及接收计数器按安全关联管理，(re)association 初始化边界需要与平台 session/exchange 标识区别。M1 无 MIC，不能更新已验证接收计数器。

3038 的 Pairwise Request 在当前没有四次握手时要求启动 PTK 重协商，并不因此改变 GTK；Group Request 的 GTK 更新用 should，且 WNM sleep 和正在四次握手中的 STA 有特殊分发处理。该段处于 beacon protection 附近，需继续结合 12.7.2 全节及相关规则，不据旁读建立完整 Request 执行器。

## 论文对照

相关基础工作为 Vanhoef/Piessens 的 ASIACCS2017 Discovering Logical Vulnerabilities in the Wi-Fi Handshake Using Model-Based Testing，作者原文：https://papers.mathyvanhoef.com/asiaccs2017.pdf 。本轮阅读 2.5 的字段与消息文字及 3.1 一般方法开头（PDF 页 3–4 的对应文字），其思路是把正常交换、预期回应和连接判据绑定后，再系统变更输入。失败需进一步核查，不能直接等同可利用漏洞。此次不是整篇精读完成，图未核验。旧文协议简图不能替代 2024 的例外及新 AKM。

## 平台改动与限制

protocol/eapol.py 的 decode_key 原先拒绝全部 MSDU 尾部，现在先检查声明包体完整，再截取准确 PDU 边界供字段解析、摘要和 MIC 校验。外层尾部仅保留 msdu_tail_length/msdu_tail_sha256，不解释为第二条消息、不宣称真实性。Key Data 内部长度一致性继续严格校验。该修改影响观察和既有响应组件使用的解码输入边界；不新增客户端或发包逻辑。

Request 独立域已明确，但尚未实现完整 Request 接受判定；现有未知 flag 路径仍保守处理。跨关联的计数器重置、AEAD 可变 MIC、TDLS、完整组更新亦不在当前 decoder profile 内。本轮只做 Python 语法和本地导入路径静态检查；未运行测试、未发包。下一步继续读 12.7.2 后续 KDE 与加密数据要求，并结合 802.1X 的 PDU 长度规则核对。
