# WNM 响应的字段与上下文边界

新读 9.4.2.80（1186–1187）和 9.6.13.19–.20（1754–1756）对应正文。视觉核对表 9-265/266、9-540 及图 9-1290–1293。图 9-549、9-1289 只读文本，尚未视觉核对。

Dialog Token：请求非零，普通响应复制请求，非请求响应为 0。状态 1 为退出且需更新组密钥。未协商 PMF 时 Key Data Length 为 0，Key Data 不出现。RSC 为小端，并可能有多个 GTK/IGTK/BIGTK 子元素；不能只接受一个子元素或把槽位当材料身份。退出时保留的 Sleep Interval 不应被解释为有效睡眠周期。

APModel 加入 wnm_response_sent 语义检查：字段范围、保留值、状态/动作关联、非请求退出、可选请求 token 匹配、已知 PMF=false 的 Key Data 边界。发送响应不自动更新 wnm_sleep 或密钥状态。外部 pcap/probe 仍为 observation，未知 PMF 不当作 false。

待完成：完整 WNM 字节解码/解密、长度一致性、请求 token 生命周期、TFS 非请求触发证据、OCI 验证和多子元素材料/RSC关联。本轮无新论文阅读，不增加论文覆盖数。只做 AST 解析，没有运行测试、CLI 或发包。
