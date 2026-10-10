# M3 Key Data 内容与 padding

实际阅读缓存 IEEE 802.11-2020 12.7.2 Key Data 定义、Table 12-9、Figure 12-36，以及 M3 内容要求（PDF 2552–2554 对应段落）。padding 为 0xdd 后跟零字节；未知元素/KDE 应忽略。GTK KDE selector 为 00-0F-AC:1，其后两字节控制字段再接 GTK。M3 可以有一个或两个 RSNE；第二个具有独立的 cipher override 语义，不能套用管理帧的“RSNE 重复即无效”规则。

联网交叉阅读 [hostap 的 KDE 解析实现镜像](https://raw.githubusercontent.com/vanhoefm/hostap-wpa3/master/src/common/wpa_common.c) 约 2905–2924、2981–3011、3088–3108 行。实现解析证据不能替代规范；本平台记录自身的保守解析范围。

新增 keydata.py。验证 TLV 边界、padding 尾部、RSNE 数量与基本格式；CCMP 组配置要求包含 16 字节 GTK。多个 GTK 被拒绝为当前配置中的歧义；未知元素仅计数，不泄漏原始 payload。GTK reserved 位记录是否为零，不据此推定接收方必须拒绝。两个 RSNE 或 RSNXE 明确标记超出当前支持范围，停止本配置的完整路径结论，不标记 AP 违规。

在 MIC/上下文及 RFC3394 解包通过后才解析；报告分开 key_data_unwrap_valid 与 key_data_content_valid。输出 RSNE、GTK Key ID/Tx/保留位状态/长度、padding 长度和未知元素数量；不输出 GTK 字节或未知内容。这里只检查本配置的结构，不证明完整协商语义或 AP 安装行为。

114 项测试通过，包含 padding、未知元素、两个 RSNE、缺失/短/重复 GTK、截断 TLV，以及 MIC 和 AES wrap 都正确但缺 GTK 的负例。修正测试构造时注意：在声明长度覆盖 padding marker 时，marker 会成为有效 payload 字节，不能把这种情况误称截断。

两组已有 133653 隔离 hwsim 原始抓包重新验证，M3 内容均通过：16 字节 GTK、2 字节 padding，无上下文异常。本轮无现场发包。

仍需：M3 与 AP Beacon/Probe Response 的 RSNE/RSNXE 关联、第二 RSNE override 规则、OCI/PMF/IGTK、内部安装与计数器生命周期证据。现行标准全文及系统文献精读目标尚未完成。
