# 正常 M4 离线构造

实际复核缓存 IEEE 802.11-2020 12.7.6.5 的 M4 字段和接收规则。M4 在此配置中带 Pairwise/MIC/Secure，Key Length、Nonce、IV、RSC、Key Data 为零；counter 对应被响应的 M3。多 pending counter 和先前回复计数器规则仍由有历史的分析器处理，单次构造函数不声称判断到达顺序或新鲜度。

联网交叉阅读 [hostap supplicant 实现镜像](https://raw.githubusercontent.com/vanhoefm/hostap-wpa3/master/src/rsn_supp/wpa.c) 1517–1553 的 M4 构造和 1556–1704 的 M3 处理。实现把报文响应、PTK/GTK 配置和端口状态分成操作；平台也不能把生成 M4 等同于 AP 已授权。历史标准/实现阅读不代表现行标准整体完成。

build_m4 仅支持一组明确的初始 PSK/CCMP 分支，复用 M2 构造校验其完整 EAPOL 字节，再验证 M3 上下文、MIC、AES unwrap、Key Data 与兼容 AP 广播参数。拒绝不匹配身份/SSID/RSNE、必需 PMF、扩展 Key Data 等情况。随后生成普通 M4；没有安装密钥、发送或重放控制。

正式离线工具 tools/protocol/wpa2_build.py / wifiseclab-wpa2-build 支持 M2、M4，要求显式输入文件和单个已知 PMK，输出不能覆盖。没有自动读取现场数据或发送能力。

133 项测试通过。生成的 EAPOL M4 与此前独立捕获的 hwsim M4 逐字节一致，包含生成 M4 的离线路径通过全部已实现检查；负例涵盖身份、nonce、counter、PMK、M2、广播参数和 MIC 失败不触发 unwrap。正式 CLI 输出及不覆盖行为已验证。本轮无现场发包。

完整自定义客户端主动握手尚未实测，仍需持久会话/重试生命周期、合法密钥安装、数据验证、隔离实验内部 oracle。完整标准与系统文献目标仍未完成。
