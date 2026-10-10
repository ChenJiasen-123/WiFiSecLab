# 控制状态与握手证据关联

实际阅读 [hostap sta_info.c 实现镜像](https://raw.githubusercontent.com/vanhoefm/hostap-wpa3/master/src/ap/sta_info.c) ap_sta_set_authorized、ap_sta_disconnect 和 ap_sta_flags_txt 的相关段落（约 1178–1256、1258–1281、1355–1390 行）。AUTHORIZED 是 hostapd 中的控制状态标志；它不是驱动密钥成功返回、固件状态或数据交付的同义词。实现镜像不是现行标准。

现有生命周期控制器已有同 STA 的 AUTHORIZED 检查，内核 trace 模块已有 cfg80211 请求/返回及丢事件检查。但历史 smoke 快照未存查询时间与文件摘要，不能把控制状态精确绑定到捕获握手。

新增 control_snapshot.py：关联单站快照、可信采集器身份、pcap 和快照 SHA256、同主机 realtime 时钟声明、采样起止区间、最后一个无歧义的 MIC 验证握手。采样必须在验证 M4 后 5 秒内；后续上下文断点保守要求独立会话证据。文件摘要是来源绑定，不是采集器可信性的密码学认证。

保留独立的 control_authorized_observed；它只表示采样时 hostapd 的 AUTH/ASSOC/AUTHORIZED 状态，不修改纯抓包报告的内部安装结论，不生成未经证明的 key_installed 事件。没有授权标志也不自动归为漏洞，可能处于不同阶段。

正式 eapol CLI 增加 --ap-station-file 和 --snapshot-metadata，要求成对提供。现有 hwsim_smoke 采集器改为查询指定 STA，并记录时间、AP/STA 实际接口身份及摘要，待 tcpdump 停止后绑定最终 pcap。

125 项测试通过，覆盖正确关联、缺失/错误摘要或身份、时间窗口/非有限时间、重复 flags/错误 STA、未授权与后续断点、CLI 集成。采集器通过语法检查，本轮未在 Linux 上运行更新后的采集器，因此不能声称新增实测通过。

重审历史 133653 WPA2 与 transition-psk：快照确实含 AUTHORIZED，但缺少必要元数据，新增关联结论均为 false。没有补造时间或把文件 mtime 当采样时间。本轮无现场发包。

后续需在隔离实验运行新采集器、验证采样/握手对应，再接入 cfg80211 成功返回、稳定密钥身份和 PN 生命周期；现行标准及近 30 年系统文献阅读仍未完成。
