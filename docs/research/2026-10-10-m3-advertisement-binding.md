# M3 与 AP 广播 RSNE 绑定

实际复核缓存 IEEE 802.11-2020 12.7.6.4 接收处理（PDF 2563–2564/印刷 2562–2563）：非 FT 情况 M3 RSNE 与 AP Beacon/Probe Response 一致。RSNXE、OCI、FT 和第二 RSNE 有额外规则，本轮不将其等同于基线字节比较。

联网交叉阅读 [hostap supplicant 实现镜像](https://raw.githubusercontent.com/vanhoefm/hostap-wpa3/master/src/rsn_supp/wpa.c) 1435–1504 行的广播参数来源、M3 RSNE/RSNXE 比较；实现与历史版本标准是独立证据，不代表现行规范精读完成。

分析器收集同源 AP/BSSID 的 Beacon（广播目的地址）和发往指定 STA 的 Probe Response。检查管理帧及 IE 边界，保留 `max_gap` 窗口内各不同 RSNE；损坏、缺失或带 RSNXE 的广播作为不可用候选保留，不能静默退回更早的合法参数。

在新路径 M1 时冻结唯一可用广播依据及原始 packet_index/time；之后的新 Beacon 不能覆盖当前路径。缺失、过期、冲突或不支持时保留未绑定。M3 经 MIC、上下文、AES unwrap、内容检查后才逐位比较第一个 RSNE。异常不直接认定 AP 违规。地址匹配的未认证广播只是抓包证据，不能证明 STA 实际收到或采用了该广播。

新增 `rsne_bound_mic_verified_four_message_path_observed` 要求 M2/关联绑定、M3/广播绑定、M2–M4 MIC 和完整路径全部通过。继续保留内部安装/授权未证实。修复未知 EAPOL 标志断点留下待用关联依据的问题，使断点真正清除旧关联上下文。

119 项测试通过：匹配、MIC/wrap 正确但广播 RSNE 不匹配、缺失/过期/冲突/损坏/不支持广播、M1 后不可覆盖、其他 BSSID 不可供证。已有 133653 的 WPA2 与 transition-psk 均通过新增结论；前者使用第 13 个记录的广播依据，后者第 14 个。过渡模式中 AP 广播包含 PSK/SAE，而 STA 关联仅选 PSK：M2 与 STA 请求比较，M3 与 AP 广播比较，不能把两者混为一个 RSNE。

本轮无现场发包。仍需完整安全配置协商检查、RSNXE/OCI/PMF/第二 RSNE、AP 内部安装和 PN 生命周期证据，以及现行标准和系统文献精读。整体目标未完成。
