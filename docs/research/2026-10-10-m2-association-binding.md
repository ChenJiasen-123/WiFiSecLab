# M2 与关联请求的 RSNE 绑定

实际重新阅读缓存 IEEE 802.11-2020 12.7.6.3 的处理段落（PDF 2561/印刷 2560）：非 FT 情况要求 RSNE 以及适用的 RSNXE 与关联请求逐位一致；FT 有 PMKID 等独立规则，不能套用普通字节比较。该历史版本不替代现行版全文。

联网交叉阅读 [hostap 实现镜像](https://raw.githubusercontent.com/vanhoefm/hostap-wpa3/master/src/ap/wpa_auth.c) 约 2875–2957 行的 Key Data 解析、RSNE/RSNXE 比较和 OCI 检查。这些是实现证据，不代表全部设备或当前规范。

实现限定为抓包中同一 AP/STA 的 PSK/CCMP、无 RSNXE 关联上下文；普通关联和重关联分别跳过 4/10 字节固定字段。M2 RSNE 必须存在、完整、无重复；存在上下文时逐位比较。断点清除旧依据；不通过外部单个关联文件给全部会话套同一上下文。

报告增加独立的 association_bound_mic_verified_four_message_path_observed。没有关联依据时不声称绑定；有证据时仍不推断 AP 实际检查、安装或授权。RSNXE/OCI、M3 内部 RSNE、完整协商合法性仍未实现。

104 项测试通过，覆盖匹配、参数不匹配、缺失/重复、断连清除及无上下文的三态结果。已有 133653 WPA2 和 transition-psk 两组原始隔离抓包均含匹配的关联 RSNE，新增绑定结论均为 true；MIC/路径仍正常。本轮无新增现场发包。完整目标保持未完成。
