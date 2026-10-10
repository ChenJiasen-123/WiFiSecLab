# WiSec 2026 TOFU 正文阅读完成与授权边界

继续读作者版第 4–6 页，完成 4.2.2 余段、4.2.3–.9、4.3（含 .1–.3）、4.4–4.5、5–6 对应全文文字。结合前轮摘要及 1–3、4.1/4.2 开头，论文主要正文文字已读完。图 1–3、表 1–2 未视觉核对；参考文献仅作为后续检索线索，未读其全文，不计整篇全部精读。
来源：https://papers.mathyvanhoef.com/wisec2026.pdf

设计思想：持久信任记录应绑定可信根/leaf 及服务端域名，后续连接仍要核实有效期；leaf 轮换与 CA 轮换不同。匿名身份还需 realm，不能一律去掉路由所需部分。自动信任证书的设想依赖 PEAP 内 EAP-PWD 和 cryptobinding 成功，且论文明确侧信道安全假设；不能推广到任意内层认证。首次接受恶意证书是 TOFU 固有风险，原型未提供撤销机制。

必须核实的正文差异：4.2.7 建议过期证书提示后才继续，但 4.3.2 描述 expired/malformed 直接终止、无需交互；4.4 描述三个真实网络，4.5 说 one additional validation。两处均保留待查，不任选一句作确定验收规则。论文的实现/评估结论须绑定其 Ubuntu、NetworkManager 开发版、wpa_supplicant 及 kernel 版本，不代表所有产品现状。

标准复核：12.6.7 全文（3024–3025）明确关联后受控端口仍阻断普通 MSDU；portValid/keyDone 与 MAC 密钥安装关系不可被观察 EAP-Success 取代。12.6.8.1 本轮只读 3025 对应开头、不计全文。重认证已有 RSNA 可保护数据，不应一律断言必须先阻断端口。EAPOL 与普通数据路径也不同。

源码复核：APModel.handshake_completed 不直接设置 authorized；port_authorized 独立检查关联/完成握手/PTK。hostapd_log 只返回 peer_connected、peer_disconnected、pairwise_handshake_completed 原始行，不直接产生 key_installed 或 port_authorized。当前缺真实 AP 端口/密钥完成生产者，保留缺口，不以日志名称自动补状态。

本轮不引入客户端或 Enterprise 协议执行，不改运行代码、不测试。对主目标的贡献是补齐最新文献正文、记录可验证假设与证据映射，并避免把认证层次合并。
