# PMKSA 缓存与信任有效性

## 标准精读
IEEE 802.11-2024 12.6.8.1–.3 全部对应文字（3025–3028，止于 12.6.9）；邻近 IBSS 文字不计全文。General 区分认证/关联和 PASN（成功不打开 802.1X 端口）。预认证已 deprecated；须受 pairwise、FT mobility domain、目标能力、PMK 长度及 AKM 条件约束。EtherType 88-C7 与普通 EAPOL 88-8E 不同，不能把预认证经 DS 分发误判为普通 EAPOL 违规转发。

缓存 PMKSA 不可在缓存期间改变，PMK 用于建立 fresh PTK。关联携带 PMKID 只是请求复用，需 Authenticator 缓存及 AKM 匹配；符合条件的响应 M1 带 PMKID 也不独立证明最终成功。缓存 miss/AKM mismatch 下 SAE、802.1X、FILS、OWE 的回退行为不同，不能统一要求某一 status 或立即失败。FT 初始域关联使用缓存与 FT authentication 本身不同。

双方声称缓存存在后握手失败，可删除（may）；寿命到期必须删除（shall）。无缓存实例/AKM/期限/材料身份和真实完成证据时，观察 PMKID 不建立缓存账本。

## 2026 论文原始修复核对
本轮成功通过 urllib 获取官方 cgit，完整读两个提交说明及 diff，web 获取失败不计阻塞：
https://git.w1.fi/cgit/hostap/commit/?id=df739e9e7c24adfbba51266bd0e4ba6489e6cda0
https://git.w1.fi/cgit/hostap/commit/?id=41996889f1ad11c3d762c1079b56259c98a90863
两提交 committer 时间均为 2025-10-06，不能因论文 2026 发表便把修复时间记为 2026。

第一提交在未配置 CA 时增加 leaf depth 0 的 notBefore/notAfter 检查，避免把时间错误一起覆盖；第二提交在 server_cert_only 的 hash 匹配路径中保留 expired/not-yet-valid 错误。显式 disable-time 配置仍有区别。只读对应 OpenSSL callback 修改，不宣称其他 TLS backend 或所有平台已修复。该源证据支持区分 pin/hash 身份相等与时间有效，未解决论文 TOFU 提示/拒绝及真实网络数量的两处差异。

## 平台映射
当前 network.hotspot.rsn_details 记录 pmkid_count，不保存完整 PMKSA 缓存来源/期限；wpa2_session 无完整缓存账本。不能据此宣称 PMKSA 状态测试已支持。未来必须把缓存实例、原始 AKM、BSS/peer、建立途径、寿命、PMK 材料身份和新 PTK 绑定分别取证；AP 缓存清除和客户端证书过期是不同义务。优先 PSK，不新建客户端。

漏洞思想推广：稳定身份相同不意味着状态仍有效，例外分支不应绕过仍成立的不变量。但证书 pin 不能机械等同于 PMKSA：规则和生命周期分别来自适用标准。当前无直接 grounded 的运行修复，因此只更新研究依据，不增加未经设计的缓存判断。

本轮无运行代码改动、无测试。
