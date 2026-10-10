# Protocol and handshake layer 
 
- authentication.py: auth observation 
- association_gate.py: association gating 
- eapol.py: EAPOL decode and handshake analysis 
- wpa2.py: key derivation and MIC logic 
- wpa2_session.py: WPA2 state machine 
 
These modules represent the 802.11 / WPA2 security semantics layer.

- wnm.py：解码已去除 MAC 头和保护封装的明文 WNM Sleep Response Action body，严格检查字段/子元素边界，支持多个密钥子元素，返回脱敏元数据。解析成功不证明 MIC、安装或对端接受。未知子元素只报告类型/长度，不解释其语义。

OCI：decode_oci_element 仅接收完整 6/9 字节 IE，校验 ID=255、扩展 ID=54、声明长度及完整 OCT 三字段。WNM 响应支持提取唯一 OCI 并保留两个信道域，附带 global class 参考行；解码本身的 channel_validation 保持 unknown。独立 ocv 比较器需要额外的链路快照，不证明 OCV 已启用。

- operating_classes.py：2024 Table E-4 中 81–84、115–136 的参考行，保持 channel set/中心索引/spacing 的区别；OCI 解码引用。未知类别返回 None，不自动视为保留值；不提供监管许可、PHY 带宽或 OCV 通过判定。

- ocv.py：OCI 与调用方链路快照的一致性比较，输出 consistent/inconsistent/unknown；检查主频率、最大宽度、40 MHz 次信道方向及 80+80 第二段。class 81 要求显式 OFDM；82、未录入类别及 OCT 完整比较仍 unknown。不证明 OCV 协商、快照新鲜性、完整性或 AP 接受。

链路快照的 max_width_mhz 使用总宽度，80+80 对应 160 且 noncontiguous_80_plus_80=True；矛盾快照被拒绝。连续 160 与 OCI 80+80 的频谱兼容关系尚未实现，报告 unknown，不能仅凭总宽度相同输出 consistent。

max_width_mhz 必须是绑定到具体 peer 的实际最大使用宽度，不是设备能力或 Beacon 宣告宽度。当前比较器不验证快照的 peer/session/时刻绑定，调用方证据引用也不等同于该绑定已经核实；consistent 仅表示给定输入之间一致。

若 max_width_mhz 来自实现依据保存的 peer 能力/Operation 元素推导的使用上限，应明确记录为推导参数，不能称作包级测量结果。当前接口未验证推导来源或完整性；驱动接口状态、推导上限与无线观测须在证据说明中区分。标准符合性结论仍需独立依据。

APModel 的 WNM 输入不得设置 decoded_oci / oci_channel_comparison；它们只由 action_body_hex 解码及条件比较派生。此来源约束不认证明文或快照真实性。

采集器转换注意：VHT Operation Segment 1 与 OCI Frequency Segment 1 含义不同。前者在连续 160 MHz 的 Width=1 编码中表示整个 160 MHz 中心；后者非 80+80 时为 0。不得直接按同名字段复制。VHT Operation 的主信道还需 HT Operation；当前未实现这一转换路径，不能用 VHT 宣告替代实际链路快照。

Extended NSS 边界：11.38.1 的较低 NSS 宽带运行可能经 HT Operation CCFS2 表示 160/80+80 信息。不得单凭 VHT CCFS1=0 判定 BSS 最大宽度为 80；未来转换必须保留 HT/VHT/NSS 的联合前提，缺失时保持 unknown。

keydata.py 的 M3 RSNXE 校验能力字段 1..16 字节及首四位 n-1 与实际长度一致，报告 SPP bit 14 的单方宣告和 negotiation_confirmed=false。保留 baseline_profile_supported=false，不因解析能力位而启用聚合、扩展 AKM 或 SPP 解密。未验证 M3 的 MIC、双方 RSNXE 一致性或接收效果。

M2 报告的 m2_rsne_payload_authenticated 仅在使用给定 PMK 验证该 M2 MIC 成功时为 true；false 表示未建立该证明，包括未检查、上下文不足、提前退出和校验失败，不等同于 MIC 无效。rsne_matches_association 只是与观察到的关联帧比较；不证明该关联帧真实、SSID 绑定、AP 接受或密钥安装。

握手报告 network_identity_validation 当前固定 unknown：未核实外部 PMK 来源、双方 SSID protection 协商或认证 M3 SSID 绑定。RSNE 字节比较及 MIC 成功不代替网络身份验证；对应扩展仍不支持。

SSID 证据使用原始字节 ssid_hex，不做 UTF-8 解码或名称归一化。广播候选按 RSNE/SSID 联合区分，多个候选保持上下文不可用；关联证据保留包序号、时间、帧类型并随边界清理。source_authenticated=false，地址匹配不代表来源认证。

management_header/握手头观察仅保留传统、未分片、无 HT Control 的 Protected 位及可见头；不验证 MIC、不解码密文 Action、不证明接收效果，不覆盖完整组地址 BIP/MMIE。Protected 断开头使观察路径不确定并建立未确认重置的边界。

bip.py：解码精确 MME IE（18/26 字节），核对 Key ID 与可选独立 cipher 长度上下文，不验证 MIC/重放或接收效果。握手报告额外记录目标 AP 组地址断开帧的 MME；仅 reason code + 单个最终 MME profile，其他结构保持不可用。

bip.verify_group_disconnect：给定独立上下文和已知 IGTK 的 BIP-CMAC-128/256 离线 MIC 校验，支持可选 48 位 floor 条件比较；不更新账本。仅传统 group deauth/disassoc + 单一末尾 MME，不覆盖 GMAC、Beacon、S1G、QMF，不证明 AP 接收或唯一发送者身份。采集报告尚未自动接入该校验。
