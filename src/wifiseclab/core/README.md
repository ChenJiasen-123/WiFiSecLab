# Core state machine 
 
- model.py: APModel / Event / Peer / Finding core logic 
- session.py: association and lifecycle context 
- stage_evidence.py: phase evidence aggregation 
- planning.py: offline planning and stage generation 
 
The real implementation now lives in this package directory; the root package keeps small compatibility shims for the old import path.

计数器事件：EAPOL-Key replay_counter 限定为无符号 64 位；data_accepted/rx_counter_configured 的可选 cipher 为 ccmp-128 或 ccmp-256 时，pn 限定为无符号 48 位。未知密码套件不自动套用 CCMP 上限，nonce_domain 仍需采集端绑定真实 SA/TID。

msdu_delivered：内部完成分类后的实际交付证据，限 bss_type=infrastructure；payload_class=eapol/user_data，destination_path=peer_sta/portal/bridge/local_upper/pae，individually_addressed 必须为 bool。peer/session 指发送方当前关联上下文，destination_path 指 AP 对接收 MSDU 的交付方向。EAPOL 交到非本地 PAE 或非个体寻址为候选异常；普通数据要求关联及授权。pcap/probe 仍只作未确认观察，不升级成内部交付。该事件不是 data_accepted 的别名，不推断解密、PN、MIC 或实际目标地址；尚未连接证据生产者。不适用于预认证封装、mesh、IBSS 或 PBSS。

交付四字段保存在内部历史 msdu_delivery，外部声明保存在未确认观察 reported_delivery。报告 conformance_proven 固定 false；no_violation_observed 表示当前输入没有触发候选规则，不能作为已测试完整、AP 安全或规范符合的通过结果。未观察到转发不自动生成“已阻断”事件。

聚合来源可选 aggregate_id + subframe_index，必须同时提供；标识非空，序号为 0..65535 的整数（采集输入界限，不是标准规定的子帧数量上限）。每条交付对应一个完成分类的 MSDU，分别检查权限；两个字段保留在历史/未确认观察中，不证明聚合完整性、不推断首个或全部子帧均已通过检查。生产者须将 aggregate_id 绑定到同一 AP/peer/session 下的实际聚合实例，不能仅用可回绕 Sequence Number。

密钥操作证据：key_install_requested/key_delete_requested 仅记录请求，data.slot 必填。真实 instrumentation 的 key_installed/key_deleted 要求 data.operation_completed 为 true，evidence 指向 MAC 实际效果；这不是标准 confirm 消息。synthetic 的旧抽象场景可省略标记，显式 false 不允许。旧插桩输入必须升级，不能把请求日志直接映射为完成事件。

组密钥分发接入现有 wifiseclab JSON trace：group_update_started 的 data 包含 bss_context、update_id、material_id、members（peer 到 association session 的映射）；Event 顶层 peer/session 仍须非空，启动事件这两个字段仅作证据归属。group_message1_sent/group_message2_accepted 的顶层 peer/session 指定成员，data 包含 bss_context、update_id、replay_counter；M2 另需 integrity_valid=true。报告 group_key_delivery 独立于四次握手覆盖率，不自动安装/删除密钥。pcap/probe 仍只进入 observation。成员快照不证明整个 BSS 完整，WNM 与动态成员尚未建模。

WNM 成员状态：wnm_sleep_enabled/wnm_sleep_disabled 表示 AP 内部服务状态已生效，不能由空口请求直接生成。初值 unknown（None），断开后恢复 unknown。已确认睡眠成员加入组更新快照或发生组交换会产生线索；未知状态不视作 awake。当前不验证 WNM 能力协商、请求/响应、OCV 或退出时密钥分发路径。

wnm_response_sent 的 data 必填 dialog_token/action_type/response_status（各 0..255）和 key_data_length（0..65535），可选 request_dialog_token（关联请求的非零 token）。检查保留值、退出状态、非请求响应和已知无 PMF 时 Key Data 非零；不自动切换睡眠状态。字段必须来自已解码且正确绑定关联的证据，当前无空口生产者。

wnm_response_sent 可用 action_body_hex 提供明文 Action body，解码导出四个必填字段；同时提供字段必须一致。输入不包括 MAC/FCS/CCMP 封装，不能直接喂完整抓包。主模型不保留原始密钥字节，不据解析结果赋予完整性或安装结论。

wnm_response_sent 使用 action_body_hex 时可附 link_channel（primary_frequency_mhz/max_width_mhz/noncontiguous_80_plus_80，按需 secondary20_offset/segment1_frequency_mhz/phy_profile）和非空 link_channel_evidence，报告信道一致性。仅条件比较，不作为规范通过或漏洞裁决。

PMF 覆盖限制：management_accepted 当前不核对 BIP 的 IGTK/BIGTK、IPN/BIPN 初值、QMF/ACI 或 MIC 后计数器更新。通用 data_accepted 不能作为完整管理帧符合性检查；具体证据契约见研究笔记 2026-10-10-bip-replay-and-key-context.md。

planning 每阶段 state_evidence_contract 规定运行时状态、用例/关联/序列/窗口绑定、unknown 与复位证据；它是计划契约，尚无执行器，不把 after、timeout 或执行时长当状态/代码覆盖证明。

stage_evidence 保留各 stage 的 evidence_records（原 history_index/event/evidence），包括重复事件并按 peer/session/source 隔离。仅用于覆盖来源追溯；不执行状态推断、不确认 AP 内部状态或时序符合性。

planning.oracle_contract 区分已知 profile、配置前提、候选偏差和已确认违规；广播不是内部配置证明，静默不是崩溃，不支持不是违规。仅计划契约，尚无自动 oracle。
