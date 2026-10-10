# Lifecycle and evidence layer 
 
- lifecycle.py: lifecycle states 
- data_session.py: data-plane session handling 
- control_snapshot.py: control-plane snapshot correlation 
- key_evidence.py: key install / delete / residue evidence 
- encrypted_evidence.py: encrypted payload verification 
- udp_evidence.py: UDP evidence parsing 

lab_datagram.py allocates PN before encryption for one caller-established fresh TK context and uses the shared network.ccmp baseline AAD function. Recreating the allocator with reused TK material is not supported. Integrity-scope metadata is retained by encrypted_evidence.py and data_session.py.

gtk_retirement.py tracks role-specific old-GTK deletion obligations from ordered internal events in one BSS/epoch. Stable material handles differ from wire Key IDs. Capture events remain observations; this API is not yet wired to an instrumentation collector.

Offline GTK reports: `wifiseclab-gtk trace.json --output report.json` (new output file only). Input root fields are bss_context, role, events. Events require kind, material_id, context, source, evidence; installed/deleted internal events additionally require operation_completed=true with a completion evidence reference. This confirms collector-reported completion, not firmware erasure. Input order is authoritative and must be justified by the collector; pcap/probe events do not change internal state.

GTK 删除历史：在同一 BSS/epoch 中保留已完成删除的材料身份；再次安装输出 previously_deleted_material_installed 线索，仍不推断 PN 重置或重放接受。删除完成必须有此前安装记录。历史仅限输入窗口，跨 epoch 关联尚未实现。

key_evidence 的阶段标记需唯一且按 connect/disconnect/reconnect 顺序，歧义为 unknown_phase_boundaries。报告 cfg80211_call_return 只表示调用返回，operation_completed=false，不可直接映射为主模型密钥完成事件。

- group_delivery.py：GroupKeyDelivery 记录同一 BSS/update/material 的固定成员会话快照、M1 发送计数器和内部接受的 M2；必须显式绑定来源与上下文。不执行收发、不代建客户端；成员确认不证明 MAC 安装或旧 GTK 删除。尚未接入采集器或 CLI。

key_evidence.analyze 只覆盖指定 peer 的 pairwise cfg80211 操作，不能证明 IGTK/BIGTK 配置或 IPN/BIPN 初值，不可作为 BIP 完整密钥上下文。报告显式标注此作用域。
