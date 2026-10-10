# 四次握手 M1/M2：标准、论文与同类边界

2026-10-10。按标准→对应论文→同类代码边界推进。

标准阅读：印刷页 3065–3068，完整覆盖 12.7.6.1、12.7.6.2、12.7.6.3；3068 的 M3 字段仅开头，12.7.6 整节尚未完成。3065 的信息流提取有疑似文字异常，不据提取串实现；图/公式未视觉核对。

M1/M2 要点：当前握手内 SNonce 在有效 M3 前保留；M2 counter 匹配未决 M1；counter 不符和 MIC/AEAD 失败为静默丢弃；非 FT 的 RSNE/RSNXE 与关联请求做逐位匹配。OCV 启用时 OCI 缺失/信道不符也有丢弃要求。M1/M2 的 Secure 位要区分初始和 PTK rekey。3068 非 FT 段同时出现 PMKR1Name 检查，待对照 FT 条款/勘误，不贸然给普通 PSK 增加强制 FT 字段。

相关文献检索先查 2025/2026 四次握手研究，本轮未找到可直接替代既有相关原始研究的结果，不称检索穷尽或 2020 全球最新。随后选读 USENIX Security 2020 https://www.usenix.org/system/files/sec20-cremers.pdf 第 3–4 页关于派生/安装、重传及 nonce 重用的文字；全文和后续证明未精读，图未核验，未运行工件。论文分析强调安装副作用需进入模型，不能仅看理想报文交换。其历史标准不能代替当前 2024 条款。

代码同类审查：wpa2_session 保留当前运行 SNonce、按验证后的历史限制计数器；APModel 的 nonce/RX 账本已有跨会话保留，但 key_installed 只查当前槽，key_deleted 后再次安装同一 key_id 并明确 counters_reset=true 会漏报。

修正：新增 key_installations 历史集合，以 peer/slot/key_id 绑定；删除密钥或替换会话不清除，后续同身份安装及计数器重置产生 KEY_REINSTALL_RESET 候选。适用于模型所有密钥槽（含 PTK/组密钥插桩槽），并非只修握手 M3。key_id 必须稳定识别真实密钥材料；记录来自可信插桩或合成事件，pcap/probe 不推进账本。仅安装不证明实际 nonce 重用；没有 counters_reset=true 不据此自动报重置。

范围限制：跨 slot/peer 的实际 nonce domain 仍须用现有 encrypt_new/RX 账本判断；该安装账本不推断全局唯一性，也不确认固件状态。没有真实 AP 标识的模型不能合并来自不同 AP 的事件。必要时适配器必须提供独立模型实例。

按用户要求未运行测试或改后代码，变更未经运行验证；未扩展客户端、未发包。已更新 reading-log.md。下一步完成 M3/M4 与实现注意事项，再核对重装防护及相关论文后续。
