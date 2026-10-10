# 组密钥握手与接收计数配置

2026-10-10。读印刷页 3076–3078，结合前轮 3075 已读开头，完成 12.7.7.1–4 的文字。12.7.7.5 样例只有开头，图未核验，不登记整节完成。

组握手需在四次握手成功后执行；请求组更新可以被忽略，因此请求后无响应不是自动违规。组 M1 replay counter 要高于会话已收值，重试也增新值；组 M2 回显对应 counter，且需有效 MIC/AEAD。控制报文 counter 与 GTK 数据 RSC/PN 是不同域。

12.7.7.4 明确保留最近 EAPOL 安装的 GTK/IGTK/BIGTK/WIGTK，不得再安装匹配材料。结合 6.5.14，同材料不得把数据 replay floor 回退；合法更新可向上推进。完整 WNM 跨来源保存规则待结合 11.2.3.15，不能以本节覆盖所有分发入口。

对应漏洞成因沿用前两轮选读 CCS2018 6.3 跨分发路径重装及 USENIX2020 安装副作用分析；本轮以现行标准落实控制计数与数据计数分离，不新增论文阅读范围或复现声明。

新增 APModel 内部事件 rx_counter_configured，要求 key_id、nonce_domain、非负整数 pn。它表示实现配置后的接收 replay floor，而不是无线报文中宣告的 RSC。仅当前已安装材料可配置；缺 key 产生 RX_COUNTER_WITHOUT_KEY，低于该 peer/material/domain 先前账本值产生 RX_COUNTER_ROLLBACK，分析账本保留 max，不因观察到错误回退而遗忘历史。随后 data_accepted 复用同一账本，pn 不超过配置 floor 即可识别为 RX_REPLAY_ACCEPTED。

事件可用于 GTK/IGTK 等插桩域以及 PTK，nonce_domain 须覆盖真实算法/方向/TID 等接收域，不得将不同域随意合并。新材料 key_id 有独立 floor；跨会话同材料/域保留账本。pcap/probe 仍仅记观察，不配置内部计数。尚无适配器自动产生此事件，也未实现组握手发包构造或密码验证；报告缺配置证据时不能断言 RSC 正确。

按用户要求未运行测试或改后模块，代码未验证；未扩展客户端、未发包。reading-log.md 已更新。下一步组握手样例/分析及对应状态机，逐项补原文依据。
