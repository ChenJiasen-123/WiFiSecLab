# 组密钥分发接入主模型

复核标准 12.7.10.2.2–.3 及相关变量（3094–3096 页对应文字）：per-STA 分发状态和全局更新状态分开，SETKEYSDONE 还涉及 SetGTK 失败恢复与 WNM sleep 例外。不能把所有关联 STA 简单视为本轮必须响应的固定集合。本实现只处理调用方明确给出的成员快照，不声称其为全局完整集合。

APModel 新增 group_update_started、group_message1_sent、group_message2_accepted，接入 GroupKeyDelivery，已有 CLI 可接受这些 JSON 事件并在报告中输出 group_key_delivery。启动检查成员关联/会话与 pairwise 前提并报告线索；旧关联事件不再更新账本。同一 update 不混用 synthetic/instrumentation，不允许复用 update 身份。组分发线索汇入主报告 findings，不把组事件错误计作四次握手阶段覆盖。pcap/probe 仍只作外部观察。

边界：尚无真实采集器生成新事件；只有显式输入证据的离线链路。跨更新计数器下界、重复 M2 再接受、超时、WNM 和动态成员未实现；快照确认不会自动生成安装或删除完成。无新文献阅读，不增加全文阅读数。仅 AST 解析，未运行 CLI、测试或无线实验。
