# SAECRED 理想状态与证据来源

继续精读 SAECRED 作者版第 4–7 页：2.2、3、4、5 引言、5.1 全部对应文字（含算法 1 提取文本及常量说明）；5.2 只读 Partitioning Inputs、Seed Inputs，Sampling 开头不计全文。图 1–3/算法版面未视觉核对。来源：https://papers.mathyvanhoef.com/ieeesp2025.pdf

论文明确区分 state inference engine 的 idealistic state 与真实 AP 状态。输入 tuple 中同时保存 state、provenance sequence、grammar 和 score，因为同一个 idealistic state 可能对应无法映射到标准状态的实际执行。unexpected response 被放入 interesting traces 后仍需人工分析，不自动当成已证漏洞。协议响应合并等 benign deviation 也要求谨慎 oracle。

借鉴到 WPA2：覆盖 stage 的事件种类集合不能表达顺序、重复、证据位置或输入序列。保留来源是后续状态上下文核查的前提，不等于完成状态推断。现有 stage_evidence 本就只统计覆盖，本轮增加各 stage evidence_records：history_index、event、evidence，保留重复和历史相对顺序，并继续按 peer/session/source 分隔；teardown 包含 disconnect one-of 的来源。没有排序修复、推断丢包或跨 source 合并。

报告新增 state_inference=not_performed_by_event_coverage、ap_internal_state_confirmed=false，明确覆盖不能证明真实状态。全量输入序列及 runtime 编排绑定仍由计划契约要求，尚未接入 executor。论文三种 SAE 状态不直接搬到 WPA2，不实现 SAE 测试客户端。

本轮无新增标准完整章节；仅 AST 语法检查通过，未运行导入/单元/无线测试。后续继续读 5.2 后续及 test oracle，审计推断所需前提。
