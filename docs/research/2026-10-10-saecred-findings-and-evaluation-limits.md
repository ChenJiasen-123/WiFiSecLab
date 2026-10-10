# SAECRED 发现与评价范围

完成 7.1 余段、7.2、8 引言、8.1–8.3 全部对应正文（作者 PDF 第 11–13 页，结合前轮第 10 页 7.1 开头）。9 仅引言，不计案例分析已读。表 2/3 和图 5 仅文本；第 13 页图 6、表 4 完成视觉核对。表 5 引用尚待后页核对。来源：https://papers.mathyvanhoef.com/ieeesp2025.pdf

论文把发现分四类，但 unexpected association/general parsing 的安全影响明确仍未知。响应成功不能自动证明 SAE Confirm 完成、双方 PMK 一致或四次握手/数据授权可用，论文明确其工具未 fuzz 四次握手。猜测 buffer overflow 不是实际内存安全证据；我们的报告也不能以此升级风险结论。

bug instances 是输入产生的实例计数，不是 deduplicated 漏洞根因数量。多队列找到更多类别不等于在每一类别都有更多实例：论文单队列 downgrade 计数反而较多，体现状态覆盖与重复触发的取舍。消融研究的配置、运行预算和目标必须在比较时保留。

视觉核对表 4：SAECRED 的 sae.c function coverage 75.9 与若干配置相同，不可概括为所有文件/所有指标都严格更高；ieee802_11.c 结果另列。图 6 是平均 function coverage 随时间，不是表 4 的最大文件覆盖，也不是六台黑盒固件的代码覆盖。harness 排除了完整网络栈路径，不能推广成全系统覆盖率。论文性能成本同样不能直接当本平台工时估计。

平台现状核对：stage_outcome 的 success_response_observed 只是关联/认证响应；stage_evidence 是事件覆盖；APModel status 为 candidate_violation/no_violation_observed。三者都不能替代独立根因确认。后续结果数据应分别计用例、异常轨迹、去重根因和确认安全影响，保留目标版本、适用 profile、证据及未验证前提。不因新增计数面板而改变这些含义。

本轮主要推进论文阅读及评价约束，无新增标准章节，无运行代码改动、无测试。下一步读 9 的根因与修复条件及后续章节。
