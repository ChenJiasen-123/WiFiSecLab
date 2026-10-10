# Authenticator 状态机与当前阶段重试判定

2026-10-10。完成 IEEE 802.11-2024 12.7.10.1–12.7.10.4，印刷页 3089–3096 的对应文字；渲染并视觉核对图 12-54–12-57（3090–3093）。3096 的 12.8 只旁读，不登记该节完整阅读。

## 标准及证据要求

图 12-54 中 M2 收到、MICVerified、PTKINITDONE 是不同边界。M4 必须是非 Request 的 Pairwise 消息且 MIC 已验证，才能沿对应边进入完成状态。SetPTK 失败需要 AP 检测并恢复；12.7.10.2.1 使用 should 和举例，不能把某一个固定去认证动作当成唯一合规恢复。

图 12-55 的 INITIALIZE 包含关闭端口、删除 PTK 等动作。平台仍必须保留分别观察这些动作的能力；收到断开帧不等于它们都已成功执行。图 12-56/57 区分每 STA 的组更新与全局组密钥切换；更新完成计数包括失败退出和 WNM sleep 排除，不能要求所有关联 STA 都发过 G2 才允许切换。3091 的 BSS max idle/doze 条件允许跳过 KEYERROR 中的 Disconnect，不能统一判定超时即应断开。

12.7.10.3 明确每次 Authenticator EAPOL-Key 发送递增重放计数器。响应复制对应请求计数器；主动 Request 使用另一个接收重放计数域。Ack、Request、Pairwise/Group 和 key index 也参与合法性判断。MICVerified 对 AEAD 的含义是 AEAD 解密步骤成功，不能只实现传统 MIC 就宣称覆盖全部 AKM。

同节 DISCONNECT 状态描述提及 MIC 失败，而变量说明要求丢弃无效 MIC；图的完成转移也要求 MICVerified。不能据单句状态摘要生成“任何坏 MIC 必须断开”的规则；需要分支、上下文及相关规范条款共同解释。

## 论文衔接

重新检索并核对 NDSS2026 WCDCAnalyzer 官方论文入口：https://www.ndss-symposium.org/wp-content/uploads/2026-s1049-paper.pdf 。其范围为 Direct、EasyConnect、EasyMesh；此前已读正文与附录的范围不变，本轮不声明新增整篇精读。其分解思路提醒平台需保留阶段接口和共享上下文；它不是普通基础设施 WPA2 AP 的完整判定规范。密钥副作用跨机制的具体背景仍参见已读 USENIX2020 WPA2 模型与 CCS2018 阅读记录。

## 本轮代码修改

core/model.py 的 handshake_message 原先只接受同阶段同计数器重复事件，把当前 M1/M3 阶段递增计数器的重试误报为阶段顺序异常。现保持当前阶段，更新响应关联计数器；降低的计数器报告 HANDSHAKE_REPLAY_COUNTER。相同值仍按重复观察处理，因为当前事件没有区分一次发送的重复采集与实际新发送，不能证明实际发送违反递增要求。重复安装及计数器重置仍由 key_installed 独立判断。

限制：这是单一当前阶段的抽象关联；没有实现多个在途请求集合、接收 Request 独立域、组更新全局协调或完整图状态。后续应补充这些上下文与证据源。此次未扩展客户端、未执行测试、未发包；只做语法和本地导入目标静态检查。
