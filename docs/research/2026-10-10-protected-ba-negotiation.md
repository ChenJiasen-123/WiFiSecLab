# 受保护 BA 的协商与窗口授权（2026-10-10）

精读 IEEE 802.11-2024 10.25.7 全部对应文字（2072–2073，止于 10.25.8 前）。MFPC=1 加 PBAC=1 表示 PBAC 支持；只有双方都是 PBAC STA 且建立 BA 协议，才能按受保护 BA 处理。单方能力广播或仅 PMF 能力不等于 PBAC 协商成立。PBACRequired 决定是否允许与非 PBAC 对端建立普通 BA。

受保护 BA 接收端不得用 BAR、MU-BAR Trigger 或 GCR-MU BAR Trigger 中的起始序列号更新 WinStartB/WinStartR；指定超窗条件计入 PBAC 错误。窗口更新改用 PBAC WinStart Update，其 TID 和 TA 必须匹配该协议实例，再依照引用的窗口过程处理。该条款不表示所有 BA 控制帧都以同样方式加密，也不表示任意数据包不能按数据窗口规则推进。

平台决策：上一轮计划中的 protected_ba_mode 必须来自双方能力和已绑定协议建立证据；未知模式保持未知，不能默认普通或受保护。当前初始 WPA2 基线执行路径不支持 PBAC，保持该限制；本轮不再新增无执行支撑的同义字段，也不实现只读完局部规范的窗口模型。后续需要读 PBAC WinStart Update 的帧格式、保护类别、验证前置条件和错误计数证据来源。

关联历史文献：核实 Bl0ck: Paralyzing 802.11 connections through Block Ack frames 的 arXiv v2 元数据（2023-05-23）并读摘要，全文尚未精读。该文以 802.11-2020 为标准背景，不能将其结论直接等同于 2024 版条款或当前目标 AP 的实际行为。
来源：https://arxiv.org/abs/2302.05899

此轮主要为标准阅读和证据条件推导，未修改执行代码、未测试、未发包。下一步回到最新相关文献的全文阅读，并核对其评价方法与目标 AP 状态证据的关联。
