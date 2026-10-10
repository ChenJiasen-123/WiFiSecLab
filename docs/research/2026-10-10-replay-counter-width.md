# 接收计数器证据复核

复核标准 12.5.2.4.4（2994 页）：接收计数器按 SA 与 TID 分域，GTK 初值来自对端，已接受帧的 PN 更新计数器；非 QoS 数据属于 TID 0。复核 12.7.2（3053、3055 页）：EAPOL-Key Replay Counter 为 8 字节，不能与数据 PN 混用。

联网复核 CCS 2018 6.4 对应文字，安装时忽略 GTK 接收初值是独立于删除历史的问题。论文历史设备结果不代表当前目标。来源：https://papers.mathyvanhoef.com/ccs2018.pdf

当前代码已有 rx_counter_configured 和 data_accepted 的同材料/域历史最高值及回退线索，因此没有重复增加 GTK 计数器状态机。本轮补上 EAPOL 计数器 64 位边界；显式标为 ccmp-128/ccmp-256 的数据事件补上 48 位 PN 边界。验证在任何状态变更之前执行。不为未知 cipher 自动套用 CCMP 上限。

尚缺：采集端提供真实计数器、稳定材料身份、SA/TID 域与 peer 初值的关联；因此还不能证明目标 AP 的初始化正确。内部状态不能由 pcap 可见 PN 替代。仅 AST 解析，未执行测试或无线实验。
