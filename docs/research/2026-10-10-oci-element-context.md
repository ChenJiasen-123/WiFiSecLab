# OCI 结构与附录 E 映射依据

新读 9.4.2.235 全段（1427），视觉核对图 9-879；核查 931 页 OCI 的 Element ID=255/Extension=54。附录 E.1 5648 页及 5649 页开头对应正文已读，视觉核对 5658 页 Table E-4 对应行。批量抽取 5648–5664 输出发生截断，不计这些页已全部精读。

OCI 基本三字段与 OCT 额外三字段必须完整出现。operating class 对应最宽当前使用带宽；Primary Channel 可能是中心频率索引对应的主 20 MHz 子信道。表中 channel spacing 不宜不加解释直接当所有 PHY 的数据带宽，例如 81/82 显示 25 MHz，不能据此草率写 CCMP/WPA2 的 20 MHz OCV 判断。国家表和 global 表也不同。

实现 decode_oci_element：严格验证完整 6/9 字节 IE 及编号，输出普通/OCT 两组信道字段；WNM 解码接入唯一 OCI，重复或截断拒绝；主模型历史报告保留已解码 OCI 元数据。channel_validation 保持 unknown，不自动认可信道一致、能力协商或消息保护。没有输出密钥材料。

仍需 Annex E 剩余行、相关 PHY 宽度定义、12.2.10 联合比较、OCV 启用条件与可信运行参数采集。本轮无新增漏洞论文阅读，未运行测试或无线实验；只做 AST 检查。
