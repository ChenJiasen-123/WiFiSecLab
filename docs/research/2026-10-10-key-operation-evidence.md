# 密钥请求与 MAC 实际效果

## 标准
复核 IEEE 802.11-2024 6.5.14.1.4（567 页）及 6.5.15.1（568 页）。SetKeys/ DeleteKeys 定义 request 与接收效果；本段未定义独立 confirm 原语。平台完成标记是采集证据契约，不是额外的协议消息。相同材料安装还涉及保持计数器、组密钥 RSC 仅增加等规则，不能将操作请求次数当作实际重新安装次数。

## 文献
复核 CCS 2018 Release the Kraken 6.3.2 对应文字，跨安装路径关联仍重要；历史研究不能证明当前目标存在漏洞。来源：https://papers.mathyvanhoef.com/ccs2018.pdf

## 代码
检索 src 与 tools，未发现主模型之外生产 key_installed/key_deleted 的适配器。APModel 新增 key_install_requested/key_delete_requested，单独保存 observation，不变更密钥槽位和状态覆盖。instrumentation 的 key_installed/key_deleted 必须明确 operation_completed=true，evidence 指向实际 MAC 效果证据。显式不完成的 synthetic 事件拒绝；原 synthetic 场景保持事件名表示抽象完成的语义，不作为实测证据。pcap/probe 仍只观察，不推断完成。key_installed 的材料/槽位格式校验前移至状态修改之前。

## 兼容与缺口
旧 instrumentation 输入缺少完成标记会拒绝，需要生产者升级；不能凭布尔值证明硬件真的完成，仍需审核证据引用。未要求所有删除都有请求记录，因输入窗口可能遗漏请求；不制造确认消息。尚缺命令关联 ID、驱动/固件采集和证据内容验证。

只做 AST 语法检查，未运行 CLI、平台测试或无线实验。
