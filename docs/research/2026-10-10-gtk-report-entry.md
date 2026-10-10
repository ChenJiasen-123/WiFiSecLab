# GTK 离线报告入口与操作完成证据（2026-10-10）

继续落实已读 12.6.19。审查现有 key_evidence：请求/返回关联是关键，操作请求本身不足以证明删除。GTK 模块现在要求内部 installed/deleted 事件显式声明 operation_completed=true 并提供证据引用；这仍是对调用方证据契约的要求，不自动验证引用真实性或物理固件状态。

新增 wifiseclab-gtk 平台入口，读取单 BSS/epoch 的有序 JSON 证据并输出报告。限制 4 MiB/10000 事件，错误定位到事件编号；输出新建文件避免覆盖已有结果。pcap/probe 仍只作为观察。退出成功只表示报告生成，不表示目标通过协议检查。

输入根字段：bss_context、role（ap/non_ap）、events。每条事件包括 kind、material_id、context、source、evidence；安装/删除完成还需 operation_completed=true。材料句柄应跨槽稳定，不可填无线 Key ID 后冒充材料身份。采集器仍未接入，此入口允许人工审阅的离线插桩记录进入模块。

更新 pyproject 平台命令和目录说明。只 AST 语法检查，未执行命令、未运行平台测试、未发包。待后续检查点完整性、时间绑定与 BSS 组密钥采集器接入。
