# WNM 字节解码与证据入口

新读 9.6.13.1 表 9-536 对应文字（1741–1742）：WNM Sleep Request/Response 为 16/17；核查元素表 925 页 WNM Sleep Mode=93。元素表本轮只抽取对应行，未视觉核对整表。Linux 官方头文件复核 Category WNM=10；该版本中未检索到 WNMSLEEP 元素常量，不以未找到作为缺失标准功能的依据。来源：https://github.com/torvalds/linux/blob/master/include/linux/ieee80211.h

基于前轮图文增加 protocol/wnm.py 明文 Action body 解码：Key Data 外层长度、TLV 边界、GTK 声明密钥长度、IGTK/BIGTK 长度和唯一睡眠元素检查。支持多个密钥子元素，未知子元素仅报告元数据。GTK RSC 小端读取，返回值不包含密钥字节或未经解释的 payload。

主模型 wnm_response_sent 支持 action_body_hex 导出字段，提供重复元数据必须一致。不修改调用者事件，不在报告保留原始 Key Data。解码不证明保护、接收接受或硬件安装。此入口需要明文 body，当前未接入受保护管理帧解密采集链路。

未实现完整 TFS/OCI 语义、Key Info 位语义和所有密码套件上下文检查；固定字段长度并不代表完整规范符合性。本轮无新漏洞论文阅读。AST 解析通过，未执行 CLI、单测或无线实验。
