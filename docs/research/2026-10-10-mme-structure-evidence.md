# MME 格式及离线观察

精读 IEEE 802.11-2024 9.4.2.53 全部对应文字（1121–1122）；核对表 9-130 印刷页 924 的 MME ID 76。图 9-454 仅提取文本。视觉核对 2997–2998 的图 12-23、24、25、26；图 12-27 及 S1G 公式仍未视觉核对，不扩展实现。

MME 字段：ID/Length、2 字节 Key ID、6 字节 IPN/BIPN、8 或 16 字节 MIC。Key ID 4/5 对应 IGTK，6/7 对应 BIGTK，其余及高保留位不支持。CMAC-128 MIC 为 8 字节，其他三种为 16；长度不能确定 16 字节 MIC 的具体 cipher。完整 IE 为 18/26 字节。MME 最后出现且 FCS 在其外。

新增 protocol/bip.py decode_mme 精确 IE 结构解码，不输出 MIC 或密钥，不提供密码学验证；可选 cipher 必须来自独立协商上下文，并核对 MIC 长度。返回 integrity_valid=None、replay_validation=unknown、receiver_acceptance_confirmed=false。

eapol 离线报告接入来自目标 AP 的组地址 deauth/disassoc 观察，仅支持 reason code + 单个最终 MME 的结构，不扫描魔数或把任意尾字节猜成 MME。BIGTK 用于此类帧时保持不可用；缺失/畸形/额外元素统记 unavailable_or_outside_profile，不判 AP 违规。Protected 位为 0 不排除 BIP，故独立于前轮 Protected 头记录。组接收成员与真实接收效果未验证；单播解密、QMF、Beacon/BCE 验证及插桩账本仍待实现。

依据漏洞思路：此前阅读 WiSec 2022 4.2.2 的 IPN 安装问题要求区分格式可读、MIC 成立与配置初值/接收效果。本轮无新增论文正文阅读，不把该结构入口当漏洞复现。
来源：https://papers.mathyvanhoef.com/wisec2022.pdf

验证仅两文件 AST 语法检查通过；未运行导入、功能测试、密码学验证或无线实验。
