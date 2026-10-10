# BIP-CMAC 离线校验接口

## 参考阅读
完整阅读 Linux net/mac80211/wpa.c 的 bip_aad、bip_ipn_set64/swap、AES-CMAC transmit/receive、AES-GMAC transmit/receive 函数对应源码；完整读 aes_cmac.c（41 行）。这不是整个 mac80211 处理链审计，硬件标志和 key 选择来源未全面追溯。
来源：https://raw.githubusercontent.com/torvalds/linux/master/net/mac80211/wpa.c
来源：https://raw.githubusercontent.com/torvalds/linux/master/net/mac80211/aes_cmac.c
联网 API 核对 wpa.c 最新文件提交为 91a4855d6c03e770e42f17c798a36a3c46e63de2，时间 2026-04-15；本轮正文从 master 获取，不将移动引用当固定版本全树证明。

实现先比较 IPN，软件 MIC 错误时退出，成功路径才写回 rx_pn；硬件 RX_FLAG_DECRYPTED 分支依赖外部已验证契约。IPN 在传输中为低字节在先，内部比较视图反转。CMAC helper 在末尾 MIC 位置补零，并有 Beacon Timestamp 特殊处理。现有离线实现不处理 Beacon/S1G/QMF，也不模拟驱动标志。

## 平台改动
protocol/bip.py 新增 verify_group_disconnect，面向完整传统 group deauth/disassoc（reason code + 最后一个 MME），输入无 radiotap/FCS、无分片/HT Control。要求给定 BIP-CMAC-128/256、对应 16/32 字节已知密钥、发送者、Key ID 4/5。核对上下文、MME 长度/ID、MIC 长度，按标准 12.5.3.3/.6 计算 CMAC。没有密钥搜索、发包、客户端或自动 AP 状态转换。

可选 replay_floor 必须是明确的 48 位整数，只有 MIC 成功且 IPN 超过给定 floor 时给出 next_floor_candidate；函数不更新账本，floor 的接收配置来源也不自动认证。MIC 失败不产生候选更新。MIC 可独立于 floor 比较计算，输出不是对真实接收步骤的复现。共享 IGTK 的校验只证明给定组密钥下完整性，不证明唯一 AP 来源。

离线采集报告仍仅结构解析：尚未接入可信密钥获取与协商来源，不自动调用新密码学接口。完整性校验、真实 AP 接收和模型状态仍分别取证。

本轮无新增完整标准章节或论文正文；完成参考实现阅读。仅 AST 语法检查通过，未运行导入、密码学/单元/无线测试，未宣称实现已验证。
