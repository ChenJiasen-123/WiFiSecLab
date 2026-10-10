# 加密套件绑定与 Beck–Tews 2008 阅读（2026-10-10）

来源为作者网站提供的 12 页、封面日期 2008-11-08 的预印本：https://www.datenzone.de/blog/wp-content/uploads/2016/06/Practical-attacks-against-WEP-and-WPA.pdf 。IACR 地址 https://eprint.iacr.org/2008/472.pdf 本轮正文访问返回 403，未以搜索摘要代替正文阅读；作者页面副本已读第 1–6 节主体文本及参考文献列表。它与 2009 年 WiSec 正式版本分开记录；数学公式抽取、成功率图未逐项视觉核对，引用文献本身也未全部读过，因此精读状态仍为未完成。

成因摘要：WEP 的统计密钥问题与 TKIP 的完整性、反馈及重放域问题不同；该文的 WPA 部分限定 TKIP，不是破解 CCMP，也不是完整恢复会话加密密钥。QoS 域和方向属于安全上下文，实验前提不能泛化到任意现代 AP。没有实现论文攻击或移植其历史缓解参数。

代码核查：Lifecycle 此前只检查 AKM、连接状态、PMF 和地址，未核对实际协商 cipher。现明确当前基线要求 pairwise_cipher=CCMP 且 group_cipher=CCMP；初次连接和重连均独立检查。报告增加所需套件及每次采样的实际套件、匹配结果。其他套件或缺失字段只能保持未确认，不被当作 AP 漏洞或自动降级测试。CCMP-256、GCMP、TKIP 都属于本控制器当前基线之外；未来新增配置需独立规则与证据。

验证：248 项离线测试通过；新增 pairwise/group TKIP、GCMP、字段缺失和重连时套件变化回归。重新分析已有四种模式状态采样，实际 pairwise/group 都为 CCMP，均仍为 connected；结果见 lifecycle-cipher-reanalysis.json。这不是新的无线或完整生命周期实验。

本轮未连接远程主机或发包。整体标准精读、跨年代文献覆盖及剩余协议状态实现继续推进。
