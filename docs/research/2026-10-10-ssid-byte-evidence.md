# SSID 原始字节证据与广播冲突

精读 IEEE 802.11-2024 9.4.2.2 对应全文，印刷页 934（PDF 第 935 页）。图 9-209 仅文本，未视觉核对。SSID 为 0–32 octets；UTF-8 能力条件不成立时字符编码未指定。零长度解释依帧及运行模式而异，当前不将空值自动裁决为隐藏网络或错误。

联网复核 SSID Confusion（WiSec 2024）6 节对应文字，重点是视觉相同名称与真实网络身份的区别；没有新增整篇精读。
来源：https://papers.mathyvanhoef.com/wisec2024.pdf

源码审计发现 advertisements 原先仅用 RSNE 作为字典键，同 RSNE 不同 SSID 会覆盖。改为 (RSNE, SSID 原始字节 hex) 联合键，并继续在存在多个候选时保持上下文不可用。解析失败的候选仍保留 rsne_hex=None，不回退到早先有效记录。

Beacon/Probe Response 及关联请求保存 ssid_hex、帧 subtype、packet_index、timestamp、source_authenticated=false。关联证据随观察边界清理并进入握手 attempt。相同 RSNE/SSID 的重复广播仍保留最近一条；没有做完整帧历史、BIGTK 验证、SSID protection 协商或目标身份裁决。管理帧来源地址匹配不等于来源认证。

新增 SSID 缺失或超过 32 字节的上下文拒绝，不裁决 AP 违规。没有文本解码/归一化，避免丢失末尾零、不可见字符或未指定编码的差异。网络身份状态仍 unknown。

仅 AST 语法检查通过，未执行导入、功能测试或无线操作。
