# 受保护管理帧头观察

继续以前轮标准 9.6.9、11.13 和 PMF 上下文为依据。联网定位并阅读 WiSec 2022 4.2.2 全部对应文字：组管理帧重放判定关联 IGTK 安装时 IPN 初值，不能凭 Protected 位或捕获重复直接证明接收方重放失效。其历史 Android/Windows 测试结果不代表当前实现。其余检索邻近文字不计新完整章节。
来源：https://papers.mathyvanhoef.com/wisec2022.pdf

新增 network.hotspot.management_header：仅解析可见传统管理帧头，保留原有不支持分片/HT Control 的范围，允许记录 Protected 位；不返回 body、不认证来源、integrity_valid=None。原 plaintext management 不放宽，密文不会流入已有 Action/body 解析。

离线 eapol 分析接入同 AP/STA 或 AP 广播范围内 Protected 位为 1 的解除认证/关联和 Action 头观察，输出包序号、时间、地址、序号、Retry、帧 hash。Action 类别/事务/OCI 不从密文推断。解除认证/关联头出现时，标记旧观察路径 ambiguous 并建立不确认重置的边界，避免跨潜在会话拼接；不声称 AP 执行了断开。伪造头也可使结论变得不可判定，这不是 AP 漏洞证明。

该入口只覆盖 Protected 位为 1 的头部观察，不是全部 PMF/BIP 保护检测器：组地址 BIP 需独立 MMIE、IGTK、IPN 与完整性处理，不能用此布尔字段代替。没有新增解密、SA Query 请求构造或客户端。

仅两文件 AST 检查通过；未执行功能、导入、无线或远端测试。后续仍须认证解封装及与 AP 内部证据关联。
