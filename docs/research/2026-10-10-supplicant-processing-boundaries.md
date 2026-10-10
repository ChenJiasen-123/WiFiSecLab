# Supplicant 处理过程与 AP 判定证据边界

2026-10-10。精读 IEEE 802.11-2024 12.7.9.4，印刷页 3087–3089（PDF 页面 3088–3090），包括跨页结束部分；12.7.10.1 仅读开头，未读完 Authenticator 状态机。图 12-53 尚未视觉核验。

## 标准要求及适用范围

过程区分 UNKNOWN、MICOK、FAILED；不能把 MIC 位被设置解释为 MIC 验证成功。临时 TPTK 用于避免收到初始消息就改变当前 PTK。无效 EAPOL-Key，包括无效 MIC、没有 MIC 的 GTK，应忽略。响应的 Key Replay Counter 使用收到的对应请求计数值。这些字段级规则仍需结合 12.7.6 中上下文、身份、ANonce、RSNE 和重放检查，不能只复制伪代码的局部分支。

M3 中存在的 GTK、IGTK、BIGTK、WIGTK涉及解密及安装，PTK 必须先于 GTK/IGTK 安装。各安装调用失败的分支要求发起去认证；空中未见回应不能证明失败分支已执行。伪代码中 PTKSAEstablished、保护配置与 portValid 分别赋值，不能视为一个原子完成事件。IBSS 的 keycount 条件不同于基础设施 BSS，不可把两者混用。

此处是 Supplicant 规则。AP 是基础设施 BSS 中的 Authenticator，平台可以利用规则理解自己提供给 AP 的输入，但不能直接拿 Supplicant 的安装顺序判 AP 违规。还需要精读 12.7.10 并核对实际证据源。

## 论文对应与阅读边界

重新核对 Cremers、Kiesl、Medinger 的 USENIX Security 2020 作者模型说明：https://people.cispa.io/cas.cremers/tools/tamarin/WPA2/index.html 。模型把四次、组密钥、WNM sleep 与加密层放在一起，并区分修补版和未修补版。启发是对同一密钥材料的安装及计数器副作用跨机制跟踪，不能只看握手消息序号。此次阅读的是作者 artifact 说明页，未重跑证明、未新增完整论文阅读完成声明；既有论文精读范围仍以此前日志为准。2020 年模型不是 2024 标准所有新增路径的证明。

## 对当前平台的审查结论

core/model.py 的 key_installed、port_authorized 和握手完成保持分离；密钥历史跨槽、删除及会话保留，符合需要跨机制关注安装副作用的方向。stage_evidence 的事件覆盖只能表示拿到了某类事件，不能表示 MIC、安装返回值或端口状态已确认。protocol/wpa2_session.py 是有界响应组件，不负责安装，不能根据它成功构造 M4 推断 AP 进入授权状态。

后续 AP 判定必须由内部安装结果、端口快照和实际受保护数据路径分别提供证据。抓包中的无效消息与内部状态变更需要身份、会话及时间关联；仅无响应记为观察不足。当前轮不依据 Supplicant 条款新增 AP 强制规则，避免角色误套；继续阅读 12.7.10。

本轮完成标准跨页过程阅读和论文模型范围核对；未运行测试、未扩展客户端、未发包。
