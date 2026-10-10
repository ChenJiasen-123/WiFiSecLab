# 生命周期采样解析约束（2026-10-10）

生命周期控制器原先通过 dict 覆盖同名状态字段，并通过子串判断 AP flags。已改为拒绝重复字段（即使重复值相同），拒绝空字段名及非文本输入；AP flags 必须完整符合方括号标记语法、存在唯一 flags 字段并匹配目标 STA。缺失 flags 不能当作已断开。连接确认同时要求 AUTH、ASSOC、AUTHORIZED，SAE 仍要求原有 MFP/PMF 条件。

无效采样不会推动连接或断开阶段；timeline 新增 sta_response_valid 与 ap_response_valid，表示响应格式可用性，不代表跨进程原子采样或身份认证。后续有效采样仍可正常推动阶段。超时依旧是未在预算内确认状态变化，不构成漏洞结论。

验证：243 项离线测试通过。新增重复 STA 状态、重复/畸形/缺失 AP flags、缺失 AUTH 标记用例。用新代码复核已有 hwsim-live-verification/evidence 中四种模式的控制状态：WPA2、WPA3、transition-psk、transition-sae 都达到 connected。结果另存 lifecycle-parser-reanalysis.json。仅复核历史连接采样，未证明完整断开重连周期；report 中 passed 保持 false，因为本次没有到达 DONE。

来源交叉核对：https://w1.fi/wpa_supplicant/devel/ctrl_iface_page.html 。已阅读 STATUS/STATUS-VERBOSE 格式说明和控制接口事件交错说明。接口状态是守护进程采样，事件可能插入命令交互；严格文本解析不能替代请求关联、进程健康、采样时间或 AP/STA 身份绑定。本次不增加并发命令，也不改变无线流程。

本轮没有远程连接或发包。仍需继续核对完整生命周期采集器的进程/时间绑定，以及标准状态机、跨年代文献和 SAE/FT/PMF/重键等覆盖。
