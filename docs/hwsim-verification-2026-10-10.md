# Kali hwsim 验证与快照时间边界修复

本轮在用户指定 Kali 机器的独立 mac80211_hwsim 网卡和网络命名空间运行正常连接。没有使用实体无线网卡发送测试帧。

四个配置均成功：WPA2、WPA3、transition-psk、transition-sae。抓包、hostapd 控制快照及同主机时间和 SHA-256 元数据保存在 hwsim-live-verification/evidence。

实际证据暴露了 control_snapshot 的时间范围错误：M4 后任何上下文边界都会否定快照，即使该边界来自快照完成后的正常清理。现在 eapol 边界事件保留抓包时间，control_snapshot 只允许明确晚于查询结束且不早于 M4 的边界不影响此前快照；未知时间、非有限时间、倒退时间及查询结束之前/恰好结束的边界仍拒绝关联。

修复后 WPA2 与 transition-psk 均验证 RSNE 绑定的 MIC 四报文路径，并关联 AUTH/ASSOC/AUTHORIZED 快照。其结论是查询期间采样到 hostapd 授权状态；不证明固件密钥安装或数据可达。SAE 两个配置仅确认标准 supplicant 正常连接，没有声称已实现 SAE 密码学分析。

191 项测试通过。运行后确认 hwsim 模块不再加载、实验命名空间为空，两个实体接口仍是 managed 模式。

剩余：自定义 M2/M4 Linux 实时链路验证、数据面证据、密钥状态证据、更多协议与漏洞文献精读及边界测试。总目标未完成。
