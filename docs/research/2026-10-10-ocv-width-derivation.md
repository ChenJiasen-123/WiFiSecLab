# OCV 对端宽度推导：调用链阅读完成范围

版本仍固定为 Android wpa_supplicant_8 提交 a2c18b71be606afcfc8ff81bb1e7371e7edd193f，不代表最新版。

本轮完整阅读 wpa_auth.c 的 get_sta_tx_parameters、wpa_auth_glue.c 的 hostapd_get_sta_tx_params 及回调注册项、ieee802_11_shared.c 的 get_tx_parameters。结合前轮已读调用分支，补齐 EAPOL M2 / 组 M2 的这段参数来源链。邻近返回文字不计完整精读。

来源：

- https://android.googlesource.com/platform/external/wpa_supplicant_8/+/a2c18b71be606afcfc8ff81bb1e7371e7edd193f/src/ap/wpa_auth.c
- https://android.googlesource.com/platform/external/wpa_supplicant_8/+/a2c18b71be606afcfc8ff81bb1e7371e7edd193f/src/ap/wpa_auth_glue.c
- https://android.googlesource.com/platform/external/wpa_supplicant_8/+/a2c18b71be606afcfc8ff81bb1e7371e7edd193f/src/ap/ieee802_11_shared.c

## 已核实行为

外层函数转发回调；glue 按地址取得 STA 对象，无对象则失败。共享函数优先依据已保存的 VHT Operation 推导宽度，否则依据 VHT Capabilities，再否则依据 HT 40 MHz 能力；结果与 AP 最大宽度取较小值。第二段是否保留也受对端 80+80 推导结果影响。代码含 Extended NSS BW Support 尚未纳入的 TODO；本轮不将它宣布为安全漏洞。

因此这些参数属于实现依据保存能力/运行元素推导的结果，并非逐包测量。前轮“面向对端参数”不能理解为所有字段都已获得实际无线行为验证。未审计保存这些元素的完整来源和完整性链，不宣称其已认证，也不能据此断言存在可利用漏洞。

## 平台契约的修正与下一步

标准 12.2.10 的比较对象是对该 peer 使用的参数。平台输入必须说明来源：驱动当前接口状态、由 peer 上下文推导的使用上限、包级观测三者证据意义不同。推导上限可以用于研究比较，但不得在报告中默认为已观测实际最大宽度；任意设备能力或 Beacon 宣告也不能直接充当该参数。

现有 max_width_mhz 数字与 link_channel_evidence 字符串不足以验证推导依据、peer/session 绑定及时间一致性。下一步应把上述来源与绑定接入现有事件契约，而非复制旧 hostap 推导函数作为通用标准实现。现有 consistent 只表示给定参数相符，不能证明 OCV 已执行或 AP 进入正确状态。

本轮尝试在本地标准印刷页 1220–1264 定位 VHT Operation 条款，未找到指定标题；不计这些页已精读。未新增完整标准章节或论文，未运行测试，也未修改无线执行代码。
