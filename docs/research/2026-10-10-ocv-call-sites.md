# OCV 调用点与派生证据来源

固定源码版本：Android wpa_supplicant_8，a2c18b71be606afcfc8ff81bb1e7371e7edd193f。通过官方 format=TEXT 接口阅读，不代表最新版。

本轮完整阅读 driver.h 的 wpa_channel_info 结构与字段说明、driver_nl80211.c 的 get_channel_info / nl80211_channel_info 两个函数；阅读 wnm_ap.c 中 WNM Sleep 请求 OCI 验证分支、wpa_auth.c 中 EAPOL M2 与组握手 M2 的 OCI 验证分支。周围其他函数不计完整阅读。

https://android.googlesource.com/platform/external/wpa_supplicant_8/+/a2c18b71be606afcfc8ff81bb1e7371e7edd193f/src/drivers/driver.h

https://android.googlesource.com/platform/external/wpa_supplicant_8/+/a2c18b71be606afcfc8ff81bb1e7371e7edd193f/src/drivers/driver_nl80211.c

https://android.googlesource.com/platform/external/wpa_supplicant_8/+/a2c18b71be606afcfc8ff81bb1e7371e7edd193f/src/ap/wnm_ap.c

https://android.googlesource.com/platform/external/wpa_supplicant_8/+/a2c18b71be606afcfc8ff81bb1e7371e7edd193f/src/ap/wpa_auth.c

接口查询采用 GET_INTERFACE，缺失宽度初始化为 UNKNOWN；频率、宽度、次信道方向和中心频率分别来自不同属性。单一返回成功不能替代逐字段完整性检查。

EAPOL M2 / 组 M2 分支调用 get_sta_tx_parameters 后再验证；WNM 退出请求分支直接使用接口宽度及 seg1_idx。尚未定位并读完 get_sta_tx_parameters 实现，不推断其参数怎样协商，也不将两个路径等同。前轮“需要面向对端参数”的输入要求仍适用于平台，不能据此声称参考实现的所有路径都已提供相同绑定。

本轮主模型审查发现，调用方可直接提供 decoded_oci 或 oci_channel_comparison，随后被记录为响应报告字段。这会混淆外部声明和内部计算来源。现将两字段保留为内部派生字段，输入出现即拒绝；有 action_body_hex 时仍由实际解码和比较产生。旧输入若手工设置这些字段，需改用明文 body 和链路快照。这个改动保证字段来源，不保证快照真实、MIC 正确或目标接受。

仅 AST 语法检查，未测试。未新增完整已读标准章节或漏洞论文，未访问目标 AP。
