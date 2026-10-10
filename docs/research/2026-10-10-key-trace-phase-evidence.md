# cfg80211 阶段边界与证据级别

## 依据与现状核查
检查 core/adapters.py 与 lifecycle/key_evidence.py。后者已有同 PID、同 phy 请求/返回匹配；此前提到的缺口应精确限定为 mac80211 drv_set_key/drv_return_int 未解析，不能说所有内核事件都未关联。
联网阅读 Linux 官方 net/wireless/trace.h 的 rdev_return_int 与 key_handle/rdev_add_key 定义：返回事件提供 phy 和 ret，不带密钥材料或请求唯一标识。因此匹配依赖采集完整性及调用序列，不等于硬件状态证明。来源：https://github.com/torvalds/linux/blob/master/net/wireless/trace.h

标准 SetKeys/DeleteKeys 的 MAC 接收效果与接口返回是不同证据层级；沿用此前 6.5.14–6.5.15 阅读，不新增已读页数。

## 改动
重复 connect/disconnect/reconnect 标记不再覆盖前一位置，而置为歧义。阶段必须完整且按 connect < disconnect < reconnect 排列，否则各阶段结果为 unknown_phase_boundaries。缺失/丢失 trace 统计仍优先使结论成为 unknown_trace_loss。报告增加阶段标记、边界有效性及 cfg80211_call_return 证据级别，明确 operation_completed=false、ap_state_conformance_confirmed=false；不自动生成主模型 key_installed/key_deleted。

## 仍缺
采集窗口完整性、真实调用层级、目标接口与 link_id 的选择、稳定材料身份、固件效果和跨 CPU 时间顺序。当前阶段解析是单次串行连接流程，不能用于任意并发会话。没有测试执行、CLI 执行或远端操作；仅 AST 检查。
