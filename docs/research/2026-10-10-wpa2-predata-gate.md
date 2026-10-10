# WPA2 主链路：数据前 AP 状态门槛

2026-10-10，用户确认近期优先 WPA2 认证/关联/握手/数据/清理及其边界。完整平台与文献阅读目标保留，WPA3 实现暂后置。

新增 predata_snapshot.collect_predata_snapshot：调用控制查询，按当前已验证握手、双方身份、快照字节哈希、同主机时间和 AUTH/ASSOC/AUTHORIZED 标志关联，有限等待；缺授权、错误身份或窗口不匹配不能通过。每次查询前后检查运行健康，过期停止，不以发送 M4 等价于 AP 已授权。

已接入 tools/hwsim/hwsim_custom_client.py：验证握手后、构造用户数据前采集并保存 ap-predata-stations.txt 和 ap-predata-snapshot-metadata.json。hwsim_custom_smoke.py 提供 AP namespace/interface/control 路径，控制命令使用参数数组且有超时。原数据后的 ap-stations.txt 保留为后置采样，不能回填为前置采样。

前置元数据当前绑定采样时仍增长的捕获文件哈希；不能作为最终文件哈希。正式分析器还需要冻结捕获后的哈希绑定、统一文件名、客户端/服务端标准端点记录及数据元数据。此改动只完成前置采样门槛，不声称正式报告或全链路已完成。样本不证明连续授权或固件密钥安装，快照后状态仍可能变化，后续捕获关联需再检查。

4 项针对测试通过：授权样本、缺授权超时、错误终端超时、采集进程故障。相关三文件语法检查通过。未执行 Linux namespace/hwsim 环境测试、未发包、未全套复测；跨 namespace 控制命令的实际运行待验证。

另补记上一轮已读印刷页 3031–3033：3031 密钥配置/启用与同 Key ID 缓存分片丢弃；3032–3033 12.6.16 终止及 PN 耗尽；3033 12.6.17 当前页 PMF。其他 IBSS/MBSS/PBSS 段仅浏览，不登记精读。ESS AP 删除终端 PTKSA 与终端删除多类 SA 的责任不同；不能要求 AP 因一个终端断开删除全局 GTK。密钥保护启用竞态不一定要求去认证；PN 耗尽的 PTKSA 与 GTKSA/IGTKSA 处理不同。分片缓存、PN 耗尽等尚未实现规则。
