# 生命周期目标身份绑定（2026-10-10）

Lifecycle 构造现在必须显式提供 bssid 和 station 两个关键字参数；校验其为不同、非零单播 MAC，并统一大小写。连接/重连确认须匹配调用目标 peer、AP 控制查询中的 STA、STA 状态中的 address 和 bssid，再应用既有 COMPLETED、AKM、AUTH/ASSOC/AUTHORIZED 及 SAE 的 PMF 约束。报告保存目标身份及每次采样的匹配布尔值。

断开状态通常没有当前 BSSID，因此只要求目标 peer 和 STA 自身 address 匹配，并满足既有 DISCONNECTED 和 AP 已移除/不再关联授权条件。地址缺失、其他 STA 的断开状态不能确认目标已断开。这里没有把 BSSID 缺失等同 AP 异常。

隔离实验工具 tools/hwsim/hwsim_lifecycle.py 已更新：从 AP/STA 各自命名空间中读取对应接口地址并传入控制器。所有项目内 Lifecycle 调用者已更新；外部调用者需要补齐这两个参数。此变更未增加发包功能。

验证：246 项离线测试通过；新增错 BSSID、错 STA、缺失身份、非法目标和错 STA 断开状态回归，既有完整模拟生命周期仍通过。使用原实验 AP 快照元数据提供目标身份，而不是从待判断 STA 状态反推目标，重新核对已有四种模式的连接采样，均为 connected。结果见 lifecycle-identity-reanalysis.json；它们不是本轮完整断开重连实验，passed 仍为 false。工具源文件已通过 Python 语法解析，本轮未在 Linux 上重新运行它。

交叉参考 https://w1.fi/wpa_supplicant/devel/ctrl_iface_page.html 的 STATUS 字段格式。地址匹配只绑定采样中的声明身份，不能认证采集器或证明密钥拥有者身份；AP 控制接口来源、进程健康、时间一致性与跨会话隔离仍需要独立证据。

本轮没有连接远程机器、操作实体网卡或发包。完整标准、文献研究与其余协议状态覆盖继续进行。
