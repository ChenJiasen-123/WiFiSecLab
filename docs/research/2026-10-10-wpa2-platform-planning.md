# 平台场景计划入口（WPA2）

2026-10-10。新增 src/wifiseclab/planning.py，并注册 wifiseclab-plan。复用 build_request/build_association，在离线计划中生成认证及关联原始帧和 SHA256，列出初始 WPA2 六阶段、依赖及所需内部事件。调用前需完整 AP profile 对象；目标身份与现有安全/速率校验不通过则不生成计划。

API：build_wpa2_plan(ssid, bssid, station, profile, session_id)。入口也可使用 python -m wifiseclab.core.planning，参数 --ssid、--bssid、--station、--session、--ap-profile、--output。ap-profile 是现有广告分析报告 targets 中选定的单个对象，不是整个报告；输出文件必须不存在，父目录需存在。session 应由上层分配唯一值，本函数只校验非空，不提供全局唯一性。

计划仅保存运行时上下文需求，M2/M4 需实际 M1/M3、关联/广告绑定、PMK 句柄与新 SNonce；数据阶段需当前 TK、nonce domain、PN、payload 及接收证据。无需重建完整网络客户端。暂未实现计划加载执行器，也未提供边界扰动场景。阶段顺序只是编排依赖，不等价实机状态判定或完整规则证明。

覆盖范围为初始 PSK/CCMP、非 PMF-required 基线；FT、SAE、重协商和缓存恢复需独立计划。所有阶段执行状态初始为 not_executed。此模块不打开 socket、不发包、不嵌入 PMK/TK；帧模板存在不证明目标支持或接收。

按用户要求，本轮未运行测试、未执行新入口或模块，新增代码未经运行验证。更新 README 与 reading-log.md。下一步把计划动作与现有收发适配器、上下文/证据边界连接，保留 no_response/环境故障/候选偏差区分。
