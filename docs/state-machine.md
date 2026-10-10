# 状态机结构与使用

本项目包含两层：model.py 检查插桩/合成事件的安全上下文，lifecycle.py 验证真实 hostapd/wpa_supplicant 的连接生命周期。两层证据不能混用：抓包看到帧不等于实现接受帧，控制器 session 编号不证明 AP 内部会话隔离。

## 组合状态

每个客户端独立维护认证、AKM、关联、PMF、握手、授权端口、密钥槽、待处理任务、定时器、SAE 阶段、握手交换 ID、消息阶段及清理待办。snapshot() 将这些维度全部纳入转换覆盖率。session ID 按客户端唯一；发送 nonce 与接收 PN 账本跨会话保留。

## 事件路径

WPA2 PSK：session_start → auth_accepted(akm=psk) → assoc_accepted → handshake_started → key_installed → handshake_completed → port_authorized。Open System 认证不能证明掌握 PSK。

WPA3 SAE：session_start → sae_commit_accepted(exchange_id) → sae_confirm_accepted(同一 exchange_id) → assoc_accepted(pmf=true) → 四次握手 → 授权。粗粒度 auth_accepted(akm=sae) 仍可表示插桩直接确认的认证结果，不意味着本模型观察过 Commit/Confirm。混合模式分别使用两条路径；关联期间禁止更换 AKM。

细粒度四次握手：handshake_started(exchange_id) 后依次提交 handshake_message，字段为 exchange_id、message(1..4)、replay_counter(非负整数)。事件语义是 AP 发送 M1/M3 或通过内部校验接受 M2/M4；不是原始帧到达。M2/M4 回应当前计数，M3 计数递增。同阶段相同计数重传不推进阶段；独立 key_installed 事件用于发现计数器重置。提供 exchange_id 后必须达到 M4 才能完成；未提供时保留旧的粗粒度抽象。

rekey_started 开始新四次握手，并保留旧密钥和授权供已有连接使用。handshake_failed/handshake_timeout 标记失败及清理待办，不自动删除密钥。认证失败使用 auth_failed。

断开：disassociated/deauthenticated → port_revoked、key_deleted、work_cleared、timer_cancelled/expired → cleanup_checkpoint。断开事件不会代替实现清理。deauthenticated 另外清除认证路径。检查点要求客户端未关联且临时上下文为空，才清除 cleanup_required。重新关联前仍有待办会报告候选异常。

任务以 work_id 区分；定时器使用 timer_id。timer_started 注册，timer_cancelled 取消，timer_expired 消耗一次超时；无注册的超时会报告异常。定时器到期本身不自动推断握手失败，应另有实现事件证明。

management_accepted(subtype=deauth/disassoc, protected, integrity_valid) 检查 PMF 关联中的稳健管理帧接受行为，不自动假定客户端已断开。data_accepted(key_id, nonce_domain, pn) 检查授权、密钥归属与接收重放。nonce_domain 必须由适配器按算法、发送者及重放域正确构造；不能把聚合重排前的原始帧直接输入此事件。

## 判定与边界

这是实现行为监视器：对有证据的异常接受可记录 finding 后继续记录实际状态，并非永远拒绝非法转换的理想 AP 模拟器。会话错误、AKM 切换等不能可靠归属的事件不更新目标上下文。finding 是候选性质违反，需独立复现和根因分析。

目前覆盖 WPA2-Personal、WPA3-Personal 与混合模式的关联安全生命周期，不是全部 IEEE 802.11 的标准符合性实现。SAE 密码学、anti-clogging、H2E/群组协商、PMKSA 缓存、802.1X/EAP、组密钥握手、SA Query、FT 漫游、DPP、节能/聚合重排及 MLO 仍需独立子状态机。这里不声称完成这些路径；标准版本与条款映射亦待建立。cleanup_checkpoint 只适用于当前要求清空临时 peer 上下文的实验策略，不能直接套用于允许缓存或漫游保留的配置。

关键代码均有中文注释：model.py 的输入校验、组合状态、断开清理、细粒度握手、重协商与跨会话账本；key_evidence.py 的调用返回配对；lifecycle.py 的客户端身份核对。
