# 模块分层说明

本目录中的代码按功能分为以下层次：

## 1. 核心状态机

- model.py：APModel 与 Event、Peer、Finding 的核心逻辑
- session.py：会话与关联上下文基础结构
- stage_evidence.py：阶段证据计算
- planning.py：离线规划与阶段结构生成

## 2. 协议与握手

- eapol.py：EAPOL 分析与 handshake trace 处理
- wpa2.py：WPA2 密钥推导、MIC、unwrap 与 key data 逻辑
- wpa2_session.py：WPA2 会话状态推进
- handshake_handoff.py：握手切换和时钟/时间边界处理
- handshake_runner.py：握手执行器入口
- radio_handshake.py：无线链路下的握手行为

## 3. 认证与关联

- authentication.py：认证观察与认证边界
- association_gate.py：关联门控与接受判定
- hotspot.py：热点构造、探测与认证-关联抽象
- hotspot_cli.py：热点入口
- wpa2_cli.py：WPA2 CLI
- cli.py：通用离线状态检查入口

## 4. 生命周期与证据

- lifecycle.py：系统生命周期状态检查
- key_evidence.py：key install/delete/residue 的证据分析
- keydata.py：key 数据解析
- control_snapshot.py：控制面快照绑定
- predata_snapshot.py：数据前快照分析
- data_evidence.py：数据阶段证据
- data_session.py：数据会话状态机
- encrypted_evidence.py：加密数据证据校验
- udp_evidence.py：UDP 层证据
- pn_observer.py：PN / replay 观察
- lab_datagram.py：实验数据报文观察

## 5. 物理与实验环境

- physical.py：物理网卡角色与收发状态
- radio_roles.py：无线角色和分工
- capture.py：抓包抽象
- capture_stream.py：数据流与帧 stream 分析
- kernel_trace.py：内核事件与 trace 解析
- hostapd_log.py：hostapd 日志事件解析
- network_guard.py：网络状态守护与边界
- runtime_guard.py：运行时约束检查

## 6. 重要说明

这些模块不是按“功能包”完全隔离实现，而是围绕同一条主线组织：

- 跟踪事件
- 验证状态
- 检查上下文
- 识别异常转换
- 输出 evidence-based findings

因此，当阅读这个目录时，应该以 model.py 和 lifecycle.py 为主线，再结合 EAPOL / hwsim / network 模块扩展细节。
