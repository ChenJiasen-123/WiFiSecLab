# 模型约定与范围

本版为可执行的研究抽象，不是标准的逐条实现。

- wpa2 允许 PSK，wpa3 允许 SAE，transition 允许两者。
- auth_accepted 表示认证路径已准备/确认：PSK 的 Open System 认证不等于密码学身份认证。
  PSK 的凭据证明仍在四次握手；SAE 需后续补齐 Commit/Confirm 内部转换。
- handshake_* 当前为抽象事件，尚未逐帧建模 M1-M4 或计时器。
- peer 区分客户端，session 区分会话，key_id 标识稳定密钥材料而非每次安装。
- nonce_domain 必须按具体算法包含完整唯一性域，如发送者及必要的优先级信息。
- encrypt_new 是新加密操作，link_retry 是已有密文重传。不能凭重复 PN 自动判漏洞。
- pcap/probe 只保留外部观测，不直接断言 AP 接受或更新内部状态。
- 断开事件不自动清空密钥和授权，需单独观察清理事件。
- cleanup_checkpoint 在适配器定义的恢复期限后执行。本版测试配置要求清空 peer 临时上下文；
  PMKSA、漫游、休眠保留策略尚未建模，不能套用同一断言。
- 候选性质违反不等于漏洞，需要原始证据、独立复跑、根因分析。

## 文献依据

KRACK (CCS 2017)：派生、安装、使用及计数器的分离。
Cremers et al. (USENIX Security 2020)：组合状态、队列和显式假设。
Dragonblood (IEEE S&P 2020)：SAE 边界输入和协商；侧信道另需测量模型。
Fragile Frames (WiSec 2025)：前置条件、解析路径与检测限制。
Bellardo/Savage (USENIX Security 2003)：符合性差异不等于安全漏洞。
Easy Connect (IJIS 2025)：角色和凭据生命周期，DPP 独立扩展。

下一阶段建立规则—标准版本—条款—实验的映射；当前没有完整标准符合性保证。

新增细粒度事件、组合状态和判定范围见 [state-machine.md](state-machine.md)。handshake_* 不再仅有粗粒度路径：提供 exchange_id 时可检查 M1-M4；不提供时报告 abstractions_used 标记观测不足。
