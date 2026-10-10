# Network and radio layer 
 
- hotspot.py: hotspot creation and probe/auth frames 
- physical.py: radio capture and frame matching 
- capture.py: radiotap decode 
- radio_roles.py: AP / client / monitor role logic 
- runtime_guard.py: runtime safety constraints 
 
This package contains the external observation and radio-level tooling that feeds the model.

CCMP baseline AAD construction is shared by lab encapsulation and offline verification in ccmp.py (IEEE 802.11-2024 12.5.2.3.3). Only exact PV0 three-address unfragmented non-aggregated data headers are supported; this helper does not establish negotiated security context.

elements() 是基础字段首值视图：遍历未知 ID，但不能完整表达同 ID 的重复 Vendor Specific/Extension 元素；关键身份及安全元素重复时本地拒绝，不据此裁决目标违规。未来扩展支持必须保留顺序、扩展 ID 和重复实例。

management_header/握手头观察仅保留传统、未分片、无 HT Control 的 Protected 位及可见头；不验证 MIC、不解码密文 Action、不证明接收效果，不覆盖完整组地址 BIP/MMIE。Protected 断开头使观察路径不确定并建立未确认重置的边界。
