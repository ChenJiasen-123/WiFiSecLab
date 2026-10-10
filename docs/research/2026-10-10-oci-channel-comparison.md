# OCI 与链路快照比较

依据已读 12.2.10、9.4.2.235、Table E-4 及 OCV 2018 4 节，增加 protocol/ocv.py。实现是从已核对行推导的初版，尚未经测试，不把实现存在当作规范符合性证明。

主频率按对应 global class 起始频率与信道计算，宽带中心索引展开为主 20 MHz 候选，检查最大宽度关系、40 MHz 次信道方向和 80+80 第二段。未知 PHY/类别/链路参数与 OCT 独立信道缺失返回 unknown；已知冲突返回 inconsistent。class 81 要求显式 OFDM profile，82 暂不支持，避免把 spacing=25 无依据等同 PHY 带宽。

接入 WNM 主模型报告：明文 body 加 link_channel 和证据引用产生条件比较。consistent 仅指输入快照与 OCI 的这些字段一致，不证明快照可信/新鲜、OCV 已启用、消息经过保护或目标接受。没有自动变成 candidate_violation；后续必须结合消息方向与接受证据裁决。

本轮检查当前参考数据。尝试读取作者原型 ocv.c 失败（cache miss），未计为已读；不据此声称核对过实现。没有新增标准已读页或论文全文数。当前不支持所有全球类别、DSSS/LC/320 MHz/OCT 完整验证；需要继续读 PHY 与对应扩展。仅 AST 解析，未运行测试、CLI 或无线实验。
