# 四次握手离线分析

入口：项目目录运行 `python3 tools/protocol/eapol.py`；安装后为 `wifiseclab-eapol`。不发包，不连接 AP。

```bash
python3 tools/protocol/eapol.py --pcap reports/example/air.pcap --bssid 12:34:56:78:9a:bc --station 02:11:22:33:44:55 --output reports/eapol-check-001.json
# 可选：使用实验环境已经知道的单个 PMK 验证 MIC
python3 tools/protocol/eapol.py --pcap reports/example/air.pcap --bssid 12:34:56:78:9a:bc --station 02:11:22:33:44:55 --pmk-file /secure/lab-pmk.bin
```

PMK 文件须为 32 个原始字节。程序不接受密码候选列表，不尝试猜测密码，也不把 PMK/KCK 输出到报告。输出文件必须不存在；父目录由调用者创建。退出码 0 只表示分析完成，具体结论在 JSON 中；输入或读写失败为 argparse 退出码 2。

可选同时提供 `--ap-station-file ap-stations.txt --snapshot-metadata ap-snapshot-metadata.json`，把控制快照作为独立证据附加到 `ap_control_snapshot`。元数据须来自可信采集器，包含 source=hostapd_ctrl、clock=pcap-realtime-same-host、bssid、station、started_at、finished_at、snapshot_sha256、pcap_sha256。关联要求最终无歧义 MIC 握手、M4 后短窗口与身份/摘要均匹配；AUTHORIZED 仅表示采样时的 hostapd 控制状态。历史缺失元数据不会被自动追认为有效。

可选安装 `pip install '.[crypto]'` 后，在已提供 `--pmk-file` 的命令上加 `--unwrap-key-data`，验证 M3 的 RFC3394 AES Key Wrap 完整性并解析当前 CCMP 配置的 Key Data。只有 MIC 和上下文通过后才解包；报告分开包装完整性与内容结构校验，输出 RSNE、GTK Key ID/长度等元数据和 padding 长度，不输出 GTK 字节。两个 RSNE、RSNXE 等扩展明确为超出支持范围；未知元素计数后忽略。此步骤不证明 M3 与广播参数一致或 AP 已安装密钥。默认不开启，默认依赖仍为空。

## 范围

输入为带 radiotap 的 classic pcap，复用 capture.py 的边界和 FCS 检查。当前解释基础设施网络中明文 Data/QoS Data 的 RFC1042 LLC EAPOL，限定 RSN descriptor type 2、descriptor version 2、16 字节 HMAC-SHA1 MIC。只为这一个明确配置识别 M1–M4 标志组合。EAPOL 长度和 Key Data 长度必须一致；未知组合明确中断当前路径。

保护数据、分片、A-MSDU 和 Order 布局有明确的不支持计数；不会把密文按明文解析。SAE/FT、Suite-B、组密钥握手及加密 rekey 不在本模块范围。M1–M4 的识别不能替代完整协议合法性检查。

## 上下文与结论

分析指定 AP/STA 地址和方向，每次新的 ANonce 建立独立观测路径；认证/关联/断连管理帧只作为观测边界，不解释为真实重置。时间倒退或超过 `--max-gap`（默认 30 秒，允许 0..300 秒但不含 0）也隔离路径。

M2 的 counter 须对应已观察的 M1；M3 须对应 ANonce 和前序 M2；M4 可对应本次路径中观察到的任一 M3 counter。相同 EAPOL payload 的链路重传不重复推进路径。M3 重传候选不等于密钥重装。缺报文、nonce 改变、计数不符、MIC 验证失败均保留明确异常原因，`ap_violation_confirmed=false`；丢包、乱序或错误 PMK 都可能导致这些结果。

不提供 PMK 时，`consistent_four_message_path_observed` 仅表示观察到连贯标志及上下文。提供单个已知 PMK 后，按双方 MAC 和 nonce 派生 KCK，对含 EAPOL 头、MIC 字段清零的完整 EAPOL 计算 HMAC-SHA1，截取 16 字节比较。只有 M2–M4 验证均通过且路径无歧义，才有 `mic_verified_four_message_path_observed=true`。M1 本身未认证。

抓包中存在相同 AP/STA 的基线 PSK/CCMP 关联或重关联请求时，保留其 RSNE，并逐位比较后续 M2 的 RSNE。M2 缺失、重复、截断 RSNE 或与请求不一致均不能得到一致路径。管理、时间和未知 EAPOL 上下文断点会清除旧关联依据。`association_bound_mic_verified_four_message_path_observed` 还要求这项比较及 M2–M4 MIC 均通过；缺少关联请求时为 false，逐路径比较字段为 null。它仅证明所观察字节的 RSNE 关联，不包含 RSNXE、OCI 或 M3 解包校验。

这些结论不证明 AP 接收了报文、安装了 PTK/GTK、解包了 M3、实际执行 RSNE 检查或开放了数据端口；相关内部状态字段保持 false，表示尚未证实。当前不生成 APModel 内部事件，也不主动发送 M2/M4。

开启解包后，M3 的第一个 RSNE 还会与 M1 开始前窗口内唯一的 AP Beacon/定向 Probe Response RSNE 比较，保留原始记录索引和时间。过期、冲突、缺失、损坏或 RSNXE 广播不能提供基线绑定；后来的广播不覆盖当前路径快照。`rsne_bound_mic_verified_four_message_path_observed` 要求 M2 与关联请求、M3 与广播的两项绑定及 MIC/完整路径全部通过。广播依据不等同于 STA 实际收到该帧，更不证明 AP 内部安全状态。

## 验证

M4 的 counter 还须大于此前观察到的 STA 回复 counter；相同 payload 的链路重传单独标记。保留多个 SNonce 候选，有 PMK 时由 M3 MIC 选择分支，M4 按对应 M3 counter 使用分支；无密码学绑定依据时保留歧义，不归为已确认的 AP 违规。

104 项项目测试通过。测试使用此前隔离 hwsim 网络实际捕获的四帧 JSON 固定样本，并覆盖错误 PMK、内容篡改、重复帧、旧 pending M3 counter 的 M4、多 SNonce、关联 RSNE、未知消息、缺失上下文、时间/管理边界、错误方向及格式。

另对 `reports/hwsim/hwsim-results-20261009-133653/` 下的 wpa2、transition-psk 两组原始抓包离线分析，均识别到一个连贯 M1–M4 路径且 MIC 全部通过。更早的 133607 抓包不含所需 EAPOL，不能用来声称通过。本轮没有现场发包或新建实验连接。

根因与协议阅读记录见 research/reading-log.md。完整主动四次握手、GTK 解包、RSNE 一致性、密钥安装/PN 生命周期和 SAE 仍是后续工作。
