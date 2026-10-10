# 数据面会话证据绑定

新增 src/wifiseclab/data_evidence.py 与离线命令 tools/hwsim/hwsim_data_analyze.py。hwsim_udp.py 记录本地及远端 IP/UDP 端口；hwsim_smoke.py 记录 AP/STA 的 BSSID、MAC、命名空间、接口、配置 IP，以及抓包和两端记录的 SHA-256。

分析器要求 RSNE 绑定且 MIC 验证通过的 PSK 四报文路径、有效授权快照、同轮文件哈希和地址映射、相同 128-bit 请求标记、成功的两端负载校验、授权快照后的有界重叠收发区间。数据完成前出现上下文边界、未知时间或新 M1 均拒绝关联。数据完成后的清理不否定此前采样。

命令示例（已知实验 PMK，文件为原始 32 字节，不是口令文本）：

    python tools/hwsim/hwsim_data_analyze.py --case /path/to/wpa2 --pmk-file /path/to/lab-pmk

退出码 0 表示关联成功，1 表示证据不足或不匹配。读取失败等输入错误会报错，不会成为成功。

实际 Linux hwsim 重跑四种配置，均完成标准连接和 UDP 往返。WPA2、transition-psk 均通过新增会话关联，结果见 hwsim-data-verification/data-session-correlation.json。SAE 两种配置没有声称完成密码学会话绑定。

198 项测试通过，覆盖标记、地址、哈希、身份、时间、上下文错配。实验后确认命名空间已清理、hwsim 已卸载，实体网卡为 managed 模式。本轮未通过实体网卡发送测试包。

信任与范围：采集器元数据是可信实验采集约定，不是远程证明。文件哈希只能绑定文件，不能证明采集器诚实或负载确实经过指定无线链路。当前证明应用层采样往返，不证明固件密钥安装、持续授权、隔离策略或漏洞不存在。自定义 M2/M4 Linux 实时发送、密钥/数据抓包验证及标准和论文精读仍待继续。
