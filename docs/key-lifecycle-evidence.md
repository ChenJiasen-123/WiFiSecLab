# 密钥生命周期证据

运行 `sudo python3 tools/hwsim/hwsim_lifecycle.py`，在隔离的 mac80211_hwsim AP/STA 上测试 WPA2、WPA3、混合模式 PSK/SAE 的连接、断开、重连。需要 hostapd、wpa_supplicant、wpa_cli、hostapd_cli、tcpdump、iw、ip，以及可用的 tracefs 和 hwsim 模块。已有 hwsim 或同名实验 namespace 时脚本拒绝运行。

每个配置输出 model-report.json、key-report.json、kernel-trace.txt、trace-stats.json、状态快照、日志和抓包。独立 tracefs instance 只记录调用元数据，不读取密钥内容；结束时清理本次创建的进程、namespace、trace instance 和模块。

key-report.json 根据 AP phy、对端 MAC、pairwise 标记和阶段边界选择 cfg80211 密钥操作。同一 PID 的操作与返回关联；中间出现其他 rdev 调用或 phy 不一致时不猜测配对。返回 0 表示内核接口报告成功。断开前安装、断开阶段删除、重连阶段安装分别独立判定。删除返回 -2 不当作成功，也不能单独证明漏洞。

observed 表示观察到符合条件的成功操作；not_confirmed 表示有效阶段中未找到成功证据；unknown 表示缺少阶段标记；unknown_trace_loss 表示缓冲区丢失或缺少完整统计。非 observed 结果都需要进一步调查，不能直接当作漏洞。

这证明软件实验环境的接口行为，不证明物理固件清除、内存擦除、密钥材料更新、队列/定时器清理或旧会话输入拒绝。debugfs 快照仅列目录，不能视为密钥库存。该脚本还不是完整 802.11 状态机一致性测试。
