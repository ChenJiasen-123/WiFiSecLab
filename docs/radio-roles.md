# 物理网卡分工

Linux 实验机采用固定硬件角色：AR9271（USB 0cf3:9271，ath9k_htc）负责注入；MT7612U（USB 0e8d:7612，mt76x2u）负责独立监听。目前机器上分别为 wlan1、wlan0，但接口编号可能变化，代码按 USB 身份与驱动动态绑定，不硬编码接口名。

在 Linux 实验机项目目录运行：

```bash
python3 tools/radio/radio_roles.py --channel 6
```

命令只读取硬件并输出角色计划，不切换模式或发送帧。缺失、重复设备、驱动不符、不支持监听、同一物理无线电或信道不可用时直接报错。两块卡须使用同一信道；当前组合仅允许 2.4 GHz 信道 1..11。5 GHz 需要另一块支持该频段的独立无线网卡。

物理适配器应调用 `RadioRoles.bind(discover(), channel)`，发送入口通过 `interface_for("injector")` 获取接口，抓包入口通过 `interface_for("listener")` 获取接口，并据此建立各自的监听模式接口。不得依赖 wlan 编号顺序。当前 APAdapter 仍为预留协议，hwsim 工具仍使用模拟无线电；本模块不将物理网卡接入模拟实验。

两卡在 1、6、11 信道的被动 Beacon 收包已经人工验证。随后物理适配器在信道 6 完成单个随机标识探测请求的发送，MT7612U 捕获到一个字节匹配帧。角色计划中的 `injection_verified=false` 只表示静态识别不能验证发送；执行报告用 `injection_observed_this_run` 和每个动作的 `over_air_observed` 表示本轮观测，不把单帧结果推广至所有类型。详见 physical-radio.md。
