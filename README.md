# WiFiSecLab

WPA2/WPA3-Personal AP 状态转换测试研究原型。目标是把测试输入、响应、会话上下文与状态证据关联起来，而不是把“发出一帧”或“没有报错”当作测试成功。

## 项目目录与结构整理

为了让代码脉络更清晰，当前仓库已按功能维度拆分为以下结构：

```text
WiFiSecLab/
├── README.md                # 项目总览与使用入口
├── run.py                   # 离线模型运行入口
├── src/
│   └── wifiseclab/
│       ├── core/            # 模型、会话与规划
│       ├── protocol/        # 认证、关联与 WPA2/EAPOL
│       ├── network/         # 抓包、网卡与执行环境
│       └── lifecycle/       # 密钥、端口与数据证据
├── tools/                   # protocol/、radio/、hwsim/
├── tests/                   # core/、protocol/、network/、lifecycle/ 与 fixtures/
├── examples/                # 正常/异常 trace 样例
├── reports/                 # 审计结果与实验输出
├── docs/
│   ├── README.md           # 文档总索引
│   ├── feature-catalog.md  # 功能索引与对应说明文档
│   ├── architecture/       # 架构、状态机和核心设计
│   ├── protocol/           # EAPOL、握手、认证与关联
│   ├── lifecycle/          # 生命周期、key 证据与状态证据
│   ├── network/            # 热点、探测、物理无线与角色分工
│   ├── experiments/       # hwsim 与受控实验
│   ├── research/           # 背景材料、文献和研究笔记
│   └── ...
└── pyproject.toml
```

详细说明请见 [docs/README.md](docs/README.md) 和 [docs/feature-catalog.md](docs/feature-catalog.md)。

## 当前能力（2026-10-10）

| 链路 | 项目入口 | 已有验证与边界 |
| --- | --- | --- |
| 离线内部事件模型 | `run.py` / `wifiseclab` | 合成正常/缺陷轨迹；支持 WPA2、WPA3、过渡策略，不是完整协议实现。 |
| 探测、Open System 认证、关联 | `tools/protocol/hotspot.py` 的 `build`、`analyze`、`discover`、`probe`、`auth`、`associate` | 构帧、独立监听与有界关联；实体网卡有限探测/认证实验不能证明完整安全连接。 |
| 已知 PMK 四次握手分析 | `tools/protocol/eapol.py` / `wifiseclab-eapol` | M1–M4、MIC、密钥数据和 RSNE 上下文分析，含 AP 控制快照关联；分析入口本身不发送响应。 |
| M2/M4 离线构造 | `tools/protocol/wpa2_build.py` / `wifiseclab-wpa2-build` | 基线 WPA2 PSK/CCMP；独立 hwsim 捕获的响应字节与密码学验证。 |
| 接收驱动的 M2/M4 响应 | `tools/protocol/hotspot.py handshake` / `wifiseclab-hotspot handshake` | 已有生产入口与模拟测试；独立自定义 hwsim 客户端已完成正常握手。实体入口的完整链路尚未验证，两者不能等同。 |
| 自定义加密 UDP 往返 | `tools/hwsim/hwsim_custom_smoke.py`、`tools/hwsim/hwsim_custom_client.py` | Linux 隔离 hwsim 中自构造握手、CCMP 请求与响应；数据状态机遇到上下文边界关闭。尚无通用实体数据阶段入口。 |
| 端点与加密捕获复核 | `tools/hwsim/hwsim_data_analyze.py` | 已有 WPA2/过渡 PSK 正常实验记录关联；不证明持续授权、固件安装或接收端重放保护。 |
| 正常连接/断开/重连 | `tools/hwsim/hwsim_lifecycle.py` | 标准 hostapd/wpa_supplicant 的隔离实验工具；当前判定绑定目标身份、AKM、CCMP 及 SAE 的 PMF 条件。最近判定修改离线通过，完整工具尚未重新运行。 |
| 物理双网卡分工 | `tools/radio/radio_roles.py`、`tools/radio/physical_radio.py` | 动态识别 AR9271 发送与 MT7612U 独立监听；有限单帧实验，不能推定所有帧或频段可用。 |

完整 SAE/FT/PMF/重键自动测试、状态恢复与轨迹最小化、当前版标准完整核对和跨年代文献覆盖仍未完成。WPA3/过渡 SAE 的标准客户端正常连接实验，不代表自定义 SAE 实现或攻击覆盖。

## 本地运行

Python 3.10+。基础离线事件模型无第三方运行依赖；密码学验证和密钥数据处理需要可选依赖 `cryptography>=46`（安装项目的 `crypto` extra）。Linux 无线工具还依赖相应系统命令、驱动及实验权限。

```bash
python run.py examples/wpa2_normal.json --mode wpa2
python run.py examples/wpa3_normal.json --mode wpa3
python run.py examples/transition_normal.json --mode transition
python tools/protocol/hotspot.py --help
python tools/protocol/hotspot.py handshake --help
python tools/protocol/eapol.py --help
python tools/protocol/wpa2_build.py --help
python tools/hwsim/hwsim_data_analyze.py --help
python -m unittest discover -s tests -v
```

以上 `--help` 命令只展示入口，不启动无线实验。`run.py` 退出码：0=未观察到性质违反，1=候选性质违反，2=输入错误；其他工具的退出含义见各自帮助/文档。最近全量离线测试为 248 项通过。

## 证据与文档

必须分别判断：响应已构造 → 提交结果 → 独立捕获与 MIC/RSNE → AP 授权采样 → 加密数据往返。没有 finding 不代表 AP 安全；收到 ACK、M4 已构造或 AP 控制标志也不能单独证明整个链路。

- 基础模型：[模型](docs/model.md)、[事件](docs/events.md)、[状态机](docs/state-machine.md)、[剩余工作](docs/roadmap.md)。
- 无线入口：[热点测试](docs/hotspot-testing.md)、[网卡角色](docs/radio-roles.md)、[物理收发](docs/physical-radio.md)。
- 握手与数据：[EAPOL 分析](docs/eapol-analysis.md)、[自定义 hwsim 握手](docs/hwsim-custom-handshake.md)、[加密数据](docs/hwsim-custom-data.md)、[数据状态机](docs/data-session.md)。
- 状态证据：[生命周期](docs/lifecycle-testing.md)、[密钥证据](docs/key-lifecycle-evidence.md)、[阅读台账](docs/research/reading-log.md)。

早期阶段文档保留当时的限制与测试数量；最新能力以本能力表及对应较新的研究记录为准。项目不保存 SSH 私钥或密码；主动实验限定自有或明确授权的隔离环境。

### WPA2 离线场景计划（新增，尚未运行验证）

`wifiseclab-plan`（或 `python -m wifiseclab.core.planning`）接受 `--ssid --bssid --station --session --ap-profile --output`。AP profile 输入为广告报告 targets 中选定的单个对象。生成初始 PSK/CCMP 六阶段计划及认证/关联帧；握手与数据列出运行时输入需求。输出文件须不存在，父目录须存在。该入口不发包，自动执行器尚未接入，计划不代表测试通过。
