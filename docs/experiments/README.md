# 匿名实验与验证结果

这些结果记录了传输协议、拥塞控制、编码恢复和计量方法的工程实验。它们说明特定样本中的行为，不构成长期性能保证、当前生产状态或云账单节省证明。失败和未达标结果同样保留。

## 从哪里开始

| 主题 | 可核验结论 | 结果与数据 |
| --- | --- | --- |
| 固定传输模式 | TCP、方向分离、双 TCP 各有速度与发送成本取舍 | [基线对比](transport-baselines.md) |
| 动态控制 | 控制器未证明优于固定 TCP，双向性能目标未通过 | [控制器](adaptive-controller.md) |
| 编码可靠传输 | 本地故障门槛通过；实网结果未证明 FEC 获益 | [编码原型](coded-transport.md) |
| 客户端与单跳 | 高带宽声明、客户端环境和拥塞控制共同影响观测 | [客户端实验](client-transports.md) |
| 两跳完整链路 | 五候选共 120 次文件尝试；成功率、速度与成本分开评价 | [完整链路](full-chain.md) |
| 计量与丢包定位 | 应用载荷、设备 NIC、专用 L3 和网络缺包各有边界 | [计量与路径](metering-and-path.md) |
| 集成回归 | 文件完整性、UDP、服务重启及隔离客户端回退 | [集成验证](integration-checks.md) |

节点和客户端名称均为公开版代号，没有公开地理位置或真实标识的映射。client-A、client-B 是两个 Linux amd64 环境；client-C 是运行于 macOS 宿主的 Linux ARM64 容器环境。gateway-A/B/C 和 origin 是逻辑角色，不能当作部署清单。不同实验中没有出现的角色不作推测。

```mermaid
flowchart LR
    C[匿名客户端] --> G[匿名网关]
    G --> O[固定合成源站]
    C -. 单跳实验 .-> G
```

## 离线核验

在仓库根目录运行：

```sh
python3 tools/verify_experiment_results.py
python3 -m unittest discover -s tests -p 'test_experiment_results.py'
```

这两项只读取公开数据，不连接任何机器、不产生网络载荷、不要求原始私有证据。验证器检查文件哈希、隐私模式、完整链路矩阵、吞吐与字节算术、失败成本、双向会话分母，以及保存的汇总是否可独立复算。

[方法和字段定义](methodology.md)说明观测层次；[公开规则](publication-policy.md)说明删减范围；[来源目录](provenance.json)、[复算汇总](summary.json)和[文件校验和](manifest.json)用于审阅。公开数据是经过字段白名单导出的历史观测记录，不是虚构样本；原始主机快照、捕获、账号及源站映射不随结果发布。公开结果可以支持离线算术复核，无法独立复验未公开的逐包捕获或现场执行。
