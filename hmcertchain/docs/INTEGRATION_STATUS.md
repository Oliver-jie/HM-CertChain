# 逐项对应论文的实现状态（请在公开时保留）

| 项目 | 本轮实现 | 仍缺少的内容 |
| --- | --- | --- |
| HOA-CH 基础运算 | `bccsp/sw/hoach.go` | 安全参数审计与部署集成 |
| HOA-CH 分级授权 | `hmcertchain/hoa/authorization.go` 派生与公钥关系验证 | 论文原算法的形式化等价、授权签名与 MPC |
| HOA-CH 身份追踪 | CA 身份与会话审计记录可关联 | 论文 `Trace` 三重碰撞身份恢复算法未实现 |
| Shamir 门限 | `hmcertchain/hoa/shamir.go` | 多方安全重构协议未实现 |
| `Pre_CA_hash` 原生字段 | 保留协议示例 | **未改原生 fabric-protos-go/common.BlockHeader** |
| Orderer 双哈希组块 | `hmcertchain/ledger/ca_index.go` 提供 CA 逻辑链接生成 | **未接入 Orderer** |
| CA 定向查询 | 逻辑链验证组件 | **未接入 Peer 的块索引/查询** |
| 历史区块授权修改 | 链码中的逻辑状态切换及审计摘要 | **未实现物理区块修改、分布式共识** |
| Peer/Orderer 账本一致性 | 保留官方原生校验 | 不支持可编辑历史区块一致性 |
| 链码 HOA-CH 证明 | `RegisterHOAAnchor` + `CommitMigration` 验证新旧证书 HOA 等式 | 缺乏外部历史区块头/证明绑定；不是完整迁移证明 |

重要：不应通过关闭 `DataHash` 或签名校验、直接覆写 blockfile 来假装实现历史区块适配。新增目录中的模型和函数是可供后续底层集成的构件，不等同于 Fabric 原生协议已经修改。

## 验证记录

本轮 `go build ./hmcertchain/hoa ./hmcertchain/ledger ./hmcertchain/chaincode` 已通过（本地环境）。现有 `main_test.go` 仍使用旧版提交参数，迁移成功路径失败；还需调整测试夹具以提供注册的 HOA 锚和适配随机数。本轮尚未测试真实 Fabric 多节点部署。
