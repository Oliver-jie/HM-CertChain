# HM-CertChain 指定代码路径补齐清单

本包基于上一轮 `HM-CertChain-Fabric22-next-development.zip`，补齐论文第 8.1 节明确指出的三个**源码位置**。

| 论文位置 | 本包实际路径 | 内容 |
|---|---|---|
| `bccsp/sw/hoach.go` | `bccsp/sw/hoach.go`、`bccsp/sw/hoach_protocol.go` | 数学核心及 `Setup/AuthSetup/Hash/Verify/Adapt/Trace` 入口 |
| `fabric-protos/common/common.proto` | `fabric-protos/common/common.proto` | `BlockHeader` 的含 `pre_ca_hash = 4` **局部定义**，不是上游全量协议源文件 |
| `fabric/chaincode/migration.go` | `chaincode/migration.go`、`chaincode/hoa_anchor.go` | 独立 shim 链码，可经 `Invoke` 调用 `Initialization/Unlock/Execution/CommitMigration` |

## 本轮额外实质修改

- `vendor/github.com/hyperledger/fabric-protos-go/common/common.pb.go`：为实际依赖中的 `BlockHeader` 加 `PreCAHash` 字段、getter，并**同步更新内嵌 gzip protobuf FileDescriptorProto**。这修改了 vendored 依赖，官方部署时应另外发布匹配的 `fabric-protos-go` fork，而不是长期只使用 vendor 覆盖。
- `protoutil/blockutils.go`：扩展 `asn1Header` 和 `BlockHeaderBytes`，使 `PreCAHash` 参与区块头哈希。**这是硬分叉级协议更改，仅能使用新建创世块的隔离网络，不能直接读取既有网络的区块。**
- `chaincode/` 是相对于 Fabric 根目录的新目录；此前版本的 `hmcertchain/chaincode/` 仍保留，因此不要把两个目录的 `.go` 文件合并到同一包里。

## 重要边界——尚未实现或不能主张实现

1. `fabric-protos/common/common.proto` 是准确的区块头片段，不是全部上游 `.proto` 文件；现有 vendor Go 文件已相应更新。后续公开应取得匹配版本的完整上游协议源码并统一再生成。
2. `Trace` 接口通过合法授权记录确认 CA 身份，**不是**论文 Algorithm 1 所述仅凭冲突元组计算身份的机制；分级授权算法也使用了清晰标注的加性派生，而非逐字复制论文中需要消歧的公式。
3. `PreCAHash` 已纳入数据类型与哈希编码，但没有接入 Orderer 的 CA 感知赋值；新增字段默认空值，不能据此声称双哈希组块已完成。
4. 未实现历史区块物理编辑、跨 Peer/Orderer 的编辑共识及块索引重建；链码的 HOA 证明验证不等于历史块更新已执行。
5. 使用论文里的旧网络数据与此改动后区块头编码不兼容。
6. 未运行完整 Fabric 网络测试。不可将本包声明为论文全部系统与安全证明的完整复现。

## 对应链码入口

| Fabric Invoke 函数名 | 代码处理函数 |
|---|---|
| `Initialization` | `(*Contract).initialization` |
| `Unlock` | `(*Contract).unlock` |
| `Execution` | `(*Contract).execution` |
| `CommitMigration` | `(*Contract).commit` |

`migration.go` 为 `package main` 的 Fabric shim 链码，其入口由 `Invoke` 对外暴露，而非同名 Go 导出函数。

## 公开前建议

至少补齐上游完整 `fabric-protos` 源码、CA 分组组块链路、历史编辑共识与账本重建，以及 Go/Fabric 版本复现材料。
