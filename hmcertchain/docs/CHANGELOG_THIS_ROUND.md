# 本轮代码修改记录（2026-10-11）

## 基础源版本
从上一版 `HM-CertChain-Fabric22-extended-development.zip` 解压，保留原版 Fabric 源码与已加入的密码模块及迁移链码。

## 实际完成
1. **解决重复声明导致的链码构建失败**：`hmcertchain/chaincode/main.go` 是旧版入口，与 `migration.go` 具有同名顶层声明。将其移至 `hmcertchain/docs/legacy_main.go.txt` 供差异核对，保留当前 HOA 证明版本 `migration.go` 作为唯一入口。`hoa_anchor.go` 保持不变。
2. **增加 CA 定向账本查询工具**：新增 `hmcertchain/ledger/block_query.go`：`QueryCA` 使用与 Fabric `BlockStore` 一致的只读接口遍历区块，逐块校验 `DataHash` 和 `PreviousHash`，通过调用方提供的**经认证 CA 分类器**过滤并构造逻辑 CA 关联链；`VerifyCALinks` 验证逻辑链接的编号与哈希连续性。
3. **原生集成边界说明**：新增 `hmcertchain/docs/NATIVE_INTEGRATION.md`，列出协议生成、区块头 ASN.1、Raft 组块和账本索引的实际入口及剩余缺口。

## 尚未完成（不得声称已完成）
- 原生 `common.BlockHeader.Pre_CA_hash` 的 protobuf 定义、生成代码和网络协议部署；仓库只含生成后的 `vendor/github.com/hyperledger/fabric-protos-go/common/common.pb.go`，没有对应源 `.proto` 或 `protoc`。
- Orderer 按 CA 分类的实际组块及跳跃链接；本轮查询仍是 O(区块总数) 的扫描。
- 历史区块物理修改及 Peer/Orderer 多节点编辑共识。
- 完整安全论证后的 HOA-CH 身份追踪、MPC 门限私钥重构。
- 链码适配证明和真实历史区块之间的链上绑定。

## 验证范围
Go 编译检查：`GOFLAGS=-mod=vendor go build ./hmcertchain/ledger ./hmcertchain/hoa ./hmcertchain/chaincode`；本轮没有执行网络端到端验收。本项目不可作为论文完整复现成果公开。
