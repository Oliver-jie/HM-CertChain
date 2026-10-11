# HM-CertChain 源码集成状态（仅文件补充，未经完整网络测试）

## 本次真正增加的文件

- `bccsp/sw/hoach.go`：HOA-CH 有限域子群计算核心，包含 HOASetup/HOAAuthSetup/HOAHash/HOAVerify/HOAAdapt/HOATrace。
- `bccsp/sw/hoach_test.go`：数学核心测试源码；本次未执行测试。
- `hmcertchain/chaincode/migration.go`：现有 CA 证书及迁移状态链码，原 `main.go` 迁移至此。
- `hmcertchain/protocol/block_header_extension.proto`：拟扩展协议的独立文档示例，非 Fabric 有效 BlockHeader 修改。

## 重要限制

- HOAAuthSetup 当前只随机生成新密钥，不等于论文要求的根 CA 分级授权派生。
- HOATrace 当前只验证原/新哈希等式，不等于论文 Trace 算法中的 CA 身份恢复。
- 没有门限 Shamir 密钥分发、重构及保护实现。
- `fabric-protos-go` 的 `common.BlockHeader` 未被修改，也未重新生成 protobuf 代码。
- `protoutil/blockutils.go`、Orderer 组块、Peer 验证及账本数据库均未改造支持 `Pre_CA_hash`。
- 不支持对 Fabric 历史区块进行共识认可的原地修改。
- 链码 CommitMigration 只保存外部证明摘要，不执行真正的 HOA-CH 验证。
- 本包不能作为论文 HM-CertChain 完整实现或安全证据对外发布。

## 后续必须完成

1. 获取和现有 Fabric go.mod 中 fabric-protos-go 对应的 proto 定义工程，并统一生成协议代码。
2. 规范化双哈希 Header 编码及验证，定义 CA 关联策略及索引。
3. 设计并实现授权历史区块修改的提交协议，保持 Orderer/Peer/账本一致性。
4. 补齐分级授权、门限密钥、Trace 和迁移会话证明验证。
5. 在新建的 Fabric v2.2 网络上进行实际端到端验证。
