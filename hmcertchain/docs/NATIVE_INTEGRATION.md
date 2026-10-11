# Fabric 原生协议与历史块编辑：未完成事项及所需实现

本工程目前没有实现原生 `BlockHeader.Pre_CA_hash`、Orderer CA 分组、原生历史区块物理改写及多节点重写共识。不得以辅助的逻辑 CA 链替代这些功能而宣称论文全部完成。

## 源码已确认的具体位置

- `vendor/github.com/hyperledger/fabric-protos-go/common/common.pb.go` 的 `BlockHeader` 仅包含 `Number`、`PreviousHash`、`DataHash`；这是生成文件，不能孤立手工加字段。
- `protoutil/blockutils.go` 的 `asn1Header` 和 `BlockHeaderBytes` 确定区块头哈希编码。
- `orderer/consensus/etcdraft/blockcreator.go` 的 `createNextBlock` 创建 Raft 区块、设置 `DataHash` 和新的区块头哈希。
- `common/ledger/blkstorage/blockstore.go` 的 `RetrieveBlockByNumber` 提供经过存储层读取的区块。

## 原生扩展的工程前置条件

1. 获取实际匹配的 `fabric-protos`（源 `.proto`），在定义 `common.BlockHeader` 的源文件新增字段并统一重新生成协议代码，包括 descriptor。代码评审需要明确 wire field number、旧新节点兼容策略和所有语言绑定。
2. 冻结新区块头的 ASN.1 字段次序和哈希规则，明确创世块及升级边界；同步修改所有产生和验证区块哈希的节点。
3. 定义经过签名认证的 CA 交易分类协议，禁止依赖不可信 transaction payload 来决定 CA 所属；再修改 blockcreator 和共识提交过程。
4. 设计和审查更改历史区块的节点共识协议及快照、索引、状态数据库同步操作；未经共识禁止原地写 blockfile。
5. 建立链码授权迁移与区块证明的绑定规则以及端到端验收；完整测试之前不作安全性和论文指标结论。

## 本轮实际添加的功能

`hmcertchain/ledger/block_query.go` 支持对已经提交的 Fabric 区块执行校验后的顺序扫描与 CA 逻辑关联，验证区块头前驱哈希、区块数据哈希，再由调用者提供经身份认证的 CA 分类器进行过滤；它不实现原生跳跃链接，也不提供论文宣称的查询加速。

## 安全边界

- 没有关闭原生哈希或签名检查。
- 不修改 Fabric 原生块文件。
- 未发明实际并不存在的 `BlockHeader` 字段和自动调用路径。
- HOA-CH 密码实现、身份追踪、门限多方计算、历史区块编辑尚缺少完整的生产级安全验证。
