# HM-CertChain 开发工程（基于用户提供的 Fabric release-2.2 源码）

## 源码范围

- `bccsp/sw/hoach.go`：原有 HOA-CH 数学原型，仍未实现论文准确 Trace 算法。
- `hmcertchain/hoa/authorization.go`：基于根标量的 CA 派生授权与变色龙哈希公开验证；另有 `shamir.go` 门限分享。
- `hmcertchain/ledger/ca_index.go`：独立 CA 逻辑关联索引和审计事件结构，不改变 Fabric 原生块格式。
- `hmcertchain/chaincode/migration.go`：CA 登记、证书、迁移状态机。
- `hmcertchain/chaincode/hoa_anchor.go`：注册 HOA 哈希锚；迁移提交必须提供真实哈希适配等式可验证的 JSON 证明。

## 迁移证明接口

调用 `RegisterHOAAnchor(caID,p,q,g,public,hash,randomness)`，所有大整数使用十六进制字符串。`Hash` 用注册证书的 DER 和 `parentID/caID` 路径；其后调用 `Initialization`、`Unlock`，再调用 `CommitMigration(sid,newCertPEM,proofJSON)`；proofJSON：

```json
{"sessionId":"session-1","caId":"CA-A","newRandomness":"...hex..."}
```

链码重新解析证书 DER，检查会话、新旧父 CA、证书公钥一致，使用链上锚内的公钥与新随机数验证两组 HOA-CH 等式；不再无条件接受一个任意 64 字节摘要。

## 注意

1. HOA 组参数须用审计过的安全参数；不能使用玩具参数。私钥及 Shamir 份额永远不能存上链。
2. 此实现还**没有改变**官方 Fabric 的 `common.BlockHeader`，没有原生 `Pre_CA_hash`、Orderer 双哈希组块或历史 blockfile 改写。
3. 后续要实现真正的可编辑块必须修改匹配的 `fabric-protos` 源码、区块编解码、排序/验证和历史账本机制，并重新构建整网。不能以这个压缩包声称已经完整复现论文。
4. 本包以源码交付为主，集成网络测试未完成；注意切勿在正式账本直接部署或替换。
