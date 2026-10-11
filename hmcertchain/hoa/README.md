# 密码扩展（独立实现）

- `DeriveCAKey` 使用根私钥与 CA 标识生成派生标量，`VerifyDelegation` 验证派生公钥对应关系。**不等价于论文 Algorithm 1 的原文公式，也不提供已证明的 UC 安全性**。
- `SplitSecret` / `RecoverSecret` 是 Shamir 门限分享和恢复的数学实现。只在可信链下进程调用，禁止把私钥或恢复份额写入账本。
- `VerifyAdapt` 验证适配前后两组数据使用相同的 HOA-CH 哈希。
- 追溯身份采用链上记录的已认证 CA 身份与会话审计记录，而不是依据论文未充分明确的三重碰撞恢复公式。
- 未提供分布式 MPC 密钥恢复、份额持有者拜占庭保护及形式化 UC 证明。
