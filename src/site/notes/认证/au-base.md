---
{"dg-publish":true,"permalink":"//au-base/","dgPassFrontmatter":true}
---










# 安全分析

## 非形式化

### 攻击及其防御

| Name    |                          | 描述             |     |
| ------- | ------------------------ | -------------- | --- |
| 中间人攻击   | man-in-the-middle attack | 截获公开信道后发送自己的消息 |     |
| 口令猜测攻击  | Password guessing attack |                |     |
| 验证器被盗攻击 | Stolen Verifier          |                |     |
| 冒充攻击    | Impersonation Attack     | 模拟公开信道的        |     |
| 前向安全    | Forward secrecy          |                |     |
|         |                          |                |     |

#### Defense against man-in-the-middle attack




## 形式化

### 查询

$I:代表所有实体（U∪S∪XX）$


> [!NOTE] Execute：输出实体间真实交互的消息
> - （C, S）（BPR）: 模拟攻击者<mark style="background: #FF5582A6;">窃听</mark> C，S 间真实执行 


> [!NOTE] Send：输出 U 接受到 m 后生成的消息
> - （U, m）（BPR）：模拟主动攻击，攻击者可<mark style="background: #FF5582A6;">拦截消息并对其进行修改、伪造新消息</mark>， 或将其直接转发给目标参与方。



- Test






### Security definitions 安全定义

> [!NOTE] Partnering：会话标识符（sid）和伙伴标识符（pid）
>- ROR：sid：某个会话。 Pid：对等实体。则若满足以下条件，则称两个实例U1和U2为伙伴：（1） U1与 U2均接受；（2） U1与 U2具有相同的会话标识符；（3） U1的伙伴标识符为 U2且反之亦然；（4）除 U1与 U2之外，没有其他实例以等于U1或 U 2的伙伴标识符接受。实际上，sid可以取为客户端和服务器实例在接受之前对话的部分记录。













