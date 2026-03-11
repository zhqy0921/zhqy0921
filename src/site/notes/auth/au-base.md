---
{"dg-publish":true,"permalink":"/auth/au-base/","dgPassFrontmatter":true}
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

> [!NOTE] 结论1
> $Adv^{ftg}(t,send,reveal,exe)\leq2\cdot Adv^{ror}(t,send,test,exe)$
> $q_{test}=q_{reveal}+1$



$I:代表所有实体（U∪S∪XX）$


> [!NOTE] Execute：输出实体间真实交互的消息
> - （C, S）（BPR）: 模拟攻击者<mark style="background: #FF5582A6;">窃听</mark> C，S 间真实执行 


> [!NOTE] Send：输出 U 接受到 m 后生成的消息
> - （U, m）（BPR）：模拟主动攻击，攻击者可<mark style="background: #FF5582A6;">拦截消息并对其进行修改、伪造新消息</mark>， 或将其直接转发给目标参与方。



- $Succ_{n}:\mathcal{A}成功在Test-query中猜测比特b$
- 
#### Game

- $Game_{0}:Adv_{p}^{ake}(A)=2Pr[Succ_{0}]-1$(真实)
	- 即$Test-query$
	- $A获得p=a\cdot s+2e,k=p\cdot s$
- $Game_{1}:|Pr[succ_{1}]-Pr[succ_{0}]|\leq \epsilon$
	- $Hash-query$
		- 在$Game_{6}$中出现
- $Game_{1}:$(随机)
	- $C设置p=b,k=p\cdot s$
	- 0,1：$A可区分rlwe实例$
- $Game_{2}:$
	- $C设置x=b\to k=p$

- $Game_{7}:$









### Security definitions 安全定义

> [!NOTE] Partnering：会话标识符（sid）和伙伴标识符（pid）
>- ROR：sid：某个会话。 Pid：对等实体。则若满足以下条件，则称两个实例U1和U2为伙伴：（1） U1与 U2均接受；（2） U1与 U2具有相同的会话标识符；（3） U1的伙伴标识符为 U2且反之亦然；（4）除 U1与 U2之外，没有其他实例以等于U1或 U 2的伙伴标识符接受。实际上，sid可以取为客户端和服务器实例在接受之前对话的部分记录。

- Semanticsecurity语义安全
	- 认证协议目的：会话密钥安全
		- 一个协议$P$中，$A$多项式时间内可执行$Execute,Send,Reveal\dots$和一次$Test$.
			- 游戏结束时输出$b$
		- ![Pasted image 20260305044052.png](/img/user/asset/Pasted%20image%2020260305044052.png)
---
- 











