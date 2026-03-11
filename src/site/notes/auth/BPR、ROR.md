---
{"dg-publish":true,"permalink":"/auth/bpr-ror/","dgPassFrontmatter":true}
---

$\textcolor{red}{1}$

|        |                                                                         |             |
| ------ | ----------------------------------------------------------------------- | ----------- |
| #00BPR | Authenticated Key Exchange Secure Against Dictionary Attacks            |             |
| #05AFP | Password-Based Authenticated Key Exchange<br>In the Three-Party Setting |             |
| #02BCP | Security Proofs for an Efficient Password-Based Key Exchange            | bpr-variant |


# BPR
- oracle在模拟攻击
- 

## 符号
- $U=C∪S$
	- $\Pi_{U}^i:主体U的第i个实例对应的oracle$



## 标准/理想模型
![Pasted image 20260309035353.png](/img/user/asset/Pasted%20image%2020260309035353.png)


## Send-query
![Pasted image 20260309075842.png](/img/user/asset/Pasted%20image%2020260309075842.png)

- 碰撞：
	- 对m1的签名变为对m2的签名
	- pw1的散列变为pw2的散列
		- 都是不正确的
### 生日悖论
- hash碰撞：$\frac{q_{h}^2}{2^{l+1}}$
- 相同碰撞：$\frac{(q_{s}+q_{e})^2}{2q}$
- 盲猜碰撞：$\frac{q_{s}}{2^l}$


# bpr02



- 目的：安全交换密钥--**语义安全**
---

$Theorem_{1}:$
- 定义$空间、分布、符号含义$
- 陈述$优势$
---
- $Game_{0}$
	- 定义$ROM、event$
	- 定义$所有实体$--覆盖并发执行

> [!NOTE] oracle
> 哈希谕言机$H_{0},H_{1}$
> 加密、解密谕言机$\mathcal{E}、\mathcal{D}$

> [!NOTE] event
> $Succ_{n}:当且仅当b=b'(Test和\mathcal{A}的输出)$
> $Enc_{n}:\mathcal{A}提交了用pw加密的数据$
> $Auth_{n}:\mathcal{A}提交了被S接受的Auth$

$$
\mathrm{Adv}^{\mathrm{ake}}_{\mathrm{P}}(\mathcal{A}) = 2 \Pr[\mathrm{Succ}_0] - 1.
$$

---
- $Game_{1}$
	- 因为A的中止（未输出答案、查询$q_{s}$和时间$t$超出上界）、将随机输出b’
		- 此时视为随机猜测--$未产生任何优势$
- $维持哈希列表\Lambda_{H}和加密列表\Lambda_{E}来模拟H_{0,1}以及Game_{7}里的H_{2,3}$
> [!NOTE] query
> - ![Pasted image 20260310222527.png](/img/user/asset/Pasted%20image%2020260310222527.png)
> - 

![Pasted image 20260310222343.png](/img/user/asset/Pasted%20image%2020260310222343.png)
![Pasted image 20260310224344.png](/img/user/asset/Pasted%20image%2020260310224344.png)




---
- $Game_{2}$
	- 模拟$Send$




---
- $Game_{3}$
	- $\textcolor{red}{Adv=\frac{2q^2_{E}+q^2_{S}}{2(q-1)}+\frac{q^2_{h}}{2^{l_{1}+1}}}$
- 

