---
{"dg-publish":true,"permalink":"/z-auth/bpr-ror/","dgPassFrontmatter":true}
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

## Game

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

## 状态、中止视角
- 如何为了区分real or random，那么中止概率就是优势

![Pasted image 20260312232642.png](/img/user/asset/Pasted%20image%2020260312232642.png)

- list
	- $\Lambda_{H}(\Lambda_{A})$
		- $rule_{H_{1}}:(i,q,r)(第i个Hash，输入，输出)$
	- $\Lambda_{E}$
		- $rule_{E_{1}}:(k,Z,*(none),*(E),Z^*)(口令，输入(明文)，..，加密算法，输出(密文))$
			- 第三个参数类似$g^*$,此处不使用*，而是随机映射
		- $rule_{D_{1}}:(k,Z,\varphi,D,Z^*)$
			- $g^\varphi=Z$
	- $\Lambda_{\Psi}(Send-query)$
		- $Send(I,m):模拟A发送m到实体I。Send(U,Start)会初始化算法，因此A会得到C\to S的流$
		- ![Pasted image 20260312233210.png](/img/user/asset/Pasted%20image%2020260312233210.png)
	- 此处惰性采样（我自己编的）
		- 就是因为$\cancel{E_{pw}(r_{1}\gets G)=C \& E_{pw}(r_{2}\gets G)=C}$会碰撞
		- 或者：$E(r_{1})=C_{1},E(r_{1})=C_{2},因为前文图中写的后置，这更有可能！$
			- $\textcolor{red}{\frac{q_{E}^2}{2q}（Game_{1}）}$
		- 如果和 #25XW 一样使用非惰性采样（记录，不会采到一样的C）那么$\textcolor{red}{Adv=negl}$
			- $在一个集合，本次与上次碰撞Pr=\frac{i-1}{q}对应上文的或者$
	- 问题出在$\cancel{服务器解密Oracle}$
		- 所以$Game_{2}修改了规则S_{1}\to S_{1}^{(2)}改为查表$
		- 此时解密Oracle有问题：$\varphi=⊥$
			- $我编一个多用户安全的概念吧$
			- $这是加密谕言机和Send谕言机冲突:q_{S}=q_{s}+q_{p}$
				- $\textcolor{red}{Adv=\frac{q_{s}*q_{e}}{q}}(Game_{2})$
					- 已经有$\frac{q_{e}}{q}个坏球，再抽q_{S}次大体这样理解吧$
	- $大量修改：$
		- $H^3:hash查表$
		- $E^3\&D^3:加解密查表$
		- $S_{1}^3:S_{1}本质加密$
		- $\textcolor{red}{Adv=\frac{2q_{e}^2+q_{S}^2}{2q}+\frac{q_{h^2}}{2^{l+1}}(Game_{3})}$
- $Game_{4}:$
	- ![Pasted image 20260312233210.png](/img/user/asset/Pasted%20image%2020260312233210.png)
		- $Enc_{n}:当且仅当A提交使用pw加密的数据$
		- $Auth_{n}:当且仅当A提交由被服务器接受的auth$
	- $U_{2}先查表，，防止密码猜测攻击已经成立$
		- $\textcolor{red}{Adv=Pr[Enc_{4}]}$
	- 



| Hash $\Lambda_{H}$    | $H_{i}(q)\to r$                   | 选择随机元素$r\in{0,1}^{l_{i}}$         | (i,q,r)->$\Lambda_{H orA}$           | H1  |
| --------------------- | --------------------------------- | --------------------------------- | ------------------------------------ | --- |
|                       |                                   | $只有一个输出是H$                        | $(1,*,H)$                            | H3  |
| E、D$\Lambda_{E}$      | $E_{k}(Z)\to Z^*$                 | 选择$Z*$                            | $(k,Z,⊥,E,Z^*)\to \Lambda_{E}$       | E1  |
|                       | $D_{K}(Z^*)=Z(\Lambda_{E})\;or\;$ | $如果Z不在\Lambda_{E},就选择Z=g^\varphi$ | $(k,Z,\varphi,D,Z^*)\to \Lambda_{E}$ | D1  |
|                       |                                   |                                   |                                      |     |
| Send $\Lambda_{\Psi}$ |                                   |                                   |                                      |     |
|                       |                                   |                                   |                                      |     |
|                       |                                   |                                   |                                      |     |
|                       |                                   |                                   |                                      |     |


















