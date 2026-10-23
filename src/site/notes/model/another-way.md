---
{"cssclasses":["column-page-h"],"dg-home":true,"dg-publish":true,"permalink":"/model/another-way/","tags":["gardenEntry"],"dgPassFrontmatter":true,"dg-note-properties":{"cssclasses":["column-page-h"]}}
---

# base
$$
\boxed{
% --- 1. 定义简化宏（只需写一次） ---
\def\L#1{#1 & & \\}
\def\R#1{& & #1 \\}
\def\toR#1{& \textcolor{red}{\xrightarrow{\quad #1 \quad}} & \\}
\def\toL#1{& \textcolor{red}{\xleftarrow{\quad #1 \quad}} & \\}
% --- 2. 协议主体（按时序直观编写，零 & 符号） ---
\begin{array}{l c r}
\textbf{U}\ (pw) & & \textbf{S}\ (pw) \\[6pt]
\L{x \leftarrow [1, q-1]}
\L{X = g^x}
\toR{Send:U^1：U,\, X}
\R{y \leftarrow [1, q-1]}
\R{Y = g^y}
\R{K_S = X^y}
\R{Y^* = \operatorname{Enc}_{pw}(Y)}
\toL{Send:S^1：S,\, Y^*}
\L{Y = \operatorname{Dec}_{pw}(Y^*)}
\L{K_U = Y^x}
\L{Auth = H_1(U \parallel S \parallel X \parallel Y \parallel K_U)}
\L{sk_u = H_0(U \parallel S \parallel X \parallel Y \parallel K_U)}
\toR{Auth}
\R{\text{验证 } Auth}
\end{array}
}
$$
# Game


## $G_{0}$
这是[[model/another-way#RO\|#RO]]和[[model/another-way#理想分组密码模型\|#理想分组密码模型]]下的真实攻击游戏。[[model/another-way#问题1\|#问题1]]
因此，$\mathcal{A}$可以访问若干[[model/another-way#谕言机\|#谕言机]]以及所有实例(以覆盖并发执行)
我们在$G_{n}$中定义若干[[model/another-way#事件\|#事件]]。
$$
Adv=2Pr[S_{0}]-1
$$
## $G_{1}$
维持：[[model/another-way#Hash、Enc、Dec\|#Hash、Enc、Dec]] 
- $\Lambda_{H}(普通和敌手)$
- $\Lambda_{\mathcal{E}},\Lambda_{D}$
来模拟$哈希谕言机H_{0},H_{1}$和$加/解密谕言机$
- 以及$H_{2},H_{3}在G_{7}出现,l_{2}=l_{0},l_{3}=l_{1}$
---
按照真实参与者的方式模拟查询 [[model/another-way#Send\|#Send]]

---

## 谕言机
### 参数

|                    |                              |                |
| ------------------ | ---------------------------- | -------------- |
|                    |                              |                |
|                    |                              |                |
| $\mathbb{G}$       | 有限循环群，阶为$l$位素数$q$            | 群的阶是群元素个数      |
| $\hat{\mathbb{G}}$ | =$\mathbb{G}\setminus1(单位元)$ | 元素的阶为n，$g^n=e$ |
| *                  | 乘法群                          |                |
|                    |                              |                |
$(\mathbb Z_q=\{0,1,\ldots,q-1\})：模 (q) 的整数集合。$
$(\mathbb Z_q^*=\{x\in\mathbb Z_q\mid \exists y,\ xy\equiv1\pmod q\})：模 (q) 下有乘法逆元的元素。$
---
排除单位元是为了避免退化情况。$\textcolor{red}{x^0=1,1^x=1(分别左右Z和\mathbb{G})}$
取 $G=\langle16\rangle\subseteq\mathbb{Z}_{29}^{*}$，其中 $g=16$，阶 $q=7$。
$$
\begin{aligned}
G
&=\{16^x\bmod 29\mid x\in\mathbb{Z}_7\}\\
&=\{1,16,24,7,25,23,20\},\\[6pt]
\hat{G}
&=\{16^x\bmod 29\mid x\in\mathbb{Z}_7^*\}\\
&=\{16,24,7,25,23,20\}\\
&=G\setminus\{1\}.
\end{aligned}
$$
---

### Hash、Enc、Dec
- $\mathcal{H}_{i}(q);i\in\{0,1,2,3\}$
	- $(i,q,r)\in \Lambda_{H}\implies r$
	- otherwise：$\mathcal{H}^{(1)}$
		- 选择$r\in\{0,1\}^{l_{i}}$并将$(i,q,r)加入\Lambda_{H}或\Lambda_{\mathcal{A}}$
---
- $\mathcal{E}_{K}(Z)$
	- $(k,Z,*,*,Z^*)\in \Lambda_{\mathcal{E}}\implies Z^*$
	- otherwise：$\mathcal{E}^{(1)}$
		- 选择$Z^*\in \hat{G}$并将$(k,Z,⊥,\mathcal{E},Z^*)加入\Lambda_{\mathcal{E}}$
---
- $D_{k}(Z^*)$
	- $(k,Z,*,*,Z^*)\in \Lambda_{\mathcal{E}}\implies Z$
	- otherwise：$\mathcal{D}^{(1)}$
		- 选择$\varphi\in Z_{q}^*$计算$Z=g^\varphi$并将$(k,Z,\varphi,\mathcal{D},Z^*)到\Lambda_{\mathcal{E}}$
### Send
- client
	- $U^{(1)}: \textcolor{blue}{Send(U^i,Start)}:选择\theta\in Z_{q}^*计算X=g^\theta 返回(U,X),客户端进入\textcolor{red}{等待状态}$
	- $U^{(2)}: \textcolor{blue}{Send(U^i,(S,Y^*))}:\textcolor{red}{等待状态}下，计算Y=D_{pw}(Y^*),K_{U}=g^\theta$
	- $U^{(3)}:计算Auth和sk_{U}$
		- 将$((U,X),(S,Y^*))加入\Lambda_{trans}$
- server
	- $S^{(1)}:\textcolor{blue}{Send(S^j,(U,X)}:$
	- $S^{(2)}:\textcolor{blue}{Send(S^j,H)}:计算Auth$
		- $S^{(3)}:计算sk_{S}$
### Execute、Reveal、Test
- $Execute(U^i,S^j):获取交互记录((U,X),(S,Y^*),Auth)$
- $Reveal(I):返回实例I的会话密钥(sk_{U}或sk_{S})\textcolor{red}{如果该实例已接收}$
- $Test(I):先从Reveal获取sk,投掷coin获取b，\textcolor{red}{如果b=1，返回sk}。否则返回\{0,1\}^{l_{0}}$



## 事件
- $S_{n}$
发生当且仅当$b=b'$. b是Test查询中的比特，b‘是敌手的输出
- $Encrypt_{n}$
发生当且仅当$\mathcal{A}$提交了一个使用口令加密的数据
- $Auth_{n}$
发生当且仅当$A$提交了一个由对手构造且服务器会接受的认证器Auth

# 构件
## RO

## 理想分组密码模型







# 问题
## 问题1
- Game0的起源










