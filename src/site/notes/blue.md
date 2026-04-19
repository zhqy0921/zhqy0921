---
{"dg-publish":true,"permalink":"/blue/","dgPassFrontmatter":true}
---



> [!NOTE] 
> only one
> 




# 模版
$$
\begin{array}{l c r}
\text{左}(param_{1}, param_{2}) & 中 & \text{右}(param_{1}) \\
\hline \\[-1.5ex] \\

(result_{1}) \leftarrow \text{ALgo}_1(参数1) & & \\
& \xrightarrow{\hspace{1.5cm} 右箭头 \hspace{1.5cm}} & \\
& & 样本 \leftarrow \$ \mathcal{采样} \\ \\

& \xleftarrow{\hspace{1.5cm} 左箭头 \hspace{1.5cm}} & \\
\{内容1\&\&\setminus\setminus\ \}\{\&箭头\&\setminus\setminus\}\{\&\&内容3\setminus\setminus\setminus\setminus\}   & & \\ \\

\end{array}
$$





# Base
## 术语表
### index

| 翻译  | F-s #f-s         | fiat-shamir |
| --- | ---------------- | ----------- |
|     | sigma #f-s-sigma |             |


| ZK  | #commitment | [[blue#ZK\|blue#ZK#base#承诺]] |
| --- | ----------- | ----------------- |
|     |             |                   |
|     |             |                   |
|     |             |                   |


| 签名  | 定义  | 定义和安全 #def-sec        |                              |
| --- | --- | --------------------- | ---------------------------- |
|     | 功能  | 线性同态签名 #line-homo-sig | #11BF #line-homo-sig-def-sec |


### term

| 术语                       | 含义          | 限制                 |
| ------------------------ | ----------- | ------------------ |
| n #n                     | 多项式的次数      |                    |
| $\gamma$ #gamma          | 控制模数大小的整数参数 |                    |
| q #q                     | 质数          |                    |
|                          |             |                    |
|                          |             |                    |
|                          |             |                    |
| w #w Y #Y R #R           | 见证、陈述、关系    | 私钥、公钥、$(w,Y)\in R$ |
| T #T                     | 承诺          |                    |
| $\mathcal{C}$ #cal-space | 挑战空间        |                    |
| st #st                   | 状态          |                    |
| c、s #c-s                 | 挑战-响应       |                    |
|                          |             |                    |
|                          |             |                    |
|                          |             |                    |
|                          |             |                    |
|                          |             |                    |
## 困难问题的难度





## 范式

### F-S
#f-s
#### 通用sigma协议
#f-s-sigma
$$
\begin{array}{l c r}
\text{P}(w, Y, \text{R}) & & \text{V}(Y, \text{R}) \\
\hline \\[-1.5ex]
(T, \text{st}) \leftarrow \text{P}_1(w, Y) & & \\
& \xrightarrow{\hspace{1.5cm} T \hspace{1.5cm}} & \\
& & c \leftarrow \$ \mathcal{C} \\
& \xleftarrow{\hspace{1.5cm} c \hspace{1.5cm}} & \\
s \leftarrow \text{P}_2(w, Y, T, c, \text{st}) & & \\
& \xrightarrow{\hspace{1.5cm} s \hspace{1.5cm}} & \\
& & \mathbf{true/false} \leftarrow \text{V}(Y, T, c, s)
\end{array}
$$
##### 实例化-DLOG
$$
\begin{array}{l c r}
\text{P}(w,Y,G) & & \text{V}(Y,G) \\
\hline \\[-1.5ex]
r \leftarrow_{\$} \mathbb{Z}_p & & \\
T := rG & & \\
& \xrightarrow{\hspace{1.8cm} T \hspace{1.8cm}} & \\
& & c \leftarrow_{\$} \mathbb{Z}_p \\
& \xleftarrow{\hspace{1.8cm} c \hspace{1.8cm}} & \\
s := r + cw & & \\
& \xrightarrow{\hspace{1.8cm} s \hspace{1.8cm}} & \\
& & \text{Return true iff} \\
& & T + cY = sG
\end{array}
$$
### Okamoto
#Okamoto 

### Katz-Wang
#Katz-Wang




# 签名
## index

|       |                                                                                               |     |
| ----- | --------------------------------------------------------------------------------------------- | --- |
| #11BF | Linearly Homomorphic Signatures over Binary Fields and New Tools for Lattice-Based Signatures | PKC |


### 盲签名

|        |                                                                                |      |         |
| ------ | ------------------------------------------------------------------------------ | ---- | ------- |
| #82Cha | Blind Signatures for Untraceable Payments                                      | 开山之作 | rsa同态构造 |
| #06Fis | Round-Optimal Composable Blind Signatures in the Common Reference String Model |      |         |
|        |                                                                                |      |         |
- 范式：
	- 同态+one more假设
	- Fischlin 框架
	- Fiat–Shamir


- one-more unforgeability 保证不可伪造：即使 l-1 次签名会话以并发方式完成，输出 l 个不同消息的有效签名仍然很难

- 应用：
	- 电子现金
	- 匿名凭证
	- 电子投票
	- 隐私保护认证


## Dilithium
### sigma
#sigma-dilithium
$$
\begin{array}{l c r}
\text{P}(w,Y,G) & & \text{V}(Y,G) \\
\hline \\[-1.5ex]
r \leftarrow_{\$} \mathbb{Z}_p & & \\
T := rG & & \\
& \xrightarrow{\hspace{1.8cm} T \hspace{1.8cm}} & \\
& & c \leftarrow_{\$} \mathbb{Z}_p \\
& \xleftarrow{\hspace{1.8cm} c \hspace{1.8cm}} & \\
s := r + cw & & \\
& \xrightarrow{\hspace{1.8cm} s \hspace{1.8cm}} & \\
& & \text{Return true iff} \\
& & T + cY = sG
\end{array}
$$


## 签名with高效协议

### jeudy











## 同态签名

### 11BF
#11BF 
#### base
#line-homo-sig-def-sec 
> [!info] 定义 2.1：线性同态签名方案 (Linearly Homomorphic Signature Scheme)
>  设 $R$ 为主理想整环 (principal ideal domain)。$R$ 上的**线性同态签名方案**是一个概率多项式时间算法元组 $(\mathrm{Setup}, \mathrm{Sign}, \mathrm{Combine}, \mathrm{Verify})$，具有以下功能：
> 
> - $\mathrm{Setup}(n, \mathrm{params})$：输入安全参数 $n$（一进制）和额外的公共参数 $\mathrm{params}$（包含周围空间(ambient space)的维度 $N$ 和待签名子空间的维度 $k$），该算法输出公钥 $\mathrm{pk}$ 和私钥 $\mathrm{sk}$。
> - $\mathrm{Sign}(\mathrm{sk}, \mathrm{id}, \mathbf{v})$：输入私钥 $\mathrm{sk}$、标识符 $\mathrm{id} \in \{0, 1\}^n$ 和向量 $\mathbf{v} \in R^N$，该算法输出签名 $\sigma$。
> - $\mathrm{Combine}(\mathrm{pk}, \mathrm{id}, \{(\alpha_i, \sigma_i)\}_{i=1}^\ell)$：输入公钥 $\mathrm{pk}$、标识符 $\mathrm{id}$ 以及一组元组 $\{(\alpha_i, \sigma_i)\}_{i=1}^\ell$（其中 $\alpha_i \in R$），该算法输出签名 $\sigma$。（此 $\sigma$ 旨在作为 $\sum_{i=1}^\ell \alpha_i \mathbf{v}_i$ 的签名。）
> - $\mathrm{Verify}(\mathrm{pk}, \mathrm{id}, \mathbf{y}, \sigma)$：输入公钥 $\mathrm{pk}$、标识符 $\mathrm{id} \in \{0, 1\}^n$、向量 $\mathbf{y} \in R^N$ 和签名 $\sigma$，该算法输出 $0$（拒绝）或 $1$（接受）。
> 
> 我们要求对于 $\mathrm{Setup}(n, \mathrm{params})$ 输出的每一对 $(\mathrm{pk}, \mathrm{sk})$，满足：
> 1. 对于所有的 $\mathrm{id}$ 和 $\mathbf{y} \in R^N$，如果 $\sigma \leftarrow \mathrm{Sign}(\mathrm{sk}, \mathrm{id}, \mathbf{y})$，则 $\mathrm{Verify}(\mathrm{pk}, \mathrm{id}, \mathbf{y}, \sigma) = 1$。
> 2. 对于所有的 $\mathrm{id} \in \{0, 1\}^n$ 和所有三元组集合 $\{(\alpha_i, \sigma_i, \mathbf{v}_i)\}_{i=1}^\ell$，如果对于所有 $i$ 都有 $\mathrm{Verify}(\mathrm{pk}, \mathrm{id}, \mathbf{v}_i, \sigma_i) = 1$ 成立，那么
> $$\mathrm{Verify} \left( \mathrm{pk}, \mathrm{id}, \sum_{i} \alpha_i \mathbf{v}_i, \mathrm{Combine} \left( \mathrm{pk}, \mathrm{id}, \{(\alpha_i, \sigma_i)\}_{i=1}^\ell \right) \right) = 1.$$

## 盲签名




# ZK
## index

|         |                                                                                      |         |     |
| ------- | ------------------------------------------------------------------------------------ | ------- | --- |
| #15BKLP | Efficient Zero-Knowledge Proofs for Commitments from Learning With Errors over Rings | esocise |     |
|         |                                                                                      |         |     |



## base
### 承诺
#commitment
> [!NOTE|aside-r] Title
> 陷门承诺方案只能是计算绑定的。有关此类方案的详细讨论，请参见例如 Fischlin [Fis01]

> [!NOTE] Commitment(KGen,Com,Ver)（承诺隐藏原信息&承诺不可更改）
> - $\textcolor{red}{KGen(1^l)}\implies 公开承诺密钥pk$
> - $\textcolor{red}{Com(m\in M,pk)}\implies 承诺和打开对(c,d)$
> - $\textcolor{red}{Ver(m,pk,c,d)}\implies{0}/1$
> ---
> - $\textcolor{red}{正确性：}Pr[Ver(\cdot)=1\textcolor{green}{:}pk\stackrel{\$}{\leftarrow} KGen(\cdot),m\in M, (c,d)\stackrel{\$}{\leftarrow}Com(\cdot)]=1$
> - $\textcolor{red}{绑定性：}$
> 	- 完美绑定：一个承诺不能被打开为不同的消息。如果这一点无条件成立，则称该方案为完美绑定。$(Ver(pk, m, c, d) = accept) ∧ (Ver(pk, m_{0} , c, d_{0} ) = accept)  ⇒ m = m_{0}$
> 		- $\textcolor{blue}{如果同一个承诺值 c，既能用凭证 d 成功验证为消息 m，又能用凭证 d' 成功验证为消息 m'，那么在数学上 m必须完全等于 m'。}$
> 	- 计算绑定：如果没有 PPT 对手能提出一个承诺和两个不同的打开值，则称该方案为计算绑定。$Pr[Ver(pk, m, c, d) = Ver(pk, m_0 , c, d_0 ) : pk $ ← KGen(1^l),(c, m, d, m_0 , d_0 ) $ ← A(pk)] ≤ negl(n)$
> - $\textcolor{red}{计算隐匿：}承诺在计算上隐匿了所承诺的消息$$$\Pr \left[ b = b' : \begin{array}{c} pk \xleftarrow{\$} \text{KGen}(1^\ell), (m_0, m_1, \text{aux}) \xleftarrow{\$} A_1(pk), b \xleftarrow{\$} \{0, 1\}, \\ (c, d) = \text{Com}(m_b, pk), b' \xleftarrow{\$} A_2(c, \text{aux}) \end{array} \right] \le \frac{1}{2} + \text{negl}(n).$$
> 	- 陷门承诺：

>$格承诺 \begin{cases} \text{哈希消息承诺}：承诺的大小几乎不依赖于被承诺值的大小， \\ 但代价是消息空间仅限于范数较小的 多项式。  \\ \\ \text{无界承诺}：消息空间无界，但承诺的大小与消 息的大小线性相关。\end{cases}$
>




## 22LNP

### ABDLOP=Ajtai+BDLOP(improve BKLP)
#15BKLP 


#### BLKP
> [!info] 承诺方案 (Commitment Scheme)
> **KGen (密钥生成)**: 公共承诺密钥 $pk = (\boldsymbol{a}, \boldsymbol{b})$ 计算为 $\boldsymbol{a}, \boldsymbol{b} \xleftarrow{\$} (\mathbb{Z}_q[x]/\langle x^n + 1 \rangle)^k$，其中 $q \equiv 3 \pmod 8$ 是素数，且 $n$ 是 2 的幂。
> 
> **Com (承诺)**: 为了对消息 $m \in \mathbb{Z}_q[x]/\langle x^n+1 \rangle$ 进行承诺，承诺算法提取 $r \xleftarrow{\$} \mathbb{Z}_q[x]/\langle x^n+1 \rangle$ 和 $\boldsymbol{e} \xleftarrow{\$} D_{\sigma_e}^k$，条件是 $\|\boldsymbol{e}\|_\infty \le n$，并输出：
> $$\boldsymbol{c} = \boldsymbol{a}m + \boldsymbol{b}r + \boldsymbol{e},$$
> 并且 $\boldsymbol{c}$ 的打开信息由 $(m, r, \boldsymbol{e}, 1)$ 给出。
> 
> **Ver (验证)**: 给定一个承诺 $\boldsymbol{c}$，一个消息 $m'$，一个随机数 $r'$，以及 $\boldsymbol{e}'$ 和 $f'$，当且仅当满足以下条件时验证者接受：
> $$\boldsymbol{a}m' + \boldsymbol{b}r' + f'^{-1}\boldsymbol{e}' = \boldsymbol{c} \quad \land \quad \|\boldsymbol{e}'\|_\infty < \left\lfloor \frac{n^{4/3}}{2} \right\rfloor \quad \land \quad \|f'\|_\infty \le 1 \quad \land \quad \deg f' < \frac{n}{2}.$$

#### BDLOP
> [!info] 承诺方案 (Commitment Scheme)
> **KeyGen (密钥生成)**: 为消息 $\boldsymbol{x} \in R_q^\ell$ 创建公共参数 $\boldsymbol{A}_1 \in R_q^{n \times k}$ 和 $\boldsymbol{A}_2 \in R_q^{\ell \times k}$：
> $$\begin{align*} \boldsymbol{A}_1 &= [\ \boldsymbol{I}_n \quad \boldsymbol{A}'_1 \ ], \quad \text{其中 } \boldsymbol{A}'_1 \xleftarrow{\$} R_q^{n \times (k-n)} \\ \boldsymbol{A}_2 &= [\ \boldsymbol{0}^{\ell \times n} \quad \boldsymbol{I}_\ell \quad \boldsymbol{A}'_2 \ ], \quad \text{其中 } \boldsymbol{A}'_2 \xleftarrow{\$} R_q^{\ell \times (k-n-\ell)} \end{align*}$$
> 
> **Commit (承诺)**: 选择随机多项式向量 $\boldsymbol{r} \xleftarrow{\$} S_\beta^k$，输出承诺：
> $$Com(\boldsymbol{x}; \boldsymbol{r}) := \begin{bmatrix} \boldsymbol{c}_1 \\ \boldsymbol{c}_2 \end{bmatrix} = \begin{bmatrix} \boldsymbol{A}_1 \\ \boldsymbol{A}_2 \end{bmatrix} \cdot \boldsymbol{r} + \begin{bmatrix} \boldsymbol{0}^n \\ \boldsymbol{x} \end{bmatrix}$$
> 
> **Open (打开)**: 一个有效打开是三元组 $(\boldsymbol{x}, \boldsymbol{r}, f)$，其中 $\boldsymbol{x} \in R_q^\ell$、$\boldsymbol{r} \in R_q^k$、$f \in \bar{C}$。验证者需检查：
> $$f \cdot \begin{bmatrix} \boldsymbol{c}_1 \\ \boldsymbol{c}_2 \end{bmatrix} = \begin{bmatrix} \boldsymbol{A}_1 \\ \boldsymbol{A}_2 \end{bmatrix} \cdot \boldsymbol{r} + f \cdot \begin{bmatrix} \boldsymbol{0}^n \\ \boldsymbol{x} \end{bmatrix}$$
> 并且对于所有的 $i$，满足 $\|r_i\|_2 \le 4\sigma\sqrt{N}$。



## SNARK
#SNARK
- A succinct non-interactive argument of knowledge





## stern































