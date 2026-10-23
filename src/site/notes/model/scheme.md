---
{"dg-publish":true,"permalink":"/model/scheme/","dgPassFrontmatter":true,"dg-note-properties":{}}
---






# TAG

|       |                                                            |     |     |
| ----- | ---------------------------------------------------------- | --- | --- |
| #19BL | Direct CCA-Secure KEM and Deterministic PKE from Plain LWE | PQC |     |
## 19BL




|         | 挑战密文 |     | 谕言机 | 不可区分的依据与熵损失 |
| ------- | ---- | --- | --- | ----------- |
|         |      |     |     |             |
| $G_{0}$ |      |     |     |             |
| $G_{1}$ |      |     |     |             |
| $G_{2}$ |      |     |     |             |


## term
### hybrid encryption
- 公钥加密 $\underbrace{会话密钥（是私钥加密的私钥）}_{\Large\text{KEM}}$。私钥加密 $\underbrace{消息}_{DEM}$
	- 为了效率
- CCA-KEM+CCA-DEM=CCA-hybrid #key 
	- Direct KEM：不通过PKE实现KEM
	- CPA-PKE+FOtransformation=CCA-KEM

- 使用FO需要RO在我们的假设下需要QROM
	- 其他方式：（$\textcolor{red}{标准模型}$）
		- LTDF
		- BCHK：IBE/tag-PKE$\implies$CCA
			- 都需要SUF-CMA OTS/MAC