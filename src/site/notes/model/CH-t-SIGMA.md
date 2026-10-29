---
{"dg-publish":true,"permalink":"/model/ch-t-sigma/","dgPassFrontmatter":true,"dg-note-properties":{}}
---



| 1   | abe和libert的适配性                         |
| --- | -------------------------------------- |
| 2   | t-sigma$\xrightarrow{?}x x-CH-x x-sig$ |
| 3   | 有什么意义？                                 |



# CH
## list

|       |                                                                           |
| ----- | ------------------------------------------------------------------------- |
| #08BR | A Characterization of Chameleon Hash Functions and New, Efficient Designs |




##  08BR
- [[model/CH-t-SIGMA#4.1\|#4.1]] 任意满足**强特殊可靠性**(strong special soundness)和**强诚实验证者零知识性**(S-HVZK)的 $\Sigma协议$可以构造 **抗碰撞hash**[CR,SS,SSS]





$$
\boxed{
\begin{array}{l}
承诺：Y=g^y\implies \\
挑战:\impliedby C \\
响应：z=y+x\cdot C \implies\\
验证；Y=X^{-C}g^z \\
----------- \\
对应的hash族： \\
H(C,z)=X^{-C}g^z
\end{array}
}
$$

### 4.1
- $SP=(K,P,V,Cm,Ch,Rp)\in \Sigma(SSS)\cap \Sigma(S-HVZK)是\Sigma协议$
- $H=(KG,H,Ch,Rp,Cm)=\Sigma{2}H(SP)是SP相关hash函数族$
- $对每个H的碰撞抗性(cr)敌手\mathcal{B}--存在一个SSS-敌手\mathcal{A}满足：$
$$
Adv_{H,\mathcal{B}}^{cr}(k)\leq Adv_{SP,\mathcal{A}}^{sss-na}(k)
$$运行时间相同
- `na` 可理解为 **no attack**
>$$
\boxed{\begin{array}{c|c|c}
 CR&SS&SSS \\
 succ:&succ:&succ: \\
 u_{1}\neq u_{2},H_{pk}(u_{1})
=H_{pk}(u_{2})&c_{1}\neq c_{2}&u_{1}\neq u_{2} \\
 不同转录，同一结果&
\end{array}
} 
 $$
>![Pasted image 20261029085940.png](/img/user/asset/Pasted%20image%2020261029085940.png)

> [!NOTE] 第二句是第一句的逆否命题？【有种A包含B的感觉】
> 任何有效的 Hash 碰撞攻击，都能被转换成有效的 SSS 攻击。因此，只要 SSS 安全，就能推出 Hash 具有碰撞抵抗性。
### schnorr is ok
- 什么是$\Sigma-H$
	- 就是$LHF$中重构承诺的概念


###




# trapdoor-$\Sigma \&$NIZK



































