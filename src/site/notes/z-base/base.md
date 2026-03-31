---
{"dg-publish":true,"permalink":"/z-base/base/","dgPassFrontmatter":true}
---


| #96Ajt | Generating Hard Instances of Lattice Problems                    |
| ------ | ---------------------------------------------------------------- |
| #07MR  | Worst-case to Average-case Reductions based on Gaussian Measures |
| #08GPV |                                                                  |
# 复杂度
## P、NP、NP-C
基于时间复杂度下不同问题的计算难度
- $字母表\sum=\{0,1\},串w_{1}=001,w_{2}=1101\dots,语言L=\{w_{1},w_{2}\dots\}$
### **图灵机**
![Pasted image 20260329010140.png](/img/user/asset/Pasted%20image%2020260329010140.png)
#### P,NP,NP-C
- P:
- NP:基于非确定性图灵机模型[(29 封私信 / 80 条消息) 【长文】什么是P、NP、NP-C问题 - 知乎](https://zhuanlan.zhihu.com/p/670075417)
- NP-C:


# paper
# 96Ajt
![Pasted image 20260329004113.png|300](/img/user/asset/Pasted%20image%2020260329004113.png)
## 摘要
> [!NOTE|aside-l] 以指数接近1
> 设成功率p(n),以指数接近1：p(n)=1-x^n ![Pasted image 20260329003940.png](/img/user/asset/Pasted%20image%2020260329003940.png)
- 给出了一类$\textcolor{red}{Z^n中的一类随机网格，生成时会附带短向量}$
	- 如果存在一种$\textcolor{red}{概率PPT算法}$以$\frac{1}{2}$的概率找到**随机网格**中的**短向量**
		- 那么存在$\textcolor{red}{概率PPT算法}$以$\textcolor{blue}{指数接近于 1 }$的成功概率解决：
			- $\textcolor{red}{Gap-SVP}$：求解n维格中最短非0向量，近似达到一个多项式因子
			- $\textcolor{red}{u-SVP}$：
			- $\textcolor{red}{SIVP}$：
	- 如果上述问题没有PPT解：
		- 存在一个单向函数
		- subset-sum问题无PPT解
---
- 困难问题是"难"的问题
	- 找到一组随机生成的问题，并证明如果有一种算法能以正概率找到随机实例的解，那么也有一种算法能在最坏情况下解决著名的未解问题之一。
- 给出了一个随机问题：在某一类随机网格（其元素可以与其中的短向量一起生成）中找到一个短向量，其在上述意义上的解意味着一组相关 "著名 "问题在最坏情况下的解。我们在此提及其中的三个最坏情况问题：
## 介绍



## 07MR

## 08GPV

### 前言






# 平滑参数Smoothing Parameter






















