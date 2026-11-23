---
{"dg-publish":true,"permalink":"/note/signature/daps/","dgPassFrontmatter":true,"dg-note-properties":{}}
---

|                                  |                                            |                    |
| -------------------------------- | ------------------------------------------ | ------------------ |
| double-authentication-preventing | Double-authentication-preventing signature | 基于2:1TDF一个像固定有两个原像 |
|                                  |                                            | 格基不知道怎么实现          |
|                                  |                                            |                    |
|                                  |                                            |                    |
|                                  |                                            |                    |

# 14
#how-many-x #
![Pasted image 20261123224844.png\|600](/img/user/asset/Pasted%20image%2020261123224844.png)
![Pasted image 20261123225158.png\|600](/img/user/asset/Pasted%20image%2020261123225158.png)

- 同一subj，不同msg

- ![Pasted image 20261124021811.png\|600](/img/user/asset/Pasted%20image%2020261124021811.png)
![Pasted image 20261124022456.png\|600](/img/user/asset/Pasted%20image%2020261124022456.png)
这里最重要的区别是：**删除不同绑定，破坏的可能是不同安全目标。**

|假设修改|主要后果|
|---|---|
|\(d_i\) 不依赖 `msg`|不同消息可能共用同一签名；不可伪造性、双签名提取性均失效|
|\(b_i\) 不依赖 \(i\)|单份签名就可能泄露陷门|
|整体取消 `subj` 绑定|不同主题的合法签名也可能触发陷门提取|
|从 \(b_i\) 中删去 \(s\)|原文的随机预言机模拟不能直接沿用；**不等于已证明不安全**|
|只保留一个分支比特|不同消息可能选择同一分支，失去提取保证|

前三项是可以明确分析的构造风险。第四项是作者在完整版 **§5 Remark 3** 专门解释的证明技术问题。

d1kjwivbowugqa.cloudfront.net+1

### **1. 删除** \(msg\)**：签名可以直接复用**

原构造：\(d=H^\#(subj,s,msg)\)。

删除后：\(d=H^\#(subj,s)\)。

同一主题的不同消息，具有完全相同的 \(s,b_i,d_i\)，因此也具有相同签名：

\[ \operatorname{Sign}(subj,msg_1)= \operatorname{Sign}(subj,msg_2). \]

攻击者拿到 \(msg_1\) 的签名，就能拿去验证 \(msg_2\)。

**后果：直接破坏不可伪造性，也无法从双签名提取陷门。**

### **2. 删除** \(i\)**：一份签名就可能泄露私钥**

原构造：\(b_i=H_{pub}(subj,s,i)\)。

删除后：\(b_i=H_{pub}(subj,s)=b\)。

假设一份消息的哈希比特为 \((0,1,\ldots)\)，则签名包含：

\[ a_1=\operatorname{Reverse}(td,b,0),\qquad a_2=\operatorname{Reverse}(td,b,1). \]

于是 \(a_1,a_2\) 是**同一个** \(b\) **的两个不同原像**，任何人都能提取 \(td\)。

**后果：单次签名就可能泄露私钥，直接破坏安全性。**

### **3. 整体删除** \(subj\)**：失去主题隔离**

如果连 \(s\) 的主题绑定也取消，使不同主题使用同一组 \(b_i\)，那么：

\[ \begin{aligned} (subj_1,msg_1)&\to b_i,a_i^{(1)},\\ (subj_2,msg_2)&\to b_i,a_i^{(2)}. \end{aligned} \]

只要两条消息在某位置选择不同分支，即使主题不同，也能恢复陷门。

**后果：原本允许的跨主题签名也可能泄露私钥。**

注意：仅从 \(b_i\) 的哈希输入删除显式的 `subj`，但保留依赖 `subj` 的 \(s\)，不必然造成上述问题。

### **4. 从** \(b_i\) **删除** \(s\)**：证明为何困难？**

这是最值得理解的一项。

原构造：\(b_i=H_{pub}(subj,s,i)\)。

删除后：\(b_i=H_{pub}(subj,i)\)。

攻击者可以在请求签名之前，就向随机预言机查询 \(H_{pub}(subj,i)\)。

归约者必须提前确定 \(b_i\)，但此时**不知道未来签名消息要求哪个分支** \(d_i\)。

等消息确定后，归约者可能只有 \(b_i\) 在 \(A_0\) 中的原像，签名却需要 \(A_1\) 中的原像。

没有陷门，就无法完成模拟。

原文引入 \(s\)，使归约者能够在确定签名分支后，再对 \(H_{pub}(subj,s,i)\) 进行编程。

**后果：原证明不能直接使用，但没有由此证明修改后的方案不安全。**

d1kjwivbowugqa.cloudfront.net

### **5. 只保留一个比特：无法保证双签名可提取**

假设两个不同消息都映射到 0：

\[ msg_1\to0,\qquad msg_2\to0. \]

它们选择同一原像，因此无法提取陷门。

增加位置数量，配合抗碰撞哈希，才能保证不同消息至少在某个位置选择不同分支。

**最终心法：**

- `subj`：决定哪些签名必须共享骨架。
    
- `msg`：决定哪些签名必须产生差异。
    
- `i`：隔离不同位置，避免单次泄露。
    
- `s`：推迟随机预言机的编程时机，服务于不可伪造性归约。
    

来源：[Poettering–Stebila, Double-authentication-preventing signatures（完整版）](https://d1kjwivbowugqa.cloudfront.net/files/research/papers/ESORICS-PoeSte14-full.pdf?utm_source=chatgpt.com)，§5 Remark 3、Theorems 2–3、Appendix B.3。

# 

