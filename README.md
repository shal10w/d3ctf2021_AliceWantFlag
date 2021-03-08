# d3ctf2021_AliceWantFlag

题目代码较长，核心主要是server有注册，登陆功能，以Alice账号登陆后发送加密信息拿flag。
nc上Alice后可以向他提供自己伪造的服务器地址，因此可以得到Alice发送的一些信息
大致有用信息为
+ 与Alice交互可以给他r并得到用服务器公钥加密的r \^ Alicepasswd
+ server在signin和signup里各有一次解密，其中signin仅判断值的正误有效信息较少，signup解密后根据长度给予不同回显更容易利用。
+ （非预期）Alice会对endkey进行解密并且与r \^ Alicepasswd的结果进行拼接得到AESkey，并不对AESkey进行长度补全
题目目标为得到Alicepasswd与endkey

预期解
elgamal有乘法同态特性，即
E（m） = y1 , y2 ; D(y1 , k*y2) = km
可以通过这个方式可以在不知道明文的情况下修改明文。比如乘以2能将明文左移一位，即有可能触发signup的长度判断。
但正常情况下也只能触发一次，得到最高位信息。因此这时我们需要利用r修改alice发送的明文。
将其最高位异或为0,就可以接着用长度来爆出下一个位，最多进行88次即可爆出密钥。
endkey很短，只有五位，这里可以使用中间相遇，在《Why Textbook ElGamal and RSA Encryption
Are Insecure》中有提到一个40位以下的数有18%的几率能够分解为两个20位以下数的乘积。
并且pow(y2 , q , p) = pow(m , q , p) = pow(a , q , p) \* pow(b , q , p)，其中m = ab
则我们可以中间相遇来得到endkey。最后获得flag
其中，中间相遇过程可以少截取一部分来减少空间占用与时间花费，大约仅需要40s即可完成一次。

非预期解（最后绝大多数队都是这么干的）
由上面第三点，aeskey并没有进行填充，通过这里的报错能够知道长度，用与预期相同的方法解出passwd，接着，由于AESkey长度为16,若长度不满16则报错，endkey长度为5,可以用二分的方法找到一个k使得
k \* endkey < 2\*\* 128 < (k+1)endkey
则endkey = 2\*\*128 // k  (+1)

代码在exp文件夹中

fake_server为伪造服务器，通过不断连接爆破passwd，再通过getflag脚本得到flag