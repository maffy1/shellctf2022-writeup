# WP

## dragon

很显然，用IDA打开就能看得出来

```
strcpy((char *)v5, "SHELLCTF{5348454c4c4354467b31355f523376337235316e675f333473793f7d}");
```

然后，16进制转字符串

```python
from libnum import *
print(n2s(0x5348454c4c4354467b31355f523376337235316e675f333473793f7d))
#b'SHELLCTF{15_R3v3r51ng_34sy?}'
```

## keygen

我们在阅读主程序后发现有一个getString的函数

```c
char *getString()
{
  char *result; // rax

  result = (char *)malloc(0x19uLL);
  strcpy(result, "SHELLCTF{k3ygen_1s_c0oL}");
  return result;
}
```

so,flag->SHELLCTF{k3ygen_1s_c0oL}

## Pulling_the_strings

我们重点关注

```
 if ( !wcscmp(flag, ws) )
```

是一个比较的

```c
flag dq offset unk_2008 
```

我们接着跟进

```
.rodata:0000000000002008 53                            unk_2008 db  53h ; S     
```

这里转数组就行，我们提取数据

```python
[0x00000053, 0x00000048, 0x00000045, 0x0000004C, 0x0000004C, 0x00000043, 0x00000054, 0x00000046, 0x0000007B, 0x00000054, 0x00000068, 0x00000034, 0x0000006E, 0x0000006B, 0x00000073, 0x0000005F, 0x00000066, 0x00000030, 0x00000072, 0x0000005F, 0x00000074, 0x00000068, 0x00000065, 0x0000005F, 0x00000066, 0x0000006F, 0x0000006F, 0x00000064, 0x0000007D, 0x00000000]
```

这里推荐一款好用的IDA插件，LazyIDA，懒人必备

```python
s=[0x00000053, 0x00000048, 0x00000045, 0x0000004C, 0x0000004C, 0x00000043, 0x00000054, 0x00000046, 0x0000007B, 0x00000054, 0x00000068, 0x00000034, 0x0000006E, 0x0000006B, 0x00000073, 0x0000005F, 0x00000066, 0x00000030, 0x00000072, 0x0000005F, 0x00000074, 0x00000068, 0x00000065, 0x0000005F, 0x00000066, 0x0000006F, 0x0000006F, 0x00000064, 0x0000007D, 0x00000000]
print(bytes(s))#b'SHELLCTF{Th4nks_f0r_the_food}\x00'
```

## warmup

```c
 v4 = 1;
    for ( i = 0; i <= 26; ++i )
      v4 = (v6[i] >> 2 == s[i]) & (unsigned __int8)v4;
    if ( v4 == 1 )
```

这里v4必须等于1，所以v6[i] >> 2 == s[i]必须恒成立

```python
enc=[0]*28
enc[0] = 460
enc[1] = 416
enc[2] = 404
enc[3] = 432
enc[4] = 432
enc[5] = 396
enc[6] = 464
enc[7] = 408
enc[8] = 492
enc[9] = 392
enc[10] = 196
enc[11] = 464
enc[12] = 348
enc[13] = 420
enc[14] = 212
enc[15] = 404
enc[16] = 380
enc[17] = 192
enc[18] = 448
enc[19] = 204
enc[20] = 456
enc[21] = 260
enc[22] = 464
enc[23] = 192
enc[24] = 456
enc[25] = 332
enc[26] = 500
for i in range(len(enc)):
    print(chr(enc[i]>>2),end='')
#shellctf{b1tWi5e_0p3rAt0rS}
```

## tea

我们阅读伪代码后发现有4个函数

分别对应 获取输入，进行奇数偶数分开

进行运算，和再次混合与比较

![image-20220813171524679](https://test-1311941730.cos.ap-nanjing.myqcloud.com/image-20220813171524679.png)

![image-20220813171536715](https://test-1311941730.cos.ap-nanjing.myqcloud.com/image-20220813171536715.png)

![image-20220813171548035](https://test-1311941730.cos.ap-nanjing.myqcloud.com/image-20220813171548035.png)

![image-20220813171555478](https://test-1311941730.cos.ap-nanjing.myqcloud.com/image-20220813171555478.png)

进行了奇偶拼接，加点数字移动，接着进行了字符串打散再拼接，

第三步逆回去时，有2种思路，可能还更多

第一个就是对字符串开头的shellctf{进行特征排,

![image-20220813171951836](https://test-1311941730.cos.ap-nanjing.myqcloud.com/image-20220813171951836.png)

第二个就是直接爆字符串，枚举所有可能的字符串

```python
s='R;crc75ihl`cNYe`]m%50gYhugow~34i'

enc=[]
for i in s:
    enc.append(ord(i))
enc=enc*50
# print(enc)
a=len(s)>>1
for k in range(len(s)):
    z=''
    for i in range(len(s)):
        
        if i<a:
            if (enc[k+i]+int(3 * (i // 2)))>=128:
                break
            z+=chr((enc[k+i]+int(3 * (i // 2))))
        else:
            z+=chr((enc[k+i]-i//6))
    if '{' in z and '}' in z:
        print(z)#hlcfT_niiy4DByn}selt{01fN7_n_30d

```

接下来拼回去就行

## one

主要经过3个加密

![image-20220813172629857](https://test-1311941730.cos.ap-nanjing.myqcloud.com/image-20220813172629857.png)

![image-20220813172641378](https://test-1311941730.cos.ap-nanjing.myqcloud.com/image-20220813172641378.png)

![image-20220813172650387](https://test-1311941730.cos.ap-nanjing.myqcloud.com/image-20220813172650387.png)

![image-20220813172701029](https://test-1311941730.cos.ap-nanjing.myqcloud.com/image-20220813172701029.png)

先拿到密文，我的伪代码被我手修过，你们做的话可能那么好看

![image-20220813172755927](https://test-1311941730.cos.ap-nanjing.myqcloud.com/image-20220813172755927.png)

转16进制，取最后2位再拆开，这个部分就逆完了

主要是对第二部分

```c
 while ( v9 < len_string )
  {
    *(_QWORD *)s1 = 0LL;
    v20 = 0;
    v10 = 0;
    for ( k = 0; k < v7 && len_string > v9 + k; ++k )
    {
      s1[k] = s[v9 + 48 + k];
      ++v10;
    }
    switch ( v10 )
    {
      case 1:
        if ( !strcmp(s1, "0") )
        {
          v22[opt] = 97;                        // 0
        }
        else if ( !strcmp(s1, "1") )
        {
          v22[opt] = 98;                        // 1
        }
        break;
      case 2:
        if ( !strcmp(s1, "00") )
        {
          v22[opt] = 99;                        // 2
        }
        else if ( !strcmp(s1, "01") )
        {                                       // 3
          v22[opt] = 100;
        }
        else if ( !strcmp(s1, "10") )
        {
          v22[opt] = 101;                       // 4
        }
        else if ( !strcmp(s1, "11") )
        {                                       // 5
          v22[opt] = 102;
        }
        break;
      case 3:
        if ( !strcmp(s1, "000") )
        {
          v22[opt] = 49;                        // 1
        }
        else if ( !strcmp(s1, "001") )
        {
          v22[opt] = 50;                        // 2
        }
        else if ( !strcmp(s1, "010") )
        {
          v22[opt] = 51;                        // 3
        }
        else if ( !strcmp(s1, "011") )
        {
          v22[opt] = 52;                        // 4
        }
        else if ( !strcmp(s1, "100") )
        {
          v22[opt] = 53;                        // 5
        }
        else if ( !strcmp(s1, "101") )
        {
          v22[opt] = 54;                        // 6
        }
        else if ( !strcmp(s1, "110") )
        {
          v22[opt] = 55;                        // 7
        }
        else if ( !strcmp(s1, "111") )
        {                                       // 8
          v22[opt] = 56;
        }
        break;
      default:                                  // 0，无效指令
        v22[opt] = 57;                          // 9
        break;
    }
    v9 += v10;
    ++opt;
    v7 = (v7 + 1) % 4;
  }
```

我们知道对应指令，却无法得知 具体对应去情况，我一开始想岔了，用递归列举全部情况，然后进行筛选，后来仔细审计发现主要指令是按一定顺序的，用v7再逆回去

剩下的函数就是转2进制，逆回去就行。



```python1
enc=[0x00000052, 0x00000091, 0x00000041, 0x00000091, 0x00000036, 0x00000090, 0x00000044, 0x00000090, 0x00000027, 0x00000091, 0x00000042, 0x00000091, 0x00000036, 0x00000091, 0x00000024, 0x00000090, 0x00000026, 0x00000091, 0x00000044, 0x00000090, 0x00000036, 0x00000091, 0x00000038, 0x00000090, 0x00000052, 0x00000091, 0x00000041, 0x00000090, 0x00000052, 0x00000090, 0x00000052, 0x00000090, 0x00000045, 0x00000091, 0x00000048, 0x00000091, 0x00000045, 0x00000091, 0x00000024, 0x00000090, 0x00000026, 0x00000091, 0x00000027, 0x00000090, 0x00000046, 0x00000091, 0x00000027, 0x00000090, 0x00000058, 0x00000090, 0x00000047, 0x00000090, 0x00000035, 0x00000090, 0x00000027, 0x00000090, 0x00000037, 0x00000091, 0x00000044, 0x00000090, 0x00000046, 0x00000090, 0x00000044, 0x00000090, 0x00000032, 0x00000091, 0x00000046, 0x00000090, 0x00000052, 0x00000090, 0x00000027, 0x00000090, 0x00000057, 0x00000091, 0x00000044, 0x00000091, 0x00000036, 0x00000090, 0x00000047, 0x00000090, 0x00000058, 0x00000090, 0x00000042, 0x00000090, 0x00000052, 0x00000091, 0x00000056, 0x00000090, 0x00000046, 0x00000090, 0x00000046, 0x00000091, 0x00000054]
command=[]
for i in range(len(enc)):
    Head=str(hex(enc[i]))[2:3]
    Next=str(hex(enc[i]))[3:]
    command.append(int(Head))
    command.append(int(Next))
o=''
v7=2
for i in range(len(command)):
    if v7==1:
        if command[i]==0:
            o+='0'
        elif command[i]==1:
            o+='1'
        else:
            print('Command Wrong!!')
    elif v7==2:
        if command[i]==2:
            o+='00'
        elif command[i]==3:
            o+='01'
        elif command[i]==4:
            o+='10'
        elif command[i]==5:
            o+='11'
        else:
            print('Command Wrong!!')
    elif v7==3:
        if command[i]==1:
            o+='000'
        elif command[i]==2:
            o+='001'
        elif command[i]==3:
            o+='010'
        elif command[i]==4:
            o+='011'
        elif command[i]==5:
            o+='100'
        elif command[i]==6:
            o+='101'
        elif command[i]==7:
            o+='110'
        elif command[i]==8:
            o+='111'
        else:
            print('Command Wrong!!')
    v7=(v7+1)%4
str_1=[]
print(len(o))
print(o)
for i in range(len(o)//8):
        s=o[i*8:(i+1)*8]
        bin_string='0b'
        for j in range(len(s)-1,-1,-1):
            bin_string+=s[j]
        str_1.append(eval(bin_string))
print(bytes(str_1))#b'shellctf{s0Me_b4S3_c0nVer51on5_4_U\xbd'
```

最后一位没抢救过来

我手补一下

shellctf{s0Me_b4S3_c0nVer51on5_4_U}

## switf-failed

说实话没看懂出题人想干什么，

加密key是"EULERSNUMBER"

密文是wbppcugz{F4zp0i5_w3l1p5_sW_4_xHhO7j0r}

然后不知道咋弄了，key搜一下是欧拉数，然后没有然后了

还是说我思路错了？