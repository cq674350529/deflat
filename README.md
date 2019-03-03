## deflat

基于`SnowGirls`的[deflat](https://github.com/SnowGirls/deflat)，利用[angr](https://github.com/angr/angr)框架实现去除控制流平坦化，详细内容请参考[利用符号执行去除控制流平坦化](https://security.tencent.com/index.php/blog/msg/112)

> 脚本仅依赖于`angr`框架，使用的`angr`版本为`8.19.2.4`

## description

`am_graph.py`脚本来自于[angr-management/utils/graph.py](https://github.com/angr/angr-management/blob/master/angrmanagement/utils/graph.py)，用于将`CFG`转换为`supergraph`，因为`angr`框架中`CFG`与`IDA`中的不太一样。

> A super transition graph is a graph that looks like IDA Pro's CFG, where calls to returning functions do not terminate basic blocks. 

通常在安装`angr`时，并不会安装`angr-managerment` (`angr`的GUI)，所以这里直接将[angr-management/utils/graph.py](https://github.com/angr/angr-management/blob/master/angrmanagement/utils/graph.py)拷贝到当前目录，并重命名为`am_graph.py`.

## requirements

+ 安装`python3`
+ 安装`angr`  

## usage

> `0x400530` 是函数`check_password()`的地址。

```shell
(angr-dev)$ python3 deflat.py check_passwd_flat 0x400530
*******************relevant blocks************************
prologue: 0x400530
main_dispatcher: 0x400554
pre_dispatcher: 0x40099b
retn: 0x40098f
relevant_blocks: ['0x40086a', '0x40080d', '0x4008ee', '0x40094f', '0x40084e', '0x400819', '0x400886', '0x40095b', '0x4007ec', '0x40092e', '0x4008a9', '0x4008cc', '0x40091b', '0x40097c', '0x400837']
*******************symbolic execution*********************
-------------------dse 0x40086a---------------------
-------------------dse 0x40080d---------------------
-------------------dse 0x4008ee---------------------
-------------------dse 0x40094f---------------------
-------------------dse 0x40084e---------------------
-------------------dse 0x400819---------------------
-------------------dse 0x400886---------------------
-------------------dse 0x40095b---------------------
-------------------dse 0x4007ec---------------------
-------------------dse 0x40092e---------------------
-------------------dse 0x4008a9---------------------
-------------------dse 0x4008cc---------------------
-------------------dse 0x40091b---------------------
-------------------dse 0x40097c---------------------
-------------------dse 0x400837---------------------
-------------------dse 0x400530---------------------
************************flow******************************
0x40084e:  ['0x40086a', '0x40095b']
0x40086a:  ['0x400886', '0x40094f']
0x400530:  ['0x4007ec']
0x4008a9:  ['0x4008cc', '0x40094f']
0x400886:  ['0x4008a9', '0x40094f']
0x4007ec:  ['0x400819', '0x40080d']
0x40091b:  ['0x40098f']
0x40080d:  ['0x40084e']
0x40092e:  ['0x40094f']
0x4008ee:  ['0x40091b', '0x40092e']
0x400819:  ['0x400837']
0x40094f:  ['0x40097c']
0x40095b:  ['0x40097c']
0x40097c:  ['0x40098f']
0x400837:  ['0x4007ec']
0x4008cc:  ['0x4008ee', '0x40094f']
0x40098f:  []
************************patch*****************************
Successful! The recovered file: check_passwd_flat_recovered
```

## reference

+ [deflat](https://github.com/SnowGirls/deflat)
+ [利用符号执行去除控制流平坦化](https://security.tencent.com/index.php/blog/msg/112)

