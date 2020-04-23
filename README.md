# Deobfuscation: recovering an OLLVM-protected program

## Flat_control_flow

### Description

基于`SnowGirls`的[deflat](https://github.com/SnowGirls/deflat)，利用[angr](https://github.com/angr/angr)框架实现去除控制流平坦化，详细内容请参考[利用符号执行去除控制流平坦化](https://security.tencent.com/index.php/blog/msg/112) 。

> 脚本仅依赖于`angr`框架，使用的`angr`版本为`8.19.4.5`

### Usage

> `0x400530` 是函数`check_password()`的地址。

```shell
(angr-dev) <path>/deflat/flat_control_flow$ python3 deflat.py -f samples/bin/check_passwd_x8664_flat --addr 0x400530
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

## Bogus_control_flow

### Description

利用[angr](https://github.com/angr/angr)框架去除虚假的控制流，详细内容请参考[Deobfuscation: recovering an OLLVM-protected program](https://blog.quarkslab.com/deobfuscation-recovering-an-ollvm-protected-program.html) 。

原文的主要思路是在进行符号执行时，对约束条件进行"精简"，通过将`x * (x + 1) % 2 `替换为`0`，使得`(y < 10 || x * (x + 1) % 2 == 0)`恒成立，从而获取正确的基本块，避免死循环。

在使用[angr](https://github.com/angr/angr)框架解决该问题时，也可以按照上述思路进行。另外一种思路是直接将`x`或`y`的值设为`0`，同样可以使得上面的约束恒成立。在默认条件下，`x`和`y`的值会被初始化为0，无需手动进行设置。也就是说，可以直接利用符号执行来解决，而不会遇到死循环的问题。

通过符号执行，获取所有执行过的基本块之后，再进行`patch`去除冗余的基本块即可。

> 对控制流进行精简后，通过`F5`查看伪代码，与源码基本一致。另外，可以在此基础上对控制流进行进一步精简，比如去除冗余的指令等。

### Usage

> `0x080483e0 `是函数`target_function()`的地址。

```shell
(angr-dev) <path>/deflat/bogus_control_flow$ python3 debogus.py -f samples/bin/target_x86_bogus --addr 0x80483e0
*******************symbolic execution*********************
executed blocks:  ['0x8048686', '0x804868b', '0x8048991', '0x8048592', '0x8048914', '0x8048715', '0x8048897', '0x8048720', '0x8048725', '0x80484ab', '0x804862c', '0x804842e', '0x80484b6', '0x80484bb', '0x80487bb', '0x80487c0', '0x80486c7', '0x8048950', '0x8048551', '0x80488d3', '0x8048955', '0x8048556', '0x8048856', '0x80489d8', '0x80488d8', '0x804885b', '0x80483e0', '0x80485e0', '0x8048761', '0x80485eb', '0x80485f0', '0x80484f7', '0x80487fc']
************************patch******************************
Successful! The recovered file: ./target_bogus_recovered
```

## Description

### Supported Arch

目前，脚本仅在以下架构的程序上进行测试:

+ `x86`系列:`x86`, `x86_64`
+ `arm`系列:`ARMEL`, `ARMHF` (`armv7 32bit`)

### Misc

`am_graph.py`脚本来自于[angr-management/utils/graph.py](https://github.com/angr/angr-management/blob/master/angrmanagement/utils/graph.py)，用于将`CFG`转换为`supergraph`，因为`angr`框架中`CFG`与`IDA`中的不太一样。

> A super transition graph is a graph that looks like IDA Pro's CFG, where calls to returning functions do not terminate basic blocks. 

通常在安装`angr`时，并不会安装`angr-managerment` (`angr`的GUI)，所以这里直接将[angr-management/utils/graph.py](https://github.com/angr/angr-management/blob/master/angrmanagement/utils/graph.py)拷贝到当前目录，并重命名为`am_graph.py`.

## Requirements

- 安装`python3`
- 安装`angr`  

## Reference

+ [deflat](https://github.com/SnowGirls/deflat)
+ [利用符号执行去除控制流平坦化](https://security.tencent.com/index.php/blog/msg/112)
+ [Deobfuscation: recovering an OLLVM-protected program](https://blog.quarkslab.com/deobfuscation-recovering-an-ollvm-protected-program.html)
+ [obfuscator-llvm wiki](https://github.com/obfuscator-llvm/obfuscator/wiki)

