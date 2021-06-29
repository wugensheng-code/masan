# ASan for mcu

## 1、ASan是什么

GCC以及LLVM编译器支持一些可以对程序进行分析检测的编译选项，sanitize就是其中的一种。sanitize原本来自Google的开源C/C++工具集：[sanitizers](https://github.com/google/sanitizers)项目，包括了AddressSanitizer、LeakSanitizer、ThreadSanitizer、MemorySanitizer、HWASAN、UBSan以及部分工具针对不同的OS kernel：KASAN、KMSAN、KCSAN。现在已经集成在了LLVM和GCC（4.8版本开始支持Address和Thread Sanitizer、4.9版本开始支持Leak Sanitizer和UB Sanitizer）



> AddressSanitizer（ASan）是一个C/C++内存错误检测工具，本软件包在RT-Thread上进行了一定的移植适配，支持一下类型错误检测：
>
> - [x] 使用已释放内存（野指针）
> - [x] 堆内存越界（读写）（Heep buffer）
> - [x] 全局变量越界（读写）（Global buffer）
> - [ ] 内存泄漏



### 1.1 目录结构

> 说明：参考下面表格，整理出 packages 的目录结构

| 名称 | 说明 |
| ---- | ---- |
| docs  | 文档目录 |
| examples | 各种类型错误的测试用例 |
| inc  | 头文件目录 |
| src  | 源代码目录 |

### 1.2 许可证

> 采用 LGPLv2.1开源协议，细节请阅读项目中的 LICENSE 文件内容。

hello package 遵循 LGPLv2.1 许可，详见 `LICENSE` 文件。

### 1.3 依赖

- RT-Thread 3.0+
- ulog 日志

## 2、如何打开ASan

> 说明：描述该 package 位于 menuconfig 的位置，并对与其相关的配置进行介绍

使用 hello package 需要在 RT-Thread 的包管理器中选择它，具体路径如下：

```
RT-Thread online packages
    tools packages --->
        [*] MASan: MASan is a system memory problem detection tool
```

然后让 RT-Thread 的包管理器自动更新，或者使用 `pkgs --update` 命令更新包到 BSP 中。

## 3、使用 ASan

目前只能针对单个源文件进行错误检查，给asan_test.c在这个位置加入编译选项	-fsanitize=kernel-address

![image-20210610162002521](C:\Users\RTT\Documents\Sanitizer\MASan\doc\img1.png)

## 5、联系方式 & 感谢

* 维护：shinu
* 主页：https://github.com/wugensheng-code

