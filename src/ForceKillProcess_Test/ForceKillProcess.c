#include "ForceKillProcess.h"


VOID ShowError(PCHAR lpszText, NTSTATUS ntStatus)
{
	DbgPrint("%s Error[0x%X]\n", lpszText, ntStatus);
}


// ǿ�ƽ���ָ������
NTSTATUS ForceKillProcess(HANDLE hProcessId)
{
	PVOID pPspTerminateThreadByPointerAddress = NULL;
	PEPROCESS pEProcess = NULL;
	PETHREAD pEThread = NULL;
	PEPROCESS pThreadEProcess = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	ULONG i = 0;

#ifdef _WIN64
	// 64 λ
	typedef NTSTATUS(__fastcall *PSPTERMINATETHREADBYPOINTER) (PETHREAD pEThread, NTSTATUS ntExitCode, BOOLEAN bDirectTerminate);
#else
	// 32 λ
	typedef NTSTATUS(*PSPTERMINATETHREADBYPOINTER) (PETHREAD pEThread, NTSTATUS ntExitCode, BOOLEAN bDirectTerminate);
#endif

	// ��ȡ PspTerminateThreadByPointer ������ַ
	pPspTerminateThreadByPointerAddress = GetPspLoadImageNotifyRoutine();
	if (NULL == pPspTerminateThreadByPointerAddress)
	{
		ShowError("GetPspLoadImageNotifyRoutine", 0);
		return FALSE;
	}
	// ��ȡ�������̵Ľ��̽ṹ����EPROCESS
	status = PsLookupProcessByProcessId(hProcessId, &pEProcess);
	if (!NT_SUCCESS(status))
	{
		ShowError("PsLookupProcessByProcessId", status);
		return status;
	}
	// ���������߳�, ����������ָ�����̵��߳�
	for (i = 4; i < 0x80000; i = i + 4)
	{
		status = PsLookupThreadByThreadId((HANDLE)i, &pEThread);
		if (NT_SUCCESS(status))
		{
			// ��ȡ�̶߳�Ӧ�Ľ��̽ṹ����
			pThreadEProcess = PsGetThreadProcess(pEThread);
			// ����ָ�����̵��߳�
			if (pEProcess == pThreadEProcess)
			{
				((PSPTERMINATETHREADBYPOINTER)pPspTerminateThreadByPointerAddress)(pEThread, 0, 1);
				DbgPrint("PspTerminateThreadByPointer Thread:%d\n", i);
			}
			// ����Lookup...������Dereference��������ĳЩʱ����������
			ObDereferenceObject(pEThread);
		}
	}
	// ����Lookup...������Dereference��������ĳЩʱ����������
	ObDereferenceObject(pEProcess);

	return status;
}


// ��ȡ PspTerminateThreadByPointer ������ַ
PVOID GetPspLoadImageNotifyRoutine()
{
	PVOID pPspTerminateThreadByPointerAddress = NULL;
	RTL_OSVERSIONINFOW osInfo = { 0 };
	UCHAR pSpecialData[50] = { 0 };
	ULONG ulSpecialDataSize = 0;

	// ��ȡϵͳ�汾��Ϣ, �ж�ϵͳ�汾
	RtlGetVersion(&osInfo);
	if (6 == osInfo.dwMajorVersion)
	{
		if (1 == osInfo.dwMinorVersion)
		{
			// Win7
#ifdef _WIN64
			// 64 λ
			// E8
			pSpecialData[0] = 0xE8;
			ulSpecialDataSize = 1;
#else
			// 32 λ
			// E8
			pSpecialData[0] = 0xE8;
			ulSpecialDataSize = 1;
#endif	
		}
		else if (2 == osInfo.dwMinorVersion)
		{
			// Win8
#ifdef _WIN64
			// 64 λ

#else
			// 32 λ

#endif
		}
		else if (3 == osInfo.dwMinorVersion)
		{
			// Win8.1
#ifdef _WIN64
			// 64 λ
			// E9
			pSpecialData[0] = 0xE9;
			ulSpecialDataSize = 1;
#else
			// 32 λ
			// E8
			pSpecialData[0] = 0xE8;
			ulSpecialDataSize = 1;
#endif			
		}
	}
	else if (10 == osInfo.dwMajorVersion)
	{
		// Win10
#ifdef _WIN64
		// 64 λ
		// E9
		pSpecialData[0] = 0xE9;
		ulSpecialDataSize = 1;
#else
		// 32 λ
		// E8
		pSpecialData[0] = 0xE8;
		ulSpecialDataSize = 1;
#endif
	}

	// �����������ȡ��ַ
	pPspTerminateThreadByPointerAddress = SearchPspTerminateThreadByPointer(pSpecialData, ulSpecialDataSize);
	return pPspTerminateThreadByPointerAddress;
}


// �����������ȡ PspTerminateThreadByPointer �����ַ
PVOID SearchPspTerminateThreadByPointer(PUCHAR pSpecialData, ULONG ulSpecialDataSize)
{
	UNICODE_STRING ustrFuncName;
	PVOID pAddress = NULL;
	LONG lOffset = 0;
	PVOID pPsTerminateSystemThread = NULL;
	PVOID pPspTerminateThreadByPointer = NULL;

	// �Ȼ�ȡ PsTerminateSystemThread ������ַ
	RtlInitUnicodeString(&ustrFuncName, L"PsTerminateSystemThread");
	pPsTerminateSystemThread = MmGetSystemRoutineAddress(&ustrFuncName);
	if (NULL == pPsTerminateSystemThread)
	{
		ShowError("MmGetSystemRoutineAddress", 0);
		return pPspTerminateThreadByPointer;
	}

	// Ȼ��, ���� PspTerminateThreadByPointer ������ַ
	pAddress = SearchMemory(pPsTerminateSystemThread,
		(PVOID)((PUCHAR)pPsTerminateSystemThread + 0xFF),
		pSpecialData, ulSpecialDataSize);
	if (NULL == pAddress)
	{
		ShowError("SearchMemory", 0);
		return pPspTerminateThreadByPointer;
	}

	// �Ȼ�ȡƫ��, �ټ����ַ
	lOffset = *(PLONG)pAddress;
	pPspTerminateThreadByPointer = (PVOID)((PUCHAR)pAddress + sizeof(LONG) + lOffset);

	return pPspTerminateThreadByPointer;
}


// ָ���ڴ������������ɨ��
PVOID SearchMemory(PVOID pStartAddress, PVOID pEndAddress, PUCHAR pMemoryData, ULONG ulMemoryDataSize)
{
	PVOID pAddress = NULL;
	PUCHAR i = NULL;
	ULONG m = 0;

	// ɨ���ڴ�
	for (i = (PUCHAR)pStartAddress; i < (PUCHAR)pEndAddress; i++)
	{
		// �ж�������
		for (m = 0; m < ulMemoryDataSize; m++)
		{
			if (*(PUCHAR)(i + m) != pMemoryData[m])
			{
				break;
			}
		}
		// �ж��Ƿ��ҵ�����������ĵ�ַ
		if (m >= ulMemoryDataSize)
		{
			// �ҵ�������λ��, ��ȡ���������������һ��ַ
			pAddress = (PVOID)(i + ulMemoryDataSize);
			break;
		}
	}

	return pAddress;
}