#ifndef _FORCE_KILL_PROCESS_H_
#define _FORCE_KILL_PROCESS_H_


#include <ntifs.h>


// ǿ�ƽ���ָ������
NTSTATUS ForceKillProcess(HANDLE hProcessId);

// ��ȡ PspTerminateThreadByPointer ������ַ
PVOID GetPspLoadImageNotifyRoutine();

// �����������ȡ PspTerminateThreadByPointer �����ַ
PVOID SearchPspTerminateThreadByPointer(PUCHAR pSpecialData, ULONG ulSpecialDataSize);

// ָ���ڴ������������ɨ��
PVOID SearchMemory(PVOID pStartAddress, PVOID pEndAddress, PUCHAR pMemoryData, ULONG ulMemoryDataSize);


#endif