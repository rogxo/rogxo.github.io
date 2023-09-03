## R3层调试API

https://learn.microsoft.com/zh-cn/windows/win32/debug/debugging-functions

[**CheckRemoteDebuggerPresent**](https://learn.microsoft.com/zh-cn/windows/win32/api/debugapi/nf-debugapi-checkremotedebuggerpresent) 确定是否正在调试指定的进程。
[**ContinueDebugEvent**](https://learn.microsoft.com/zh-cn/windows/win32/api/debugapi/nf-debugapi-continuedebugevent) 使调试器能够继续之前报告调试事件的线程。
[**DebugActiveProcess**](https://learn.microsoft.com/zh-cn/windows/win32/api/debugapi/nf-debugapi-debugactiveprocess) 使调试器能够附加到活动进程并对其进行调试。
[**DebugActiveProcessStop**](https://learn.microsoft.com/zh-cn/windows/win32/api/debugapi/nf-debugapi-debugactiveprocessstop) 停止调试器调试指定的进程。
[**DebugBreak**](https://learn.microsoft.com/zh-cn/windows/win32/api/debugapi/nf-debugapi-debugbreak) 导致当前进程中发生断点异常。
[**DebugBreakProcess**](https://learn.microsoft.com/zh-cn/windows/desktop/api/WinBase/nf-winbase-debugbreakprocess) 导致指定进程中发生断点异常。
[**DebugSetProcessKillOnExit**](https://learn.microsoft.com/zh-cn/windows/desktop/api/WinBase/nf-winbase-debugsetprocesskillonexit) 设置在调用线程退出时要执行的操作。
[**FatalExit**](https://learn.microsoft.com/zh-cn/windows/desktop/api/WinBase/nf-winbase-fatalexit) 将执行控制转移到调试器。
[**FlushInstructionCache**](https://learn.microsoft.com/zh-cn/windows/win32/api/processthreadsapi/nf-processthreadsapi-flushinstructioncache) 刷新指定进程的指令缓存。
[**GetThreadContext**](https://learn.microsoft.com/zh-cn/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadcontext) 检索指定线程的上下文。
[**GetThreadSelectorEntry**](https://learn.microsoft.com/zh-cn/windows/desktop/api/WinBase/nf-winbase-getthreadselectorentry) 检索指定选择符和线程的描述符表条目。
[**IsDebuggerPresent**](https://learn.microsoft.com/zh-cn/windows/win32/api/debugapi/nf-debugapi-isdebuggerpresent) 确定用户模式调试器是否正在调试调用进程。
[**OutputDebugString**](https://learn.microsoft.com/zh-cn/windows/win32/api/debugapi/nf-debugapi-outputdebugstringa) 将字符串发送到调试器进行显示。
[**ReadProcessMemory**](https://learn.microsoft.com/zh-cn/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory) 从指定进程中的内存区域读取数据。
[**SetThreadContext**](https://learn.microsoft.com/zh-cn/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadcontext) 设置指定线程的上下文。
[**WaitForDebugEvent**](https://learn.microsoft.com/zh-cn/windows/win32/api/debugapi/nf-debugapi-waitfordebugevent) 等待正在调试的进程中发生调试事件。
[**WaitForDebugEventEx**](https://learn.microsoft.com/zh-cn/windows/win32/api/debugapi/nf-debugapi-waitfordebugeventex) 等待正在调试的进程中发生调试事件，并启用对 OutputDebugStringW 中的 Unicode 字符串的支持。
[**Wow64GetThreadContext**](https://learn.microsoft.com/zh-cn/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadcontext) 检索指定 WOW64 线程的上下文。
[**Wow64GetThreadSelectorEntry**](https://learn.microsoft.com/zh-cn/windows/desktop/api/WinBase/nf-winbase-wow64getthreadselectorentry) 检索指定选择器和 WOW64 线程的描述符表条目。
[**Wow64SetThreadContext**](https://learn.microsoft.com/zh-cn/windows/win32/api/wow64apiset/nf-wow64apiset-wow64setthreadcontext) 设置指定的 WOW64 线程的上下文。
[**WriteProcessMemory**](https://learn.microsoft.com/zh-cn/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory) 将数据写入指定进程中的内存区域。

## 编写调试器

https://learn.microsoft.com/zh-cn/windows/win32/debug/writing-the-debugger-s-main-loop

```C++
BOOL DebugActiveProcess(DWORD dwProcessId)
{
  HANDLE hProcess; // rax MAPDST
  int status; // edi MAPDST

  status = DbgUiConnectToDbg();
  if ( status < 0 )
    goto ERROR_HANDLE;
  hProcess = ProcessIdToHandle(dwProcessId);
  if ( !hProcess )
    return 0;
  status = DbgUiDebugActiveProcess(hProcess);
  if ( status < 0 )
  {
    NtClose(hProcess);
ERROR_HANDLE:
    BaseSetLastNTError(status);
    return 0;
  }
  NtClose(hProcess);
  return 1;
}

HANDLE ProcessIdToHandle(DWORD dwProcessId)
{
  HANDLE ProcessId; // rax
  NTSTATUS status; // eax
  struct _CLIENT_ID ClientId; // [rsp+20h] [rbp-40h] BYREF
  struct _OBJECT_ATTRIBUTES ObjectAttributes; // [rsp+30h] [rbp-30h] BYREF
  void *ProcessHandle; // [rsp+78h] [rbp+18h] MAPDST BYREF

  if ( dwProcessId == -1 )                      // INVALID_HANDLE_VALUE
    ProcessId = CsrGetProcessId();
  else
    ProcessId = (HANDLE)(int)dwProcessId;
  ProcessHandle = 0i64;
  ClientId.UniqueProcess = ProcessId;
  ClientId.UniqueThread = 0i64;
  memset(&ObjectAttributes.RootDirectory, 0, 20);
  ObjectAttributes.Length = 48;
  *(_OWORD *)&ObjectAttributes.SecurityDescriptor = 0i64;
  status = NtOpenProcess(&ProcessHandle, 0xC3Au, &ObjectAttributes, &ClientId);
  if ( status < 0 )
    BaseSetLastNTError(status);
  return ProcessHandle;
}

NTSTATUS DbgUiConnectToDbg()
{
  NTSTATUS status; // ecx
  OBJECT_ATTRIBUTES ObjectAttributes; // [rsp+20h] [rbp-38h] BYREF

  status = 0;
  if ( !NtCurrentTeb()->DbgSsReserved[1] )
  {
    // InitializeObjectAttributes() Macro
    memset(&ObjectAttributes.RootDirectory, 0, 20);
    *(_OWORD *)&ObjectAttributes.SecurityDescriptor = 0i64;
    ObjectAttributes.Length = 48;
    //创建调试对象，句柄保存在Teb->DbgSsReserved[1]
    return NtCreateDebugObject(&NtCurrentTeb()->DbgSsReserved[1], 0x1F000Fu, &ObjectAttributes, 1u);
  }
  return status;
}

NTSTATUS DbgUiDebugActiveProcess(HANDLE Process)
{
  NTSTATUS status; // ebx

  status = NtDebugActiveProcess(Process, NtCurrentTeb()->DbgSsReserved[1]);
  if ( status >= 0 )
  {
    status = DbgUiIssueRemoteBreakin(Process);	//创建线程执行int 3
    if ( status < 0 )
      ZwRemoveProcessDebug(Process, NtCurrentTeb()->DbgSsReserved[1]);
  }
  return status;
}

NTSTATUS DbgUiIssueRemoteBreakin(HANDLE Process)
{
  NTSTATUS status; // ebx
  __int64 v3; // [rsp+30h] [rbp-48h]
  _CLIENT_ID v4; // [rsp+60h] [rbp-18h] BYREF
  HANDLE Handle; // [rsp+88h] [rbp+10h] BYREF
  
  status = RtlpCreateUserThreadEx(Process, 0i64, 2u, 0, 0i64, 0x4000ui64, v3, DbgUiRemoteBreakin, 0i64, &Handle, &v4);
  if ( status >= 0 )
    NtClose(Handle);
  return status;
}
```