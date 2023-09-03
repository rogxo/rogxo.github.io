# 内核层调试API

创建调试对象，初始化调试环境：
NtCreateDebugObject
==NtDebugActiveProcess==
==***DbgkpSetProcessDebugObject***==
DbgkpMarkProcessPeb

发送模拟消息：
DbgkpPostFakeProcessCreateMessages
DbgkpPostFakeThreadMessages

发送接收异常调试事件消息：
==***KiDispatchException***==
==***DbgkpQueueMessage***==
DbgkpSendApiMessage
~~DbgkSendSystemDllMessages~~
~~DbgkpPostModuleMessages~~
~~DbgkPostEnclaveModuleMessages~~
~~DbgkPostModuleMessage~~
***==NtWaitForDebugEvent==***
==***NtDebugContinue***==
==***DbgkForwardException***==

退出调试清理环境：
DbgkpWakeTarget
DbgkpFreeDebugEvent
==NtRemoveProcessDebug==
==***DbgkClearProcessDebugObject***==

```C++
NTSTATUS NtCreateDebugObject(
        PHANDLE DebugObjectHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        ULONG Flags)
{
  char bFlags; // si
  CHAR PreviousMode; // r10
  __int64 MmUserProbeAddress; // rcx
  NTSTATUS status; // eax
  _EWOW64PROCESS *Wow64Process; // rax
  unsigned __int16 Machine; // ax
  void *v13; // [rsp+20h] [rbp-68h]
  PDEBUG_OBJECT DebugObject; // [rsp+58h] [rbp-30h] MAPDST BYREF
  void *Handle[4]; // [rsp+60h] [rbp-28h] BYREF

  bFlags = Flags;
  Handle[0] = 0i64;
  DebugObject = 0i64;
  PreviousMode = KeGetCurrentThread()->PreviousMode;
  if ( PreviousMode )                           // KernelMode = 0,UserMode = 1
  {
    // ProbeForWriteHandle(DebugObjectHandle);
    MmUserProbeAddress = 0x7FFFFFFF0000i64;
    if ( DebugObjectHandle < 0x7FFFFFFF0000i64 )
      MmUserProbeAddress = DebugObjectHandle;
    *MmUserProbeAddress = *MmUserProbeAddress;
  }
  *DebugObjectHandle = 0i64;
  if ( (Flags & 0xFFFFFFFE) != 0 )
    return 0xC000000D;
  status = ObCreateObjectEx(PreviousMode, DbgkDebugObjectType, ObjectAttributes, 
  			PreviousMode, v13, sizeof (DEBUG_OBJECT), 0, 0, &DebugObject, 0i64);
  if ( status >= 0 )
  {
    // ExInitializeFastMutex (&DebugObject->Mutex);
    DebugObject->Mutex.Count = 1;
    DebugObject->Mutex.Owner = 0i64;
    DebugObject->Mutex.Contention = 0;
    KeInitializeEvent(&DebugObject->Mutex.Event, SynchronizationEvent, 0);
    // InitializeListHead (&DebugObject->EventList);
    DebugObject->EventList.Blink = &DebugObject->EventList;
    DebugObject->EventList.Flink = &DebugObject->EventList;
    KeInitializeEvent(&DebugObject->EventsPresent, NotificationEvent, 0);
    if ( (bFlags & 1) != 0 )                    // Flags & DEBUG_KILL_ON_CLOSE
      DebugObject->Flags = 2;                   // DEBUG_OBJECT_KILL_ON_CLOSE
    else
      DebugObject->Flags = 0;
    Wow64Process = KeGetCurrentThread()->ApcState.Process.WoW64Process;
    if ( Wow64Process )
    {
      Machine = Wow64Process->Machine;
      // #define IMAGE_FILE_MACHINE_I386 0x014c  // Intel 386.
      if ( Machine == 0x14C || Machine == 0x1C4 )
        DebugObject->Flags |= 4u;
    }
    // 把调试对象插入到调试进程的句柄表中,其中句柄的权限就是R3传入的DesriedAccess;
    status = ObInsertObjectEx(DebugObject, 0i64, DesiredAccess, 0, 0, 0i64, Handle);
    if ( status >= 0 )
      *DebugObjectHandle = Handle[0];           // Teb->DbgSsReserved[1]
  }
  return status;
}

NTSTATUS __fastcall NtDebugActiveProcess(HANDLE ProcessHandle, HANDLE DebugHandle)
{
  CHAR PreviousMode; // bp
  NTSTATUS status; // eax MAPDST
  PKTHREAD CurrentThread; // rax
  PEPROCESS CurrentProcess; // rsi
  PEWOW64PROCESS WoW64Process; // rax
  USHORT Machine; // cx
  PEWOW64PROCESS TargetWoW64Process; // rax
  USHORT TargetMachine; // cx
  NTSTATUS MsgStatus; // eax
  PETHREAD LastThread; // [rsp+40h] [rbp-28h] BYREF
  PEPROCESS TargetProcess; // [rsp+80h] [rbp+18h] MAPDST BYREF
  PDEBUG_OBJECT DebugObject; // [rsp+88h] [rbp+20h] MAPDST BYREF

  TargetProcess = 0i64;
  PreviousMode = KeGetCurrentThread()->PreviousMode;
  LastThread = 0i64;
  status = ObReferenceObjectByHandleWithTag(
             ProcessHandle,
             0x800u,                            // PROCESS_SET_PORT
             PsProcessType,
             PreviousMode,
             'OgbD',
             &TargetProcess,
             0i64);
  if ( status >= 0 )
  {
    CurrentThread = KeGetCurrentThread();
    CurrentProcess = CurrentThread->ApcState.Process;// PsGetCurrentProcess()
    if ( TargetProcess == CurrentProcess || TargetProcess == PsInitialSystemProcess )
    {
      status = 0xC0000022;                      // STATUS_ACCESS_DENIED
    }
    else if ( PsTestProtectedProcessIncompatibility(PreviousMode, CurrentThread->ApcState.Process, TargetProcess) )
    {
      status = 0xC0000712;                      // STATUS_PROCESS_IS_PROTECTED
    }
    else if ( (TargetProcess->Pcb.SecureState.SecureHandle & 1) == 0
           || (status = PsRequestDebugSecureProcess(TargetProcess, 1u), status >= 0) )
    {
      WoW64Process = CurrentProcess->WoW64Process;
      if ( !WoW64Process
        || (Machine = WoW64Process->Machine, Machine != 0x14C) && Machine != 0x1C4
        || (TargetWoW64Process = TargetProcess->WoW64Process) != 0i64
        && ((TargetMachine = TargetWoW64Process->Machine, TargetMachine == 0x14C) || TargetMachine == 0x1C4) )
      {
        DebugObject = 0i64;
        status = ObReferenceObjectByHandle(DebugHandle, 2u, DbgkDebugObjectType, PreviousMode, &DebugObject, 0i64);
        if ( status >= 0 )
        {
          if ( ExAcquireRundownProtection_0(&TargetProcess->RundownProtect) )
          {
            MsgStatus = DbgkpPostFakeProcessCreateMessages(TargetProcess, DebugObject, &LastThread);
            status = DbgkpSetProcessDebugObject(TargetProcess, DebugObject, MsgStatus, LastThread);
            ExReleaseRundownProtection_0(&TargetProcess->RundownProtect);
          }
          else
          {
            status = 0xC000010A;                // STATUS_PROCESS_IS_TERMINATING
          }
          // ObfDereferenceObjectWithTag（DebugObject）
          HalPutDmaAdapter(DebugObject);
        }
      }
      else
      {
        status = 0xC00000BB;                    // STATUS_NOT_SUPPORTED
      }
    }
    ObfDereferenceObjectWithTag(TargetProcess, 'OgbD');
  }
  return status;
}

NTSTATUS __stdcall DbgkpPostFakeProcessCreateMessages(
        PEPROCESS Process,
        PDEBUG_OBJECT DebugObject,
        PETHREAD *pLastThread)
{
  NTSTATUS status; // eax
  PETHREAD FirstThread; // [rsp+30h] [rbp-68h] BYREF
  PETHREAD LastThread; // [rsp+38h] [rbp-60h] MAPDST BYREF
  KAPC_STATE ApcState; // [rsp+40h] [rbp-58h] BYREF

  // This routine posts the faked initial process create, thread create and mudule load messages
  // 调试假消息的意义在于附加时进程已经创建,无法还原线程进程创建时场景
  // 因此采取模拟发送假消息方式进行折中,还原进程刚创建时的调试信息不会遗漏。
  LastThread = 0i64;
  FirstThread = 0i64;
  memset(&ApcState, 0, sizeof(ApcState));
  LastThread = 0i64;
  status = DbgkpPostFakeThreadMessages(Process, DebugObject, 0i64, &FirstThread, &LastThread);
  if ( status >= 0 )
  {
    KiStackAttachProcess(Process, 0, &ApcState);
    DbgkpPostModuleMessages(Process, FirstThread, &DebugObject->EventsPresent);
    KiUnstackDetachProcess(&ApcState, 0i64);
    ObfDereferenceObjectWithTag(FirstThread, 'OgbD');
    status = 0;
  }
  *pLastThread = LastThread;
  return status;
}

NTSTATUS __stdcall DbgkpPostFakeThreadMessages(
        PEPROCESS Process,
        PDEBUG_OBJECT DebugObject,
        PETHREAD StartThread,
        PETHREAD *pFirstThread,
        PETHREAD *pLastThread)
{
  struct _ETHREAD *FirstThread; // r15
  PETHREAD v9; // rdi
  int status; // r12d
  bool v11; // r13
  ULONG v12; // esi
  char v13; // r13
  void *SectionObject; // rcx
  __int64 v15; // rax
  bool v17; // [rsp+30h] [rbp-1E8h]
  struct _ETHREAD *CurrentThread; // [rsp+68h] [rbp-1B0h]
  struct _DBGKM_APIMSG ApiMsg; // [rsp+90h] [rbp-188h] BYREF
  struct _KAPC_STATE ApcState; // [rsp+1A0h] [rbp-78h] BYREF

  memset(&ApcState, 0, sizeof(ApcState));
  memset(&ApiMsg, 0, sizeof(ApiMsg));
  FirstThread = 0i64;
  v9 = 0i64;
  CurrentThread = KeGetCurrentThread();
  status = 0xC0000001;
  if ( StartThread )
  {
    FirstThread = StartThread;
    ObfReferenceObjectWithTag(StartThread, 'OgbD');
  }
  else
  {
    StartThread = PsGetNextProcessThread(Process, 0i64);
  }
  v11 = StartThread == 0i64;
  v17 = StartThread == 0i64;
  while ( StartThread )
  {
    if ( v9 )
      ObfDereferenceObjectWithTag(v9, 'OgbD');
    v9 = StartThread;
    ObfReferenceObjectWithTag(StartThread, 'OgbD');
    if ( (StartThread->Tcb.MiscFlags & 0x400) == 0 )
    {
      if ( (StartThread->CrossThreadFlags & 2) != 0
        || (PsSynchronizeWithThreadInsertion(StartThread, CurrentThread), (StartThread->CrossThreadFlags & 2) != 0) )
      {
        if ( ExAcquireRundownProtection_0(&StartThread->RundownProtect) )
        {
          v12 = 0xA;
          if ( PsSuspendThread(StartThread, 0i64) >= 0 )
            v12 = 0x2A;
        }
        else
        {
          v12 = 0x12;
        }
        memset(&ApiMsg, 0, sizeof(ApiMsg));
        if ( !v11 || (v12 & 0x10) != 0 )
        {
          v13 = 0;
          ApiMsg.ApiNumber = DbgKmCreateThreadApi;
          ApiMsg.u.Exception.ExceptionRecord.FileHandle = StartThread->Win32StartAddress;// StartAddress
        }
        else
        {
          v13 = 1;
          ApiMsg.ApiNumber = DbgKmCreateProcessApi;
          SectionObject = Process->SectionObject;
          if ( SectionObject )
            ApiMsg.u.Exception.ExceptionRecord.FileHandle = DbgkpSectionToFileHandle(SectionObject);
          else
            ApiMsg.u.Exception.ExceptionRecord.FileHandle = 0i64;
          ApiMsg.u.Exception.ExceptionRecord.BaseOfImage = Process->SectionBaseAddress;
          KeStackAttachProcess(&Process->Pcb, &ApcState);
          v15 = RtlImageNtHeader(Process->SectionBaseAddress);
          if ( v15 )
          {
            ApiMsg.u.ErrorMsg.ExceptionRecord.ExceptionInformation[1] = 0i64;
            ApiMsg.u.LoadDll.NamePointer = *(v15 + 12);
          }
          KeUnstackDetachProcess(&ApcState);
        }
        status = DbgkpQueueMessage(Process, StartThread, &ApiMsg, v12, DebugObject);
        if ( status < 0 )
        {
          if ( (v12 & 0x20) != 0 )
            PsResumeThread(StartThread, 0i64);
          if ( (v12 & 8) != 0 )
            ExReleaseRundownProtection_0(&StartThread->RundownProtect);
          if ( ApiMsg.ApiNumber == DbgKmCreateProcessApi && ApiMsg.u.Exception.ExceptionRecord.FileHandle )
            ObCloseHandle(ApiMsg.u.Exception.ExceptionRecord.FileHandle, 0);
          PsQuitNextProcessThread(StartThread);
          break;
        }
        if ( v13 )
        {
          v11 = 0;
          v17 = 0;
          ObfReferenceObjectWithTag(StartThread, 'OgbD');
          FirstThread = StartThread;
          DbgkSendSystemDllMessages(StartThread, DebugObject, &ApiMsg);
        }
        else
        {
          v11 = v17;
        }
      }
    }
    StartThread = PsGetNextProcessThread(Process, StartThread);
  }
  if ( status >= 0 )
  {
    if ( FirstThread )
    {
      *pFirstThread = FirstThread;
      *pLastThread = v9;
    }
    else
    {
      if ( v9 )
        ObfDereferenceObjectWithTag(v9, 'OgbD');
      return 0xC0000001;
    }
  }
  else
  {
    if ( FirstThread )
      ObfDereferenceObjectWithTag(FirstThread, 'OgbD');
    if ( v9 )
      ObfDereferenceObjectWithTag(v9, 'OgbD');
  }
  return status;
}

HANDLE __stdcall DbgkpSectionToFileHandle(PVOID SectionObject)
{
  POBJECT_NAME_INFORMATION v1; // rdi
  NTSTATUS v2; // ebx
  struct _IO_STATUS_BLOCK IoStatusBlock; // [rsp+30h] [rbp-40h] BYREF
  OBJECT_ATTRIBUTES ObjectAttributes; // [rsp+40h] [rbp-30h] BYREF
  POBJECT_NAME_INFORMATION FileNameInfo; // [rsp+88h] [rbp+18h] BYREF
  HANDLE FileHandle; // [rsp+90h] [rbp+20h] BYREF

  *(&ObjectAttributes.Length + 1) = 0;
  *(&ObjectAttributes.Attributes + 1) = 0;
  FileHandle = 0i64;
  FileNameInfo = 0i64;
  IoStatusBlock = 0i64;
  if ( MmGetFileNameForSection(SectionObject, &FileNameInfo) < 0 )
    return 0i64;
  v1 = FileNameInfo;
  ObjectAttributes.RootDirectory = 0i64;
  ObjectAttributes.ObjectName = &FileNameInfo->Name;
  ObjectAttributes.Length = 48;
  *&ObjectAttributes.SecurityDescriptor = 0i64;
  ObjectAttributes.Attributes = 1600;
  v2 = ZwOpenFile(&FileHandle, 0x80100000, &ObjectAttributes, &IoStatusBlock, 7u, 0x20u);
  ExFreePoolWithTag(v1, 0);
  if ( v2 < 0 )
    return 0i64;
  else
    return FileHandle;
}

void __fastcall DbgkSendSystemDllMessages(PETHREAD Thread, PDEBUG_OBJECT DebugObject, PDBGKM_APIMSG ApiMsg)
{
  struct _EPROCESS *Process; // r15
  union _DBGKM_APIMSG::$1C0BB51BD40DD7F329A455188E31308E *ApiMsgUnionData; // rsi
  int i; // r14d
  PPS_SYSTEM_DLL_INFO SystemDllInfo; // rax MAPDST
  __int64 BaseAddress; // r13
  PIMAGE_NT_HEADERS NtHeader; // rax
  struct _KTHREAD *CurrentThread; // rcx
  char v13; // [rsp+30h] [rbp-108h]
  PTEB Teb; // [rsp+38h] [rbp-100h]
  OBJECT_ATTRIBUTES ObjectAttributes; // [rsp+88h] [rbp-B0h] BYREF
  struct _IO_STATUS_BLOCK IoStatusBlock; // [rsp+B8h] [rbp-80h] BYREF
  struct _KAPC_STATE ApcState; // [rsp+C8h] [rbp-70h] BYREF

  memset(&ApcState, 0, sizeof(ApcState));
  IoStatusBlock = 0i64;
  memset(&ObjectAttributes, 0, sizeof(ObjectAttributes));
  if ( Thread )
    Process = Thread->Tcb.Process;
  else
    Process = KeGetCurrentThread()->ApcState.Process;
  ApiMsgUnionData = &ApiMsg->u;
  for ( i = 0; i < 6; ++i )
  {
    SystemDllInfo = PsQuerySystemDllInfo(i);
    if ( SystemDllInfo
      && (i <= 0 || *(&SystemDllInfo->1 + 1) && Process->WoW64Process && i == PsWow64GetProcessNtdllType(Process)) )
    {
      *&ApiMsgUnionData->Exception.ExceptionRecord.SubSystemKey = 0i64;
      *&ApiMsgUnionData->ErrorMsg.ExceptionRecord.ExceptionAddress = 0i64;
      Teb = 0i64;
      BaseAddress = SystemDllInfo->BaseAddress;
      ApiMsgUnionData->Exception.ExceptionRecord.FileHandle = BaseAddress;
      if ( Thread && i )
      {
        v13 = 1;
        KiStackAttachProcess(Process, 0, &ApcState);
      }
      else
      {
        v13 = 0;
      }
      NtHeader = RtlImageNtHeader(BaseAddress);
      if ( NtHeader )
      {
        ApiMsgUnionData->LoadDll.DebugInfoFileOffset = NtHeader->FileHeader.PointerToSymbolTable;
        ApiMsgUnionData->LoadDll.DebugInfoSize = NtHeader->FileHeader.NumberOfSymbols;
      }
      if ( !Thread )
      {
        CurrentThread = KeGetCurrentThread();
        if ( (CurrentThread->MiscFlags & 0x400) != 0 || CurrentThread->ApcStateIndex == 1 )
          Teb = 0i64;
        else
          Teb = CurrentThread->Teb;
        if ( Teb )
        {
          RtlStringCbCopyW(Teb->StaticUnicodeBuffer, 0x20Aui64, *&SystemDllInfo[1].Flags);
          Teb->NtTib.ArbitraryUserPointer = Teb->StaticUnicodeBuffer;
          ApiMsgUnionData->LoadDll.NamePointer = &Teb->NtTib.ArbitraryUserPointer;
        }
      }
      if ( v13 )
        KiUnstackDetachProcess(&ApcState, 0i64);
      ObjectAttributes.Length = 48;
      ObjectAttributes.RootDirectory = 0i64;
      ObjectAttributes.Attributes = 1600;
      ObjectAttributes.ObjectName = &SystemDllInfo->DllPath;
      *&ObjectAttributes.SecurityDescriptor = 0i64;
      if ( ZwOpenFile(ApiMsgUnionData, 0x80100000, &ObjectAttributes, &IoStatusBlock, 7u, 0x20u) < 0 )
        ApiMsgUnionData->LoadDll.FileHandle = 0i64;
      ApiMsg->h.u1.Length = 5242920;
      ApiMsg->h.u2.ZeroInit = 8;
      ApiMsg->ApiNumber = DbgKmLoadDllApi;
      if ( Thread )
      {
        if ( DbgkpQueueMessage(Process, Thread, ApiMsg, 2u, DebugObject) < 0 && ApiMsgUnionData->LoadDll.FileHandle )
          ObCloseHandle(ApiMsgUnionData->LoadDll.FileHandle, 0);
      }
      else
      {
        DbgkpSendApiMessage(Process);
        if ( ApiMsgUnionData->LoadDll.FileHandle )
          ObCloseHandle(ApiMsgUnionData->LoadDll.FileHandle, 0);
        if ( Teb )
          Teb->NtTib.ArbitraryUserPointer = 0i64;
      }
    }
  }
}
```