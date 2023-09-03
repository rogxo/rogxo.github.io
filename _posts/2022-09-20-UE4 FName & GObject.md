FName就是NamePoolData
GObject就是GUObjectArray

```C
__int64 __fastcall FName::GetPlainNameString(_DWORD *a1, __int64 a2)
{
  __int64 v3; // rbx
  RTL_SRWLOCK *v4; // r8
  int v6; // [rsp+34h] [rbp+Ch]

  v3 = HIWORD(*a1);
  v6 = (unsigned __int16)*a1;
  if ( byte_148D8736C )
  {
    v4 = &stru_148D9B9C0;
  }
  else
  {
    v4 = (RTL_SRWLOCK *)FNamePool::FNamePool((FNamePool *)&stru_148D9B9C0);	//NamePoolData
    byte_148D8736C = 1;
  }
  FNameEntry::GetPlainNameString((char *)v4[v3 + 2].Ptr + (unsigned int)(2 * v6), a2);
  return a2;
}


void UObjectBaseInit(void)
{
  unsigned int v0; // ecx
  char v1; // bl
  ......

  if ( *((int *)CpuChannel + 6) < 0 )
  {
    v0 = dword_148DBD114;
  }
  else
  {
    ......
  }  
  ......

  GUObjectAllocator = v13;
  qword_148DBCD48 = (__int64)FMemory::MallocPersistentAuxiliary(v13, 0);
  qword_148DBCD50 = qword_148DBCD48;
  qword_148DBCD58 = qword_148DBCD48;
  FUObjectArray::AllocateObjectPool((FUObjectArray *)&GUObjectArray, v14, v12, v11);	//An instance of FUObjectArray
  InitAsyncThread();
  byte_148DBCFC8 = 1;
  sub_142058840();
  FScopedBootTiming::~FScopedBootTiming((FScopedBootTiming *)v10);
  if ( v1 )
    FCpuProfilerTrace::OutputEndEvent();
}
```

GUObjectArray是FUObjectArray的一个实例化对象 `GetPlainNameString`
其结构为

```c
class COREUOBJECT_API FUObjectArray
{
public:
    ......
private:
    typedef FChunkedFixedUObjectArray TUObjectArray;
    int32 ObjFirstGCIndex;
    int32 ObjLastNonGCIndex;
    int32 MaxObjectsNotConsideredByGC;
    bool OpenForDisregardForGC;
    /** Array of all live objects.*/
    TUObjectArray ObjObjects;
    FCriticalSection ObjObjectsCritical;
    TLockFreePointerListUnordered<int32, PLATFORM_CACHE_LINE_SIZE> ObjAvailableList;
#if UE_GC_TRACK_OBJ_AVAILABLE
    FThreadSafeCounter ObjAvailableCount;
#endif
};
```

NamePoolData是FNamePool的一个实例化对象
其结构为

```c
struct FNameEntryAllocator{
    mutable PVOID Lock;
    unsigned int CurrentBlock;
    unsigned int CurrentByCursor;
    PVOID Blocks[FNameMaxBlocks];
}

struct FNamePool{
    FNameEntryAllocator Entires;
    ...
}

//这里Blocks，可以理解为每个NamePool的一个块。在该块中，每个条目由FNameEntry构成

//FNameEntry具有以下结构。

struct FNameEntryHeader {
    USHORT bIsWide : 1;
    USHORT Len : 15;
};

struct FNameEntry {
    FNameEntryHeader Header;
    union
    {
        char	AnsiName[NAME_SIZE];
        wchar_t	WideName[NAME_SIZE];
    };
}
```