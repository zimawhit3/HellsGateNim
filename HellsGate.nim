include custom
import strutils
import os
import strformat

{.passC:"-masm=intel".}

var syscall*  : WORD
type
    HG_TABLE_ENTRY* = object
        pAddress*    : PVOID
        dwHash*      : uint64
        wSysCall*    : WORD
    PHG_TABLE_ENTRY* = ptr HG_TABLE_ENTRY

proc djb2_hash*(pFuncName : string) : uint64 =

    var hash : uint64 = 0x5381

    for c in pFuncName:
        hash = ((hash shl 0x05) + hash) + cast[uint64](ord(c))

    return hash

proc moduleToBuffer*(pCurrentModule : PLDR_DATA_TABLE_ENTRY) : PWSTR =
    return pCurrentModule.FullDllName.Buffer

proc flinkToModule*(pCurrentFlink : LIST_ENTRY) : PLDR_DATA_TABLE_ENTRY =
    return cast[PLDR_DATA_TABLE_ENTRY](cast[ByteAddress](pCurrentFlink) - 0x10)

proc getExportTable*(pCurrentModule : PLDR_DATA_TABLE_ENTRY, pExportTable : var PIMAGE_EXPORT_DIRECTORY) : bool =

    let 
        pImageBase : PVOID              = pCurrentModule.DLLBase
        pDosHeader : PIMAGE_DOS_HEADER  = cast[PIMAGE_DOS_HEADER](pImageBase)
        pNTHeader : PIMAGE_NT_HEADERS = cast[PIMAGE_NT_HEADERS](cast[ByteAddress](pDosHeader) + pDosHeader.e_lfanew)

    if pDosheader.e_magic != IMAGE_DOS_SIGNATURE:
        return false

    if pNTHeader.Signature != cast[DWORD](IMAGE_NT_SIGNATURE):
        return false

    pExportTable = cast[PIMAGE_EXPORT_DIRECTORY](cast[ByteAddress](pImageBase) + pNTHeader.OptionalHeader.DataDirectory[0].VirtualAddress)

    return true

proc getTableEntry*(pImageBase : PVOID, pCurrentExportDirectory : PIMAGE_EXPORT_DIRECTORY, tableEntry : var HG_TABLE_ENTRY) : bool =

    var 
        cx : DWORD = 0
        numFuncs : DWORD = pCurrentExportDirectory.NumberOfNames
    let 
        pAddrOfFunctions    : ptr UncheckedArray[DWORD] = cast[ptr UncheckedArray[DWORD]](cast[ByteAddress](pImageBase) + pCurrentExportDirectory.AddressOfFunctions)
        pAddrOfNames        : ptr UncheckedArray[DWORD] = cast[ptr UncheckedArray[DWORD]](cast[ByteAddress](pImageBase) + pCurrentExportDirectory.AddressOfNames)
        pAddrOfOrdinals     : ptr UncheckedArray[WORD]  = cast[ptr UncheckedArray[WORD]](cast[ByteAddress](pImageBase) + pCurrentExportDirectory.AddressOfNameOrdinals)

    while cx < numFuncs:    
        var 
            pFuncOrdinal    : WORD      = pAddrOfOrdinals[cx]
            pFuncName       : string    = $(cast[PCHAR](cast[ByteAddress](pImageBase) + pAddrOfNames[cx]))
            funcHash        : uint64    = djb2_hash(pFuncName)
            funcRVA         : DWORD64   = pAddrOfFunctions[pFuncOrdinal]
            pFuncAddr       : PVOID     = cast[PVOID](cast[ByteAddress](pImageBase) + funcRVA)
        
        if funcHash == tableEntry.dwHash:

            tableEntry.pAddress = pFuncAddr
            if cast[PBYTE](cast[ByteAddress](pFuncAddr) + 3)[] == 0xB8:
                tableEntry.wSysCall = cast[PWORD](cast[ByteAddress](pFuncAddr) + 4)[]

            return true
        inc cx
    return false

proc GetPEBAsm64*(): PPEB {.asmNoStackFrame.} =
    asm """
        mov rax, qword ptr gs:[0x60]
        ret
    """

proc getNextModule*(flink : var LIST_ENTRY) : PLDR_DATA_TABLE_ENTRY =
    flink = flink.Flink[]
    return flinkToModule(flink)

proc searchLoadedModules*(pCurrentPeb : PPEB, tableEntry : var HG_TABLE_ENTRY) : bool =
    var 
        currFlink       : LIST_ENTRY                = pCurrentPeb.Ldr.InMemoryOrderModuleList.Flink[]
        currModule      : PLDR_DATA_TABLE_ENTRY     = flinkToModule(currFlink)                 
        moduleName      : string
        pExportTable    : PIMAGE_EXPORT_DIRECTORY
    let 
        beginModule = currModule
    
    while true:

        moduleName = $moduleToBuffer(currModule)

        if moduleName.len() == 0 or moduleName in paramStr(0):            
            currModule = getNextModule(currFlink)
            if beginModule == currModule:
                break
            continue

        if not getExportTable(currModule, pExportTable):
            echo "[-] Failed to get export table..."
            return false

        if getTableEntry(currModule.DLLBase, pExportTable, tableEntry):
            return true
        
        currModule = getNextModule(currFlink)
        if beginModule == currModule:
            break
    return false

proc getSyscall*(tableEntry : var HG_TABLE_ENTRY) : bool =
    
    let currentPeb  : PPEB = GetPEBAsm64()
       
    if not searchLoadedModules(currentPeb, tableEntry):
        return false

    return true

proc NtAllocateVirtualMemory(ProcessHandle: HANDLE, BaseAddress: var PVOID, ZeroBits: ULONG, RegionSize: PSIZE_T, AllocationType: ULONG, Protect: ULONG): NTSTATUS {.asmNoStackFrame.} =
    asm """
        mov r10, rcx
        mov eax, `syscall`
        syscall
        ret
    """




when isMainModule:
    
    when defined(amd64):
        echo fmt"[i] Hell's Gate - A quick Nim implementation example"
        
        if paramCount() != 0:
            echo fmt"[!] Usage: .\Hellsgate.exe"
        else:
            var 
                funcHash        : uint64            = djb2_hash("NtAllocateVirtualMemory")
                example         : HG_TABLE_ENTRY    = HG_TABLE_ENTRY(dwHash : funcHash)
                status          : NTSTATUS          = 0x00000000
                buffer          : LPVOID            = NULL
                dataSz          : SIZE_T            = sizeof(0x1000)      
            if getSyscall(example):
                
                echo fmt"[+] NtAllocateVirtualMemory"
                echo fmt"    Opcode  : {toHex(example.wSyscall)}"
                echo fmt"    Address : 0x{toHex(cast[ByteAddress](example.pAddress))}"
                echo fmt"    Hash    : {toHex(example.dwHash)}"

                echo fmt"[+] Calling NtAllocateVirtualMemory"

                
                syscall = example.wSysCall
                status = NtAllocateVirtualMemory(cast[HANDLE](-1), buffer, 0, &dataSz, MEM_COMMIT, PAGE_READWRITE)
                
                echo fmt"[i] Status: 0x{toHex(status)}"
                if not NT_SUCCESS(status):
                    echo fmt"[-] Failed to allocate memory."
                else:
                    echo fmt"[+] Allocated a page of memory with RW perms at 0x{toHex(cast[ByteAddress](buffer))}"
            else:
                echo fmt"[-] Failed to find opcode for NtAllocateVirtualMemory"
