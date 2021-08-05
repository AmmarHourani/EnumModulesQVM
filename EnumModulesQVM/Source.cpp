
#include <iostream>
#include <windows.h>

#pragma region definitions
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define NT_INFORMATION(Status) ((((ULONG)(Status)) >> 30) == 1)
#define NT_WARNING(Status) ((((ULONG)(Status)) >> 30) == 2)
#define NT_ERROR(Status) ((((ULONG)(Status)) >> 30) == 3)
#define NT_FAIL(Status) ((NTSTATUS)(Status) < 0)

typedef enum _MEMORY_INFORMATION_CLASS
{
    MemoryBasicInformation, // MEMORY_BASIC_INFORMATION
    MemoryWorkingSetInformation, // MEMORY_WORKING_SET_INFORMATION
    MemoryMappedFilenameInformation, // UNICODE_STRING
    MemoryRegionInformation, // MEMORY_REGION_INFORMATION
    MemoryWorkingSetExInformation, // MEMORY_WORKING_SET_EX_INFORMATION
    MemorySharedCommitInformation, // MEMORY_SHARED_COMMIT_INFORMATION
    MemoryImageInformation, // MEMORY_IMAGE_INFORMATION
    MemoryRegionInformationEx, // MEMORY_REGION_INFORMATION
    MemoryPrivilegedBasicInformation,
    MemoryEnclaveImageInformation, // MEMORY_ENCLAVE_IMAGE_INFORMATION // since REDSTONE3
    MemoryBasicInformationCapped, // 10
    MemoryPhysicalContiguityInformation, // MEMORY_PHYSICAL_CONTIGUITY_INFORMATION // since 20H1
    MaxMemoryInfoClass
} MEMORY_INFORMATION_CLASS;

#pragma comment(lib, "ntdll.lib")
extern "C" NTSTATUS DECLSPEC_IMPORT NTAPI NtQueryVirtualMemory(HANDLE, PVOID, MEMORY_INFORMATION_CLASS, PVOID, SIZE_T, PSIZE_T);

struct SECTION_INFO
{
    WORD Len;
    WORD MaxLen;
    wchar_t* szData;
    BYTE pData[MAX_PATH * 2];
};



#pragma endregion

UINT EnumModulesQVM(HANDLE hProc)
{
    UINT Count = 0;

    MEMORY_BASIC_INFORMATION MBI{ 0 };

    while (NT_SUCCESS(NtQueryVirtualMemory(hProc, MBI.BaseAddress, MemoryBasicInformation, &MBI, sizeof(MEMORY_BASIC_INFORMATION), nullptr)))
    {
        if (!(MBI.State & MEM_COMMIT))
        {
            MBI.BaseAddress = reinterpret_cast<BYTE*>(MBI.BaseAddress) + MBI.RegionSize;
            continue;
        }

        SECTION_INFO section_info;
        if (NT_FAIL(NtQueryVirtualMemory(hProc, MBI.BaseAddress, MemoryMappedFilenameInformation, &section_info, sizeof(SECTION_INFO), nullptr)))
        {
            MBI.BaseAddress = reinterpret_cast<BYTE*>(MBI.BaseAddress) + MBI.RegionSize;
            continue;
        }

        void* hDll = MBI.BaseAddress;
        SIZE_T SizeOfImage = MBI.RegionSize;
        MBI.BaseAddress = reinterpret_cast<BYTE*>(MBI.BaseAddress) + MBI.RegionSize;

        while (NT_SUCCESS(NtQueryVirtualMemory(hProc, MBI.BaseAddress, MemoryBasicInformation, &MBI, sizeof(MEMORY_BASIC_INFORMATION), nullptr)))
        {
            SECTION_INFO section_info2;
            if (NT_FAIL(NtQueryVirtualMemory(hProc, MBI.BaseAddress, MemoryMappedFilenameInformation, &section_info2, sizeof(SECTION_INFO), nullptr)))
                break;

            if (wcscmp(section_info.szData, section_info2.szData))
                break;

            MBI.BaseAddress = reinterpret_cast<BYTE*>(MBI.BaseAddress) + MBI.RegionSize;
            SizeOfImage += MBI.RegionSize;
        }

        Count++;

        wchar_t* pDllName = &section_info.szData[section_info.Len / sizeof(wchar_t) - 1];
        while (*(pDllName-- - 2) != '\\'); //grab module name
        wprintf_s(L"%u: %-20ls\t    Base: 0x%p\t    Size: 0x%08X\t\n", Count, pDllName, hDll, SizeOfImage);
    }
    return Count;
}

int main()
{
    std::cout << "Enter the target process Id:  \n";
    
    int procID;
    std::cin >> procID;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, procID);
    printf("%p", hProcess);
    EnumModulesQVM(hProcess);
    CloseHandle(hProcess);
    system("pause");

}