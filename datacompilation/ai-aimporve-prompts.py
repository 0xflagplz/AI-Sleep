import json
import re
from openai import OpenAI

# Set up local LM Studio endpoint
client = OpenAI(base_url="http://192.168.0.210:443/v1", api_key="lm-studio")

def parse_and_format_entries(raw_entries):
    formatted_entries = []

    # Split raw entries by newlines and filter out empty lines
    for line in (l for l in raw_entries.splitlines() if l.strip()):
        try:
            # Parse the line as JSON and unescape the response
            entry = json.loads(line)
            instructions = entry["instructions"]
            response = entry["response"].replace('\\n', '\n')

            # Send instructions to the model for improvement
            completion = client.chat.completions.create(
                model="lmstudio-community/Meta-Llama-3.1-8B-Instruct-GGUF",
                messages=[
                    {"role": "system", "content": "Improve the prompt for clarity and effectiveness. Do not alter the code content in the response. Format the entire entry for JSONL, escaping special characters as needed."},
                    {"role": "user", "content": instructions}
                ],
                temperature=0.7,
            )
            
            # Get improved instructions from the response
            improved_instructions = completion.choices[0].message["content"].strip()

            # Re-escape newlines and other special characters for JSON
            escaped_response = json.dumps(response)[1:-1]

            # Structure the formatted JSON object
            formatted_entry = {
                "instructions": improved_instructions,
                "response": escaped_response
            }
            
            # Append the formatted entry as a JSON string
            formatted_entries.append(json.dumps(formatted_entry))

        except Exception as e:
            print(f"Error processing entry: {e}")
            continue

    return formatted_entries

# Sample raw entries as multi-line string input
raw_entries = """
{"instructions": "How can I implement AES Decryption Using The Tiny-AES Library", "response": "```c \n#include "TinyAES.h"\n#include <windows.h>\n#include <stdio.h>\nBOOL InstallAesDecryptionViaTinyAes(IN PBYTE pCipherTextBuffer, IN SIZE_T sCipherTextSize, IN PBYTE pAesKey, IN PBYTE pAesIv) {\n\n    struct  AES_ctx AesCtx = { 0x00 };\n\n    if (!pCipherTextBuffer || !sCipherTextSize || !pAesKey || !pAesIv)\n        return FALSE;\n\n    RtlSecureZeroMemory(&AesCtx, sizeof(AesCtx));\n    AES_init_ctx_iv(&AesCtx, pAesKey, pAesIv);\n    AES_CBC_decrypt_buffer(&AesCtx, pCipherTextBuffer, sCipherTextSize);\n\n    return TRUE;\n}\n```"}
{"instructions": "How can I implement AES Encryption Using The Tiny-AES Library", "response": "```c \n#include "TinyAES.h"\n#include <windows.h>\n#include <stdio.h>\nBOOL InstallAesEncryptionViaTinyAes(IN PBYTE pRawDataBuffer, IN SIZE_T sRawBufferSize, IN PBYTE pAesKey, IN PBYTE pAesIv, OUT PBYTE* ppCipherTextBuffer, OUT SIZE_T* psCipherTextSize) {\n\n    if (!pRawDataBuffer || !sRawBufferSize || !pAesKey || !pAesIv || !ppCipherTextBuffer || !psCipherTextSize)\n        return FALSE;\n\n    PBYTE   pNewBuffer      = pRawDataBuffer;\n    SIZE_T  sNewBufferSize  = sRawBufferSize;\n    struct  AES_ctx AesCtx  = { 0x00 };\n\n    if (sRawBufferSize % 16 != 0x00) {\n\n        sNewBufferSize      = sRawBufferSize + 16 - (sRawBufferSize % 16);\n        pNewBuffer          = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sNewBufferSize);\n\n        if (!pNewBuffer) {\n            printf("[!] HeapAlloc Failed With Error: %d \n", GetLastError());\n            return FALSE;\n        }\n\n        memcpy(pNewBuffer, pRawDataBuffer, sRawBufferSize);\n    }\n\n    RtlSecureZeroMemory(&AesCtx, sizeof(AesCtx));\n    AES_init_ctx_iv(&AesCtx, pAesKey, pAesIv);\n    AES_CBC_encrypt_buffer(&AesCtx, pNewBuffer, sNewBufferSize);\n\n    *psCipherTextSize   = sNewBufferSize;\n    *ppCipherTextBuffer = pNewBuffer;\n\n    return TRUE;\n}\n```"}
{"instructions": "How can I implement AES Decryption Using WinAPIs", "response": "```c \n#include <Bcrypt.h>\n#include <windows.h>\n#include <stdio.h>\n#pragma comment(lib, "Bcrypt.lib")\n\n#define NT_SUCCESS(STATUS)  (((NTSTATUS)(STATUS)) >= 0x00)\n#define AES_KEY_SIZE        32\n#define AES_IV_SIZE         16\n\nBOOL InstallAesDecryption(IN PBYTE pCipherTextBuffer, IN SIZE_T sCipherTextSize, IN PBYTE pAesKey, IN PBYTE pAesIv, OUT PBYTE* ppRawBuffer, OUT PSIZE_T psRawBufferSize) {\n\n    NTSTATUS                STATUS              = 0x00;\n\n    ULONG                   cbResult            = NULL;\n    BCRYPT_ALG_HANDLE       hAlgorithm          = NULL;\n    BCRYPT_KEY_HANDLE       hKeyHandle          = NULL;\n    DWORD                   dwBlockSize         = 0x00;\n    DWORD                   dwKeyObjectLength   = 0x00;\n    PBYTE                   pKeyObjectBuff      = NULL;\n\n    PBYTE                   pTmpRawBuff         = NULL;\n    DWORD                   dwTmpRawSize        = 0x00;\n\n    if (!NT_SUCCESS((STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0x00)))) {\n        printf("[!] BCryptOpenAlgorithmProvider Failed With Error: 0x%0.8X \n", STATUS);\n        goto _END_OF_FUNC;\n    }\n\n    if (!NT_SUCCESS((STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&dwKeyObjectLength, sizeof(DWORD), &cbResult, 0x00)))) {\n        printf("[!] BCryptGetProperty [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);\n        goto _END_OF_FUNC;\n    }\n\n    if (!NT_SUCCESS((STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0x00)))) {\n        printf("[!] BCryptGetProperty [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);\n        goto _END_OF_FUNC;\n    }\n\n    if (dwBlockSize != AES_IV_SIZE)\n        goto _END_OF_FUNC;\n\n    if (!(pKeyObjectBuff = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwKeyObjectLength))) {\n        printf("[!] HeapAlloc Failed With Error: %d \n", GetLastError());\n        goto _END_OF_FUNC;\n    }\n\n    if (!NT_SUCCESS((STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0x00)))) {\n        printf("[!] BCryptSetProperty Failed With Error: 0x%0.8X \n", STATUS);\n        goto _END_OF_FUNC;\n    }\n\n    if (!NT_SUCCESS((STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pKeyObjectBuff, dwKeyObjectLength, (PUCHAR)pAesKey, AES_KEY_SIZE, 0x00)))) {\n        printf("[!] BCryptGenerateSymmetricKey Failed With Error: 0x%0.8X \n", STATUS);\n        goto _END_OF_FUNC;\n    }\n\n    if (!NT_SUCCESS((STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pCipherTextBuffer, (ULONG)sCipherTextSize, NULL, pAesIv, AES_IV_SIZE, NULL, 0x00, &dwTmpRawSize, BCRYPT_BLOCK_PADDING)))) {\n        printf("[!] BCryptDecrypt [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);\n        goto _END_OF_FUNC;\n    }\n\n    if (!(pTmpRawBuff = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwTmpRawSize))) {\n        printf("[!] HeapAlloc Failed With Error: %d \n", GetLastError());\n        goto _END_OF_FUNC;\n    }\n\n    if (!NT_SUCCESS((STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pCipherTextBuffer, (ULONG)sCipherTextSize, NULL, pAesIv, AES_IV_SIZE, pTmpRawBuff, dwTmpRawSize, &cbResult, BCRYPT_BLOCK_PADDING)))) {\n        printf("[!] BCryptDecrypt [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);\n        goto _END_OF_FUNC;\n    }\n\n    *ppRawBuffer        = pTmpRawBuff;\n    *psRawBufferSize    = dwTmpRawSize;\n\n_END_OF_FUNC:\n    if (hKeyHandle)\n        BCryptDestroyKey(hKeyHandle);\n    if (hAlgorithm)\n        BCryptCloseAlgorithmProvider(hAlgorithm, 0x00);\n    if (pKeyObjectBuff)\n        HeapFree(GetProcessHeap(), 0x00, pKeyObjectBuff);\n    if (pTmpRawBuff && !*ppRawBuffer)\n        HeapFree(GetProcessHeap(), 0x00, pTmpRawBuff);\n    return (*ppRawBuffer && *psRawBufferSize) ? TRUE : FALSE;\n}\n```"}
"""

# Parse and format the entries
formatted_entries = parse_and_format_entries(raw_entries)

# Save formatted entries as JSONL
with open("formatted_entries.jsonl", "w") as f:
    for entry in formatted_entries:
        f.write(entry)
        f.write("\n")
