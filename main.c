/*
 * Metin1 ANI_FORMAT_ERROR Fix by Helia01 (local.dll)
 * 
 * Fixes on non-Chinese Windows by hooking mbstowcs and CreateFileA
 * to use GBK (codepage 936) encoding instead of system locale.
 *
 * Target addresses for mts.exe:
 *   _mbstowcs:         0x4A1935  (called by sub_4857F5, sub_485D1C, sub_4978C0)
 *   __imp_CreateFileA: 0x4DE220  (called by sub_485C87 and etc)
 */

#include <windows.h>

#define CP_GBK 936

#define MBSTOWCS_FUNC_VA   0x4A1935
#define CREATEFILEA_IAT_VA 0x4DE220

typedef HANDLE (WINAPI *CreateFileA_t)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
static CreateFileA_t g_OriginalCreateFileA = NULL;
static volatile LONG g_inHook = 0;


/**
 * mbstowcs wrapper - converts using GBK instead of system locale
 */
int __cdecl mbstowcs_gbk_wrapper(wchar_t* dest, const char* src, size_t max) {
    return MultiByteToWideChar(CP_GBK, 0, src, -1, dest, (int)max);
}

/**
 * CreateFileA wrapper - converts path via GBK and calls CreateFileW
 */
HANDLE WINAPI CreateFileA_GBK_Wrapper(
    LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile)
{
    WCHAR wFileName[MAX_PATH];
    HANDLE result;
    
    // Recursion guard and validation
    if (g_OriginalCreateFileA == NULL || 
        InterlockedCompareExchange(&g_inHook, 1, 0) != 0 ||
        lpFileName == NULL) {
        if (g_OriginalCreateFileA)
            return g_OriginalCreateFileA(lpFileName, dwDesiredAccess, dwShareMode,
                                         lpSecurityAttributes, dwCreationDisposition,
                                         dwFlagsAndAttributes, hTemplateFile);
        return INVALID_HANDLE_VALUE;
    }
    
    // Convert path from GBK to Unicode and call CreateFileW 
    if (MultiByteToWideChar(CP_GBK, 0, lpFileName, -1, wFileName, MAX_PATH) > 0) {
        result = CreateFileW(wFileName, dwDesiredAccess, dwShareMode,
                            lpSecurityAttributes, dwCreationDisposition,
                            dwFlagsAndAttributes, hTemplateFile);
    } else {
        result = g_OriginalCreateFileA(lpFileName, dwDesiredAccess, dwShareMode,
                                       lpSecurityAttributes, dwCreationDisposition,
                                       dwFlagsAndAttributes, hTemplateFile);
    }
    
    InterlockedExchange(&g_inHook, 0);
    return result;
}


/**
 * Hook mbstowcs by patching first 5 bytes with JMP
 */
static BOOL HookMbstowcs(void) {
    BYTE* func = (BYTE*)MBSTOWCS_FUNC_VA;
    DWORD oldProtect, jmpRel;
    BYTE patch[5];
    
    if (func[0] != 0x8B && func[0] != 0x55)
        return FALSE;
    
    if (!VirtualProtect(func, 5, PAGE_EXECUTE_READWRITE, &oldProtect))
        return FALSE;
    
    // Build JMP rel32 instruction
    jmpRel = (DWORD)&mbstowcs_gbk_wrapper - (MBSTOWCS_FUNC_VA + 5);
    patch[0] = 0xE9;
    *(DWORD*)&patch[1] = jmpRel;
    
    CopyMemory(func, patch, 5);
    VirtualProtect(func, 5, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), func, 5);
    
    return TRUE;
}

/**
 * Hook CreateFileA via IAT patching
 */
static BOOL HookCreateFileA(void) {
    DWORD* iat = (DWORD*)CREATEFILEA_IAT_VA;
    DWORD oldProtect, iatValue;
    
    iatValue = *iat;
    if (iatValue == 0 || iatValue == (DWORD)&CreateFileA_GBK_Wrapper)
        return FALSE;
    
    g_OriginalCreateFileA = (CreateFileA_t)iatValue;
    
    if (!VirtualProtect(iat, 4, PAGE_EXECUTE_READWRITE, &oldProtect))
        return FALSE;
    
    *iat = (DWORD)&CreateFileA_GBK_Wrapper;
    VirtualProtect(iat, 4, oldProtect, &oldProtect);
    
    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        HookMbstowcs();
        HookCreateFileA();
    }
    return TRUE;
}