/* ************************************************************************************************
 * Copyright (C) 2022-2026 Symbiotic Systems Research, LLC
 * All Rights Reserved * Proprietary and confidential
 * 
 * The methods and techniques described herein are considered 
 * trade secrets and/or confidential. Reproduction or distribution, 
 * in whole or in part, is forbidden except by express written 
 * permission of Symbiotic Systems Research, LLC.
 * Please contact <info@symsysresearch.com> for licensing information.
 * 
 * NO WARRANTY, EXPLICIT OR IMPLICIT, IS PROVIDED.
 * In no event shall the author be liable for any claim or damages.
 * 
 * Author: Randall Steck
 * ***********************************************************************************************/

 /* ***********************************************************************************************
 * CPU Info Implementation
 * Based on:
 * https://github.com/dj-on-github/rdrand_stdint
 * which is clearly based on:
 * https://www.intel.com/content/dam/develop/external/us/en/documents/drng-software-implementation-guide-2-1-185467.pdf
 *
 * 1) No license text is required, but we acknowledge here in source
 * 2) Unnecessary functions and features have been removed
 * 3) Functions have been renamed
 * ***********************************************************************************************/

#include "kpep/kpep_cpuinfo.h"

#include <string.h>

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__)
static void get_cpuid_windows(int leaf, CPUIDinfo *info) {
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;

    asm("\n\
        mov %4, %%eax\n\
        cpuid\n\
        mov %%eax,%0\n\
        mov %%ebx,%1\n\
        mov %%ecx,%2\n\
        mov %%edx,%3":"=r"(a),"=r"(b),"=r"(c),"=r"(d):"r"(leaf):"%eax","%ebx","%ecx","%edx");
    info->EAX = a;
    info->EBX = b;
    info->ECX = c;
    info->EDX = d;
}
#else
static void get_cpuid_linux(CPUIDinfo *info, const uint32_t func, const uint32_t subfunc)
{
    asm(".intel_syntax noprefix;\n\
        mov r8, rdi;\n\
        mov r9, rsi;\n\
        mov r10, rdx;\n\
        push rax;\n\
        push rbx;\n\
        push rcx;\n\
        push rdx;\n\
        mov eax, r9d;\n\
        mov ecx, r10d;\n\
        cpuid;\n\
        mov DWORD PTR [r8], eax;\n\
        mov DWORD PTR [r8+4], ebx;\n\
        mov DWORD PTR [r8+8], ecx;\n\
        mov DWORD PTR [r8+12], edx;\n\
        pop rdx;\n\
        pop rcx;\n\
        pop rbx;\n\
        pop rax;\n\
        .att_syntax prefix\n");
}
#endif

void get_cpuid(CPUIDinfo *info, const uint32_t func, const uint32_t subfunc) {
    #if defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__)
        get_cpuid_windows(func, info);
    #else
        get_cpuid_linux(info, func, subfunc);
    #endif
}

typedef uint32_t DWORD;

int check_is_intel() 
{
    CPUIDinfo info;
    get_cpuid(&info,0,0);
    if( memcmp((char *)(&info.EBX), "Genu", 4) == 0 &&
        memcmp((char *)(&info.EDX), "ineI", 4) == 0 &&
        memcmp((char *)(&info.ECX), "ntel", 4) == 0) {
            return 1;
    }
    return 0;
}

int check_is_amd() 
{
    CPUIDinfo info;
    get_cpuid(&info,0,0);
    if( memcmp((char *)(&info.EBX), "Auth", 4) == 0 &&
        memcmp((char *)(&info.EDX), "enti", 4) == 0 &&
        memcmp((char *)(&info.ECX), "cAMD", 4) == 0) {
            return 1;
    }
    return 0;
}

int check_aesni_support()
{
    CPUIDinfo info;
    if ((check_is_intel()==1) || (check_is_amd()==1)){
        get_cpuid(&info,1,0);
        return !!((info.ECX & 0x02000000)==0x02000000);
    }
    return 0;
}
 
int check_rdrand_support()
{
    CPUIDinfo info;
    if ((check_is_intel()==1) || (check_is_amd()==1)){
        get_cpuid(&info,1,0);
        return !!((info.ECX & 0x40000000)==0x40000000);
    }
    return 0;
}

int check_rdseed_support()
{
    CPUIDinfo info;
    if ((check_is_intel()==1) || (check_is_amd()==1)){
        get_cpuid(&info,7,0);
        return !!((info.EBX & 0x00040000)==0x00040000);
    }
    return 0;
}

