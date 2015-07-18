#include "main.h"
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// a sample exported function


inline void  WINAPI trampoline()
{

    fprintf(stdout,"%s \n ","Hooked !! ");

}

void HookIAT (const char  * api , DWORD  HookFuncAddr )
{

    IMAGE_DOS_HEADER * idh = NULL ;
    HMODULE CurrentExe = GetModuleHandle(NULL);
    DWORD Protect = 0;
    IMAGE_NT_HEADERS * inh = NULL ;
    DWORD t = 0 ;
    IMAGE_THUNK_DATA * itd ;
    int j = -1, i  = 0;
    IMAGE_THUNK_DATA * itdf ;
    idh = (IMAGE_DOS_HEADER * )CurrentExe ;


    if(idh->e_magic != 0x5a4d )
    {
        ExitProcess(-1) ;
    }
    inh = (IMAGE_NT_HEADERS * )((DWORD)CurrentExe  + (DWORD)idh->e_lfanew ) ;

    if(inh->Signature != 0x4550 )
    {
        ExitProcess(-1);
    }
    // Get the Virtaul address of import adress table !!
    IMAGE_IMPORT_DESCRIPTOR * va_import = (IMAGE_IMPORT_DESCRIPTOR * )((DWORD)inh->OptionalHeader.ImageBase + (DWORD)inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress );

     itd = (IMAGE_THUNK_DATA * )( (DWORD)CurrentExe + va_import[0].OriginalFirstThunk );
    // contains the adresses of the imported APIs
     itdf = (IMAGE_THUNK_DATA * )( (DWORD)CurrentExe + va_import[0].FirstThunk ) ;


    while(va_import[i].Characteristics != 0)
    {

        j = -1 ;

        while(itd[++j].u1.Function != 0)
        {

            if(strcmp((const char *)api , (const char * )((DWORD) CurrentExe + (DWORD)(itd[j].u1.ForwarderString + 2)) ) == 0)
            {

                if(!VirtualProtect(&itdf[j].u1.Function, sizeof(LPVOID), PAGE_READWRITE, &Protect) )
                {
                    ExitProcess(-1) ;
                }

                 itdf[j].u1.Function = (DWORD )HookFuncAddr;


                if(!VirtualProtect(&itdf[j].u1.Function, sizeof(LPVOID), Protect, &t) )
                {
                    ExitProcess(-1) ;
                }

            }
        }

        i++ ;
        itd = (IMAGE_THUNK_DATA * )((DWORD)CurrentExe + va_import[i].OriginalFirstThunk );

        itdf = (IMAGE_THUNK_DATA * )((DWORD)CurrentExe + va_import[i].FirstThunk );
    }
}



extern "C" DLL_EXPORT BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {

    case DLL_PROCESS_ATTACH:
        // attach to process
        // return FALSE to fail DLL load

        HookIAT("MessageBoxA",(DWORD  )trampoline) ;

 /// the following api will be hooked and the trampoline() function will be executed instead !!

        MessageBoxA(NULL,"L0phtTn","HookMe",0);

        break;

    case DLL_PROCESS_DETACH:
        // detach from process
        break;

    case DLL_THREAD_ATTACH:
        // attach to thread
        break;

    case DLL_THREAD_DETACH:
        // detach from thread
        break;

    }
    return TRUE; // succesful
}
