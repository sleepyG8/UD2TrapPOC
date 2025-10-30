#include <Windows.h>
#include <stdio.h>

BYTE* data;
BYTE* oldbytes[2];
LONG WINAPI ud2Handler(EXCEPTION_POINTERS* ep) {

    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION) {
        printf("RIP: %llX\n", ep->ContextRecord->Rip);

        // maybe ill write the 2 original bytes back
        // OG isdebuggerpresent first 2 bytes lets dynamically store them...
        data[0] = oldbytes[0];
        data[1] = oldbytes[1];

        //ep->ContextRecord->Rip += 2;

        Sleep(300);
        return -1; // Continue exec = -1 probaly will crash because I need to skip these next instruction 
    }
}


FARPROC ImportWalker(char* func) {
    
    BYTE* baseAddress = (BYTE*)GetModuleHandle(NULL);

    // Read DOS header
    PIMAGE_DOS_HEADER dh = (PIMAGE_DOS_HEADER)baseAddress;
    if (dh->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Invalid PE file\n");
        return FALSE;
    }

    // Read NT headers
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)dh + dh->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
       printf("Invalid NT headers\n");
        return FALSE;
    }

    // Get Optional Header
    PIMAGE_OPTIONAL_HEADER oh = &nt->OptionalHeader;

    // Check for Import Table
    if (oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0) {
       printf("No imports found\n");
        return FALSE;
    }

    // Locate Import Table
    PIMAGE_IMPORT_DESCRIPTOR id = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)baseAddress + oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    while (id->Name != 0 && id->OriginalFirstThunk != 0) {
        char* importName = (char*)((BYTE*)baseAddress + id->Name);
        printf("%s\n", importName);

        PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)((BYTE*)baseAddress + id->OriginalFirstThunk);
        PIMAGE_THUNK_DATA thunkData = (PIMAGE_THUNK_DATA)((BYTE*)baseAddress + id->FirstThunk);

            while (origThunk->u1.AddressOfData != 0) {
                PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)baseAddress + origThunk->u1.AddressOfData);                    

                if (importByName) {
                FARPROC funcAddr = (FARPROC)thunkData->u1.Function;
                printf("+ %s\n", importByName->Name);
                printf("Function Address: %p\n", funcAddr);
               
                //FILE* file = fopen("C:\\", "r+");

                
                if (strcmp(importByName->Name, func) == 0) {
                    printf("Found\n");
                    // Were gonna do stuff here now that my Import walker is primed
                    return funcAddr;

                }
            }
                origThunk++;
                thunkData++;
            
        }
        
    
    id++;
}
}

int main(int argc, char* argv[]) {
    
    if (argc < 2) return 1;

    //Wrote UD2 to the function VirtualAlloc now we need to setup our VEH handler
    void* handler = AddVectoredExceptionHandler(1, ud2Handler);

    data = (BYTE*)ImportWalker(argv[1]);

    if (!data) {
        printf("Couldnt find funtion name\n");
        return 1;
    }

    oldbytes[0] = data[0];
    oldbytes[1] = data[1];
    
    // Changing Protections to RWX
    DWORD oldprotect;
    VirtualProtect((void*)data, 0x1000, PAGE_EXECUTE_READWRITE, &oldprotect);
    
    // Opcode for UD2 I just had to lookup rq (0F 0B)
    data[0] = 0x0F;
    data[1] = 0x0B;

    printf("UD2 Activated!\n");

    printf("%02X %02X\n", data[0], data[1]);

    // Activation Example
    IsDebuggerPresent();
 
    puts("End");

    return 0;
}

