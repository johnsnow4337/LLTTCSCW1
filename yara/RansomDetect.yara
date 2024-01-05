import "pe"
import "console"
import "math"
rule LLTTCS_PackedExe1_ExaminePE
{
    meta:
        source = "u2150600"
        description = "Finds first packer stage from pe file objects"
        andigin_malware = "Teslacrypt v3.0.1"
        rule_strength = 65
        rule_generality = 45
        file_type = "exe"
        date = "03/Jan/2024"
        md5hash_unpacked1exe = "1c9885ddd44974a8864019fabb51dddc"
    
    condition:
        //Entropy value check from Practical Security Analytics (2019)
        math.entropy( 0x6000, 0x466b7) > 7.2 and

        pe.is_pe and pe.is_32bit() and

        //Only check for imports used in the actual code as the other imports can easily be removed\replaced
        pe.imports("msvcrt.dll","memset") and
        pe.imports("msvcrt.dll","memcpy") and
        pe.imports("kernel32.dll","GlobalMemoryStatus") and
        pe.imports("kernel32.dll","CreateEventW") and
        pe.number_of_exports == 0 and

        pe.version_info["CompanyName"] == "nah nah Corporation" and
        pe.version_info["FileDescription"] == "nah  nahApp" and
        pe.version_info["InternalName"] == "nah nah" and
        pe.version_info["LegalCopyright"] == "\xa9nah nah Corporation. All rights reserved." and
        pe.version_info["OriginalFilename"] == "nah nah" and
        pe.version_info["ProductName"] == "nah nah\xae " and

        pe.image_base == 0x400000 and

        pe.opthdr_magic == pe.IMAGE_NT_OPTIONAL_HDR32_MAGIC and 
        pe.subsystem == pe.SUBSYSTEM_WINDOWS_GUI and 
        pe.checksum != pe.calculate_checksum() and 
        pe.machine == pe.MACHINE_I386 and 
        pe.pdb_path == "E:\\Tools\\aolfed\\release\\osc.pdb"                   
}

rule LLTTCS_PackedExe1_Strings
{
    meta:
        source = "u2150600"
        description = "Finds first packer stage from bytes inside the exectuable"
        andigin_malware = "Teslacrypt v3.0.1"
        rule_strength = 85
        rule_generality = 55
        file_type = "exe"
        date = "03/Jan/2024"
        md5hash_unpacked1exe = "1c9885ddd44974a8864019fabb51dddc"

    strings:
        $i_kernel32 = "kernel32.dll" nocase wide ascii
        $i_ntdll = "ntdll.dll" nocase wide ascii
        $x_LdrGetProcedureAddress = "LdrGetProcedureAddress" xor wide ascii
        $i_VirtualAlloc = "VirtualAlloc" nocase wide ascii
        //Can be removed from rule to be more generalised but will increase false positive likelyhood
        //0x22 long value at offset 0x5158
        $encryptionKey = {00 28 50 60 96 D1 7A 92 80 FF CD 1C CE 93 84 27 E7 7C A7 AF 01 9F 7F C3 B4 22 5F 75 C8 B4 01 CB 05 00}

        //Not in the current executable but can be implemented easily with the same functionality
        $x_kernel32 = "kernel32.dll" xor wide ascii
        $x_ntdll = "ntdll.dll" xor wide ascii
        $i_LdrGetProcedureAddress = "LdrGetProcedureAddress" nocase wide ascii
        $x_VirtualAlloc = "VirtualAlloc" xor wide ascii

    condition:
        ($i_kernel32 and $x_kernel32) and ($i_ntdll and $x_ntdll) 
        and ($x_LdrGetProcedureAddress and $i_LdrGetProcedureAddress) and
        ($i_VirtualAlloc and $x_VirtualAlloc) and $encryptionKey
}

//This executable is only ever in memory
rule LLTTCS_PackedExe2_ExaminePE
{
    meta:
        source = "u2150600"
        description = "Finds second packer stage from pe file objects"
        andigin_malware = "Teslacrypt v3.0.1"
        rule_strength = 65
        rule_generality = 65
        file_type = "exe"
        date = "03/Jan/2024"
        md5hash_unpacked2exe = "7c71ce8fcd9024f5342d4cee7562f9aa"
    
    condition:
        //Entropy value check from Practical Security Analytics (2019)
        math.entropy( 0x940f, filesize) > 7.2 and

        pe.is_pe and pe.is_32bit() and

        pe.number_of_imports == 0 and
        pe.number_of_exports == 0 and

        //Values hard-coded in the previous unpacker
        pe.image_base == 0x400000 and
        pe.size_of_image == 0x85000 and
        pe.entry_point_raw == 0x2830 and

        pe.opthdr_magic == pe.IMAGE_NT_OPTIONAL_HDR32_MAGIC and 
        pe.subsystem == pe.SUBSYSTEM_WINDOWS_GUI and 
        pe.checksum != pe.calculate_checksum() and 
        pe.machine == pe.MACHINE_I386  
}

//This executable is only ever in memory
rule LLTTCS_PackedExe2_Strings
{
    meta:
        source = "u2150600"
        description = "Finds second packer stage from pe file objects"
        andigin_malware = "Teslacrypt v3.0.1"
        rule_strength = 85
        rule_generality = 55
        file_type = "exe"
        date = "03/Jan/2024"
        md5hash_unpacked2exe = "7c71ce8fcd9024f5342d4cee7562f9aa"
    
    strings:
        $user32 = "user32.dll" nocase wide ascii
        $ntdll = "ntdll.dll" nocase wide ascii
        $kernel32 = "kernel32.dll" nocase wide ascii

        $EnableMenuItem = "EnableMenuItem" nocase wide ascii
        $VirtualAlloc = "VirtualAlloc" nocase wide ascii
        $VirtualProtect = "VirtualProtect" nocase wide ascii
        $LoadLibraryA = "LoadLibraryA" nocase wide ascii
        $GetProcAddress = "GetProcAddress" nocase wide ascii
        $LdrGetProcedureAddress = "LdrGetProcedureAddress" nocase wide ascii

        $encryptionKey = {00 66 39 B1 37 AE CE 55 F6 4D 9B CD 65 CD 93 39 5A 95 4B 4F 14 72 F9 30 06 47 1F 3D E1 FD 5E 94 BB 00}

    condition:
        all of them
}

//This executable is only ever in memory
rule LLTTCS_Unpacked_TeslaCrypt_ExaminePE
{
    meta:
        source = "u2150600"
        description = "Finds unpacked teslacrypt from pe file objects"
        andigin_malware = "Teslacrypt v3.0.1"
        rule_strength = 70
        rule_generality = 55
        file_type = "exe"
        date = "03/Jan/2024"
        md5hash_Teslacrypt = "3490a397fd7698b35098436fb662e7bb"
    condition:
        pe.is_pe and pe.is_32bit() and


        // Not using imphash increases generalisation
        // Including imports reduces generalisation alot but does increase reliablility
        // However the malware does implement a custom function finder 
        // so it can remove some of these functions from the import table reducing the effectiveness of this measure
        pe.imports("gdiplus.dll", "GdipCreateBitmapFromHBITMAP") and
        pe.imports("gdiplus.dll", "GdiplusStartup") and
        pe.imports("gdiplus.dll", "GdipDisposeImage") and
        pe.imports("gdiplus.dll", "GdipFree") and
        pe.imports("gdiplus.dll", "GdipAlloc") and
        pe.imports("gdiplus.dll", "GdipCloneImage") and
        pe.imports("gdiplus.dll", "GdipGetImageEncoders") and
        pe.imports("gdiplus.dll", "GdipGetImageEncodersSize") and
        pe.imports("gdiplus.dll", "GdipSaveImageToFile") and

        pe.imports("SHLWAPI.dll", "PathFindExtensionW") and
        pe.imports("SHLWAPI.dll", "PathFindFileNameW") and

        pe.imports("PSAPI.DLL", "GetProcessImageFileNameW") and
        pe.imports("PSAPI.DLL", "EnumProcesses") and

        pe.imports("ntdll.dll", "isxdigit") and
        pe.imports("ntdll.dll", "wcsstr") and
        pe.imports("ntdll.dll", "wcsncmp") and
        pe.imports("ntdll.dll", "strstr") and
        pe.imports("ntdll.dll", "_vsnwprintf") and
        pe.imports("ntdll.dll", "_allshl") and
        pe.imports("ntdll.dll", "_alldiv") and
        pe.imports("ntdll.dll", "_aullshr") and
        pe.imports("ntdll.dll", "RtlUnwind") and

        pe.imports("KERNEL32.dll", "HeapFree") and
        pe.imports("KERNEL32.dll", "GetProcessHeap") and
        pe.imports("KERNEL32.dll", "WriteFile") and
        pe.imports("KERNEL32.dll", "GlobalAlloc") and
        pe.imports("KERNEL32.dll", "Sleep") and
        pe.imports("KERNEL32.dll", "GetFileAttributesW") and
        pe.imports("KERNEL32.dll", "CreateFileW") and
        pe.imports("KERNEL32.dll", "ExitThread") and
        pe.imports("KERNEL32.dll", "FlushFileBuffers") and
        pe.imports("KERNEL32.dll", "GetLastError") and
        pe.imports("KERNEL32.dll", "GlobalFree") and
        pe.imports("KERNEL32.dll", "FindClose") and
        pe.imports("KERNEL32.dll", "CloseHandle") and
        pe.imports("KERNEL32.dll", "DeleteFileW") and
        pe.imports("KERNEL32.dll", "SetFileAttributesW") and
        pe.imports("KERNEL32.dll", "GetVolumeInformationW") and
        pe.imports("KERNEL32.dll", "GlobalMemoryStatus") and
        pe.imports("KERNEL32.dll", "FreeLibrary") and
        pe.imports("KERNEL32.dll", "QueryPerformanceCounter") and
        pe.imports("KERNEL32.dll", "GetTickCount") and
        pe.imports("KERNEL32.dll", "LoadLibraryW") and
        pe.imports("KERNEL32.dll", "GetLogicalDriveStringsW") and
        pe.imports("KERNEL32.dll", "GetCurrentProcessId") and
        pe.imports("KERNEL32.dll", "GetEnvironmentVariableW") and
        pe.imports("KERNEL32.dll", "CreateProcessW") and
        pe.imports("KERNEL32.dll", "GetCurrentProcess") and
        pe.imports("KERNEL32.dll", "WaitForSingleObject") and
        pe.imports("KERNEL32.dll", "GetModuleHandleW") and
        pe.imports("KERNEL32.dll", "CopyFileW") and
        pe.imports("KERNEL32.dll", "GetModuleFileNameW") and
        pe.imports("KERNEL32.dll", "SetThreadPriority") and
        pe.imports("KERNEL32.dll", "SetLastError") and
        pe.imports("KERNEL32.dll", "LocalAlloc") and
        pe.imports("KERNEL32.dll", "GetShortPathNameW") and
        pe.imports("KERNEL32.dll", "LocalFree") and
        pe.imports("KERNEL32.dll", "CreateThread") and
        pe.imports("KERNEL32.dll", "InitializeCriticalSectionAndSpinCount") and
        pe.imports("KERNEL32.dll", "LeaveCriticalSection") and
        pe.imports("KERNEL32.dll", "EnterCriticalSection") and
        pe.imports("KERNEL32.dll", "LCMapStringW") and
        pe.imports("KERNEL32.dll", "MoveFileExW") and
        pe.imports("KERNEL32.dll", "HeapAlloc") and
        pe.imports("KERNEL32.dll", "GetDriveTypeW") and
        pe.imports("KERNEL32.dll", "SetFilePointer") and
        pe.imports("KERNEL32.dll", "GetFileSize") and
        pe.imports("KERNEL32.dll", "ReadFile") and
        pe.imports("KERNEL32.dll", "SetHandleCount") and
        pe.imports("KERNEL32.dll", "GetFileType") and
        pe.imports("KERNEL32.dll", "DeleteCriticalSection") and
        pe.imports("KERNEL32.dll", "FreeEnvironmentStringsW") and
        pe.imports("KERNEL32.dll", "GetEnvironmentStringsW") and
        pe.imports("KERNEL32.dll", "WideCharToMultiByte") and
        pe.imports("KERNEL32.dll", "GetConsoleCP") and
        pe.imports("KERNEL32.dll", "GetVersionExW") and
        pe.imports("KERNEL32.dll", "GetConsoleMode") and
        pe.imports("KERNEL32.dll", "MultiByteToWideChar") and
        pe.imports("KERNEL32.dll", "GetStringTypeW") and
        pe.imports("KERNEL32.dll", "SetStdHandle") and
        pe.imports("KERNEL32.dll", "WriteConsoleW") and
        pe.imports("KERNEL32.dll", "IsProcessorFeaturePresent") and
        pe.imports("KERNEL32.dll", "HeapSize") and
        pe.imports("KERNEL32.dll", "SetEndOfFile") and
        pe.imports("KERNEL32.dll", "GetProcAddress") and
        pe.imports("KERNEL32.dll", "GetCurrentThreadId") and
        pe.imports("KERNEL32.dll", "TlsFree") and
        pe.imports("KERNEL32.dll", "TlsSetValue") and
        pe.imports("KERNEL32.dll", "TlsGetValue") and
        pe.imports("KERNEL32.dll", "TlsAlloc") and
        pe.imports("KERNEL32.dll", "IsValidCodePage") and
        pe.imports("KERNEL32.dll", "GetOEMCP") and
        pe.imports("KERNEL32.dll", "GetACP") and
        pe.imports("KERNEL32.dll", "InterlockedDecrement") and
        pe.imports("KERNEL32.dll", "InterlockedIncrement") and
        pe.imports("KERNEL32.dll", "GetCPInfo") and
        pe.imports("KERNEL32.dll", "GetStdHandle") and
        pe.imports("KERNEL32.dll", "ExitProcess") and
        pe.imports("KERNEL32.dll", "HeapCreate") and
        pe.imports("KERNEL32.dll", "DecodePointer") and
        pe.imports("KERNEL32.dll", "EncodePointer") and
        pe.imports("KERNEL32.dll", "GetSystemTimeAsFileTime") and
        pe.imports("KERNEL32.dll", "HeapReAlloc") and
        pe.imports("KERNEL32.dll", "GetCommandLineW") and
        pe.imports("KERNEL32.dll", "HeapSetInformation") and
        pe.imports("KERNEL32.dll", "GetStartupInfoW") and
        pe.imports("KERNEL32.dll", "TerminateProcess") and
        pe.imports("KERNEL32.dll", "UnhandledExceptionFilter") and
        pe.imports("KERNEL32.dll", "SetUnhandledExceptionFilter") and
        pe.imports("KERNEL32.dll", "IsDebuggerPresent") and

        pe.imports("USER32.dll", "LoadStringW") and
        pe.imports("user32.dll", "GetDC") and
        pe.imports("user32.dll", "ReleaseDC") and
        pe.imports("user32.dll", "DrawTextA") and

        pe.imports("GDI32.dll", "SetBkMode") and
        pe.imports("GDI32.dll", "CreateFontW") and
        pe.imports("GDI32.dll", "GetStockObject") and
        pe.imports("GDI32.dll", "DeleteDC") and
        pe.imports("GDI32.dll", "DeleteObject") and
        pe.imports("GDI32.dll", "SelectObject") and
        pe.imports("GDI32.dll", "CreateCompatibleDC") and
        pe.imports("GDI32.dll", "CreateCompatibleBitmap") and
        pe.imports("GDI32.dll", "SetTextColor") and

        pe.imports("ADVAPI32.dll", "RegQueryValueExA") and
        pe.imports("ADVAPI32.dll", "AdjustTokenPrivileges") and
        pe.imports("ADVAPI32.dll", "CheckTokenMembership") and
        pe.imports("ADVAPI32.dll", "FreeSid") and
        pe.imports("ADVAPI32.dll", "AllocateAndInitializeSid") and
        pe.imports("ADVAPI32.dll", "LookupPrivilegeValueA") and
        pe.imports("ADVAPI32.dll", "GetTokenInformation") and
        pe.imports("ADVAPI32.dll", "GetSidSubAuthority") and
        pe.imports("ADVAPI32.dll", "OpenProcessToken") and
        pe.imports("ADVAPI32.dll", "RegSetValueExW") and
        pe.imports("ADVAPI32.dll", "RegCloseKey") and
        pe.imports("ADVAPI32.dll", "RegFlushKey") and
        pe.imports("ADVAPI32.dll", "RegCreateKeyExA") and
        pe.imports("ADVAPI32.dll", "RegQueryValueExW") and
        pe.imports("ADVAPI32.dll", "RegCreateKeyExW") and
        
        pe.imports("SHELL32.dll", "ShellExecuteExW") and
        pe.imports("SHELL32.dll", "SHGetFolderPathW") and
        pe.imports("SHELL32.dll", "SHGetSpecialFolderPathW") and

        pe.imports("ole32.dll", "CoInitializeEx") and

        pe.imports("MPR.dll", "WNetEnumResourceW") and
        pe.imports("MPR.dll", "WNetOpenEnumW") and
        pe.imports("MPR.dll", "WNetCloseEnum") and

        pe.imports("WININET.dll", "InternetOpenA") and
        pe.imports("WININET.dll", "InternetCrackUrlA") and
        pe.imports("WININET.dll", "HttpSendRequestA") and
        pe.imports("WININET.dll", "InternetSetOptionA") and
        pe.imports("WININET.dll", "InternetCloseHandle") and

        pe.number_of_exports == 0 and

        //This is hardcoded in previous unpacker
        pe.entry_point_raw == 0x265e8 and

        pe.opthdr_magic == pe.IMAGE_NT_OPTIONAL_HDR32_MAGIC and 
        pe.subsystem == pe.SUBSYSTEM_WINDOWS_GUI and 
        pe.checksum != pe.calculate_checksum() and 
        pe.machine == pe.MACHINE_I386  
}

import "cuckoo"
rule LLTTCS_Unpacked_TeslaCrypt_RegistryWrite
{
    meta:
        source = "u2150600"
        description = "Finds unpacked teslacrypt's registry writing from cuckoo output"
        andigin_malware = "Teslacrypt v3.0.1"
        rule_strength = 75
        rule_generality = 45
        file_type = "cuckoo json"
        date = "03/Jan/2024"
        md5hash_Teslacrypt = "3490a397fd7698b35098436fb662e7bb"
        
    condition:
        cuckoo.registry.key_access(/HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\[a-z]{12}/i) and
        cuckoo.registry.key_access(/HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLinkedConnections/i) and
        cuckoo.registry.key_access(/HKEY_CURRENT_USER\\Software\\(xxx|yyy)sys\\ID|HKEY_USERS\\S-1-5-18\\Software\\(xxx|yyy)sys\\ID/i) and
        cuckoo.registry.key_access(/HKEY_CURRENT_USER\\Software\\[A-Fa-f0-9]{8,16}\\data|HKEY_USERS\\S-1-5-18\\Software\\[A-Fa-f0-9]{16}\\data/i)
}

rule LLTTCS_Unpacked_TeslaCrypt_Mutex
{
    meta:
        source = "u2150600"
        description = "Finds unpacked teslacrypt's mutex creation from cuckoo output"
        andigin_malware = "Teslacrypt v3.0.1"
        rule_strength = 60
        rule_generality = 45
        file_type = "cuckoo json"
        date = "03/Jan/2024"
        md5hash_Teslacrypt = "3490a397fd7698b35098436fb662e7bb"
        
    condition:
        cuckoo.sync.mutex(/ityeofm9234-2342/)
}
rule LLTTCS_Unpacked_TeslaCrypt_FileCreate
{
    meta:
        source = "u2150600"
        description = "Finds unpacked teslacrypt's file creation from cuckoo output"
        andigin_malware = "Teslacrypt v3.0.1"
        rule_strength = 60
        rule_generality = 55
        file_type = "cuckoo json"
        date = "03/Jan/2024"
        md5hash_Teslacrypt = "3490a397fd7698b35098436fb662e7bb"
        
    condition:
    
        cuckoo.filesystem.file_access(/(C:\\Windows\\[a-z]{12}\.exe|\\.*Documents.*\\[a-z]{12}\.exe)/i) and
        cuckoo.filesystem.file_access(/\\_RECOVERY_\+[a-z]{5}\.txt/i) and
        cuckoo.filesystem.file_access(/\\_RECOVERY_\+[a-z]{5}\.html/i) and
        cuckoo.filesystem.file_access(/\\_RECOVERY_\+[a-z]{5}\.png/i) and
//As this is only generated once encryption is finished it is commented out here, but is included for completeness
//        cuckoo.filesystem.file_access(/\\.*Desktop.*\\RECOVERY\.txt/i) and
//        cuckoo.filesystem.file_access(/\\.*Desktop.*\\RECOVERY\.htm/i) and
//        cuckoo.filesystem.file_access(/\\.*Desktop.*\\RECOVERY\.png/i) and
        cuckoo.filesystem.file_access(/\\.*Documents.*\\recover_file_[a-z]{9}\.txt/i)
}
rule LLTTCS_Unpacked_TeslaCrypt_NetworkComms
{
    meta:
        source = "u2150600"
        description = "Finds unpacked teslacrypt's network communication from cuckoo output"
        andigin_malware = "Teslacrypt v3.0.1"
        rule_strength = 65
        rule_generality = 55
        file_type = "cuckoo json"
        date = "03/Jan/2024"
        md5hash_Teslacrypt = "3490a397fd7698b35098436fb662e7bb"
        
    condition:
    
        cuckoo.network.http_user_agent(/Mozilla\/5\.0 \(Windows NT 6\.3; WOW64; Trident\/7\.0; Touch; rv:11\.0\) like Gecko/) and
        cuckoo.network.http_post(/worldisonefamily\.info/) or
        cuckoo.network.http_post(/surrogacyandadoption\.com/) or
        cuckoo.network.http_post(/stacon\.eu/) or
        cuckoo.network.http_post(/imagescroll\.com/) or
        cuckoo.network.http_post(/biocarbon\.com\.ec/) 
}