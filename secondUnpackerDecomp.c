//returnArr structure
//from getFuncAddrs
    //returnArr = esp (at 0x3520_startUnpacking)+0x24 (0x19FBFC)
    //[returnArr] = *CreateActCtxW
    //[returnArr+0x4] = *ActivateActCtx
    //[returnArr+0x8] = *LoadLibraryA
    //[returnArr+0xc] = *GetProcAddress
    //...
    //[returnArr+0x1c] = *VirtualAlloc
    //[returnArr+0x20] = *VirtualProtect
    //[returnArr+0x24] = *VirtualFree
    //[returnArr+0x28] = *UnmapViewOfFile
    //[returnArr+0x2c] = *AddVectoredExceptionHandler
    //[returnArr+0x30] = *RemoveVectoredExceptionHandler
//Assigned in 0x3520_startUnpacking [esp+0x58/0x5c] = [returnArr+0x34/0x38]
    //[returnArr+0x34] = [arrayOfResults] = newRWMem+0x940f
    //[returnArr+0x38] = 0x3f400
//from unpackFunc_d
    //[returnArray+0x3c]=newestRWMem
    //[returnArray+0x40]=0x4
    //[returnArray+0x44]=0x265e8
    //[returnArray+0x48]=0x85000
//Assigned in 0x3520_startUnpacking [esp+0x70/0x74] = [returnArr+0x4c/0x50]
    //[returnArr+0x4c] = 0x400000   //self address
    //[returnArr+0x50] = 0x9e000    //self size of image
//from 0x1d70_DecryptedToRWX
    //[returnArr+0x54] = newXMem
    //[returnArr+0x58] = newXMem-0x400000
    //...
//Assigned in 0x3520_startUnpacking [esp+0x88-0x98] = [returnArr+0x64/0x74]
    //[returnArr+0x64] = orig_esp 0x019FF70
    //[returnArr+0x68] = orig_ebp 0x019FF80
    //[returnArr+0x6c] = 0x403C40 //original entry point
    //[returnArr+0x70] = 0x403C40
    //[returnArr+0x74] = orig_ebx 0x33400

decrypytedEntry(*returnArr):
    getFuncAddrs(*returnArr)
    LoadLibraryA = [returnArr+0x8]
    user32Addr = LoadLibraryA("user32.dll")
    EnableMenuItem = findDllFunc_d(user32Addr, "EnableMenuItem")
    //Attempt to grey out menu item 0 in menu at handle 0x1f
    menuReturn = (*EnableMenuItem)(0x1f,0,MF_GRAYED)
    // If return value is MF_ENABLED:0 
    // or item 0 at handle 0x1f not found:-1 then continue
    if menuReturn<1:
        unpackFunc_d(*returnArr)
        changeOrigLDRData(*returnArr)
        setupAndRunUnpacked(*returnArr)

setupAndRunUnpacked(*returnArr):
    returnArrPtr = esp+0x7c
    selfAddr = [returnArr+0x4c]
    sizeOfSelf = [returnArr+0x50]
    retAddr = esp+0xb8
    _0x4= [returnArray+0x40]
    _0x85000 = [returnArray+0x48]
    VirtualProtect = [returnArr+0x20]

    VirtualProtect(selfAddr,sizeOfSelf,0x4,retAddr)

    //Set original mem to null
    newMemSet(selfAddr,0,sizeOfSelf)

    newestRWMem=[returnArr+0x3c]

    //Copy decrypted mem to orignal memory
    newMemCpy_d(selfAddr,newestRWMem,_0x85000)

    //set decrypted mem to null
    newMemSet(newestRWMem,0,_0x85000)

    //set first 0x400 bytes to read only permissions
    VirtualProtect(selfAddr,0x400,0x2,retAddr)
    peHeader = getPEHeader_d(selfAddr)
    
    //IMAGE_OPTIONAL_HEADER start = IMAGE_NT_HEADERS addr + size of Signature (0x4) and size of IMAGE_FILE_HEADER (0x14)
    optionalStart = peHeader+0x18
    
    //IMAGE_NT_HEADERS.FileHeader.SizeOfOptionalHeader offset = 0x14
    sizeOfOptional = [peHeader+0x14]
    
    //IMAGE_SECTION_HEADER start = IMAGE_OPTIONAL_HEADER start + IMAGE_FILE_HEADER.SizeOfOptionalHeader
    currSection = optionalStart+sizeOfOptional
    
    protArr = esp+0x98
    protArrAdd0x14 = protArr+0x14
    protArrAdd0x18 = protArr+0x18
    protArrAdd0x1c = protArr+0x1c
    protArrAdd0x10 = protArr+0x10
    
    count=0
    while count!=_0x4:
    
        // Get current section's memory address by adding base virtual address (0x400000)
        // and the virtual address offset of the current section
        // found by looking at IMAGE_SECTION_HEADER.VirtualAddress (offset 0xc) in current section header
        currSectionVAddr = selfAddr+[currSection+0xc]
    
        //Get IMAGE_SECTION_HEADER.Characteristics (offset 0x24) of current section
        characteristics = [currSection+0x2]
    
        //Get IMAGE_SECTION_HEADER.Misc.VirtualSize (offset 0x8) of current section
        virtualSize = [currSection+0x8]

    
        //Get bit number 31 from IMAGE_SECTION_HEADER.Characteristics
        //this corresponds to SECTION_CHARACTERISTICS.IMAGE_SCN_MEM_READ
        isReadable = (characteristics>>0x1e) & 0x1
    
        //Get bit number 32 from IMAGE_SECTION_HEADER.Characteristics
        //this corresponds to SECTION_CHARACTERISTICS.IMAGE_SCN_MEM_WRITE
        isWriteable = characteristics>>0x1f
    
        //Get bit number 30 from IMAGE_SECTION_HEADER.Characteristics
        //this corresponds to SECTION_CHARACTERISTICS.IMAGE_SCN_MEM_EXECUTE
        isExecutable = (characteristics>>0x1d) & 0x1

    
        //Set up addresses so that when each of the characteristics are added together 
        //at different bit positions the correct memory protection constant can be retrived
        //Binary offset 0000:PAGE_NOACCESS(0x1)
        [protArr] = 0x1
        //Binary offset 10000:PAGE_READONLY(0x2)
        [protArrAdd0x10] = 0x2
        //Binary offset 11000:PAGE_READWRITE(0x4)
        [protArrAdd0x18] = 0x4
        //Binary offset 11100:PAGE_EXECUTE_READWRITE(0x40)
        [protArrAdd0x1c] = 0x40
        //Binary offset 10100:PAGE_EXECUTE_READ(0x20)
        [protArrAdd0x14] = 0x20

        //Add isReadable shifted left 4 bits to get leftmost bit of protArr offset
        protectionAddr = protArr+(isReadable<<0x4)
    
        //Add isWriteable shifted left 3 bits to get second leftmost bit of protArr offset
        protectionAddr = protectionAddr+(isWriteable<<0x3)
    
        //Add isExecutable shifted left 2 bits to get third leftmost bit of protArr offset
        protectionAddr = protectionAddr+(isExecutable<<0x2)
        protection = [protectionAddr]
    
        VirtualProtect(currSectionVAddr, virtualSize, protection, retAddr)

        count+=1
        //Move section header to next section header by adding size of IMAGE_SECTION_HEADER to currSectionHeader
        currSectionAddr+=0x28
    checkTLSDirSize(*returnArr)

    _0x265e8 = [returnArray+0x44]

    origStart = [returnArr+0x6c]
    origStart_2 = [returnArr+0x70]
    origEBX = [returnArr+0x74]
    origEBP = [returnArr+0x68]
    origESP = [returnArr+0x64]

    newEntry = selfAddr+_0x265e8

    esi = origStart //0x403C40
    edi = origStart_2 //0x403C40
    ebx = origEBX
    eax = newEntry //0x4265e8
    newEntry()

checkTLSDirSize(*returnArr):
    varAddr = esp+0x5c
    varAddr2 = esp+0x68
    selfAddr = [returnArr+0x4c]
    [varAddr] = selfAddr
    kernel32Addr = findKernel32_d()
    ntdllAddr = findNTDLLAddr_d()
    peHeader = getPEHeader_d(selfAddr)
    
    //get IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[9].Size (offset 0xc4)
    // DataDirectory[9] is the TLSDirectory
    tlsSize = [peHeader+0xc4]
    retVar = 1
    if tlsSize==0:
        return retVar
    else:
        //There is logic here however it isn't called due to tlsSize always being equal to 0 so isn't in scope
         

changeOrigLDRData(*returnArr):
    origLDRDataTableAddr = getOrigLDRDataTableAddr(*returnArr)
    if origLDRDataTableAddr!=0:
        selfAddr = [returnArr+0x4c]
        _0x265e8= [returnArray+0x44]
        _0x4265e8 = selfAddr+_0x265e8
        //change the LDR_DATA_TABLE_ENTRY.EntryPoint for the original program to 0x4265e8
        [origLDRDataTableAddr+0x1c] = _0x4265e8
        _0x85000 = [returnArray+0x48]
        //change the LDR_DATA_TABLE_ENTRY.SizeOfImage for the original program to 0x85000
        [origLDRDataTableAddr+0x20] = _0x85000
    return

getOrigLDRDataTableAddr(*returnArr):
    selfAddr = [returnArr+0x4c]
    return findDLL_d(0,selfAddr)

unpackFunc_d(*returnArr):
    newRWMemPlus0x940f = [returnArr+0x34]
    _0x3f400 = [returnArr+0x38]
    decryptFunc_d(newRWMemPlus0x940f, _0x3f400)
    peAddr = getPEHeader_d(newRWMemPlus0x940f)

    VirtualAlloc = [returnArr+0x1c]

    //Get IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage from [peAddr+0x50]
    sizeOfImage = [peAddr+0x50] //0x85000

    //Maps virtual memory at address found by CPU with the size of the decrypted image with RW permissions
    newestRWMem = VirtualAlloc(0,sizeOfImage,0x1000,0x4)

    copyDecrypted_d(newRWMemPlus0x940f,newestRWMem)

    newMemSet(newRWMemPlus0x940f, 0x00, _0x3f400)

    newestPEAddr = getPEHeader_d(newestRWMem)

    // get 0x400000 from [returnArr+0x4c]
    // get IMAGE_NT_HEADERS.OptionalHeader.ImageBase from [newestPEAddr+0x34]
    baseOffset = [returnArr+0x4c]-[newestPEAddr+0x34]

    useRelocTable(newestRWMem, baseOffset)
    loadImports(newestRWMem, *returnArr)
    [returnArray+0x3c]=newestRWMem
    [returnArray+0x40]=0x4
    [returnArray+0x44]=0x265e8
    [returnArray+0x48]=0x85000
    //set IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[10].Size (0xcc) and .VirtualAddress (0xc8) =0
    // DataDirectory[10] is the LoadConfigurationDirectory
    [newestPEAddr+0xcc] = 0
    [newestPEAddr+0xc8] = 0
    return 0

newMemSet(dst, val, size):
    if size!=0:
        count=0
        while count+1!=size:
            //Move least significant byte of val to [dst+count]
            [dst+count] = val
            count+=1
    return dst

//Almost the same logic as non decrypted with check for noOfSections
copyDecrypted_d(newMem, decryptedMem):
    peAddr = getPEHeader_d(decryptedMem)
    //Get _IMAGE_NT_HEADERS.FileHeader.NumberOfSections
    noOfSections = [peAddr+0x6]
    if noOfSections!=0:
        //Get start of section header by copmuting
        //Size of _IMAGE_NT_HEADERS (0x18) add _IMAGE_NT_HEADERS.FileHeader.SizeOfOptionalHeader (peHeader+0x14)
        currSectionAddr = peAddr+0x18+[peAddr+0x14]
        count=0
        while count<NumberOfSections:
            //Get the address of where the section starts in the new virtual memory
            //IMAGE_SECTION_HEADER.VirtualAddress = currSectionAddr+0xc
            newMemSectionAddr = newMem+[currSectionAddr+0xc]
            
            sizeOfData = [currSectionAddr+0x10]

            //Get location of section in decrypted mem by adding decryptedMem and PointerToRawData
            //Section header offset 0x14 IMAGE_SECTION_HEADER.PointerToRawData
            rawData = decryptedMem+[currSectionAddr+0x14]
            newMemCpy_d(newMemSectionAddr, rawData, sizeOfData)
            
            //Move section header to next section header by adding size of IMAGE_SECTION_HEADER to currSectionHeader
            currSectionAddr+=0x28
            count+=1
    //Get IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders
    sizeOfHeaders = [peAddr+0x54]
    newRWMemcpy_d(newMem, decryptedMem, sizeOfHeaders)
    return

//Almost the same logic as non decrypted
newMemCpy_d(dst,src,size):
    count=0
    if size!=0:
        while count!=size:
            dl = [src+count]
            [dst+count] = dl
            count+=1
    return dst

//Almost the same logic as non decrypted decryptFunc with different memory addresses and offset increment
decryptFunc_d(mem1, size):
    count=0
    while count!=0xff:
        incOffset = 0x4014_LongArr[count*4]
        while incOffset<size:
            _0x3063 = [0x4010] //0xXX4010 points to 0xXX3063
            bl = [_0xab3063+(incOffset&0x1f)]
            bh = [mem1+incOffset] - bl
            [mem1+incOffset] = bh
            incOffset+=0xff
        count+=1
    return

getFuncAddrs(*returnArr):
    //from 0x1d70_DecryptedToRWX
    newXMem = [returnArr+0x54]
    newXMemMinus0x400000 = [returnArr+0x58]

    useRelocTable(newXMem, newXMemMinus0x400000)

    [returnArr+0x1c] = findKernel32FuncAddr_d("VirtualAlloc")
    [returnArr+0x20] = findKernel32FuncAddr_d("VirtualProtect")
    [returnArr+0x24] = findKernel32FuncAddr_d("VirtualFree")
    [returnArr+0x8] = findKernel32FuncAddr_d("LoadLibraryA")
    [returnArr+0xc] = findKernel32FuncAddr_d("GetProcAddress")
    [returnArr+0x28] = findKernel32FuncAddr_d("UnmapViewOfFile")
    [returnArr] = findKernel32FuncAddr_d("CreateActCtxW")
    [returnArr+0x4] = findKernel32FuncAddr_d("ActivateActCtx")
    [returnArr+0x2c] = findKernel32FuncAddr_d("AddVectoredExceptionHandler")
    [returnArr+0x30] = findKernel32FuncAddr_d("RemoveVectoredExceptionHandler")

    retVar = loadImports(newXMem, *returnArr)
    return 1

loadImports(dosStart, *returnArr):
    LoadLibraryA = [returnArr+0x8]
    GetProcAddress = [returnArr+0xc]
    peHeaderAddr = getPEHeader_d(dosStart)
    // Get size of imports
    //_IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[1].Size
    importSize = [peHeaderAddr+0x84]

    if importSize!=0:
        //Get virtual address of import table
        //_IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[1].VirtualAddress
        importTableVAddr = [peHeaderAddr+0x80]
        currImportAddr = peHeaderAddr+importTableVAddr
        //Get virtual address of first import Name
        //IMAGE_IMPORT_DESCRIPTOR.Name
        importNameVAddr = [importTableRAddr+0xc]
        if currImportNameVAddr!=0:
            libraryAddr = 0 //Used only in this pseudocode not in actual assembly
            while True:
                if libraryAddr==0:
                    return 0

                currImportName = dosStart+importNameVAddr
                libraryAddr = LoadLibraryA(currImportName)
                //Get address of IMAGE_IMPORT_DESCRIPTOR
                originalThunkVAddr = [currImportAddr]

                if originalThunkVAddr==0:
                    //Get absolute address of firstThunk
                    //dosStart + IMAGE_IMPORT_DESCRIPTOR.FirstThunk
                    currFirstThunkAddr = dosStart + [currImportAddr+0x10]
                    //As original thunk is null first thunk is original
                    currOriginalThunkAddr = currFirstThunkAddr
                else:
                    //Get absolute address of original Thunk
                    currOriginalThunkAddr = dosStart+originalThunkVAddr
                    //Get absolute address of firstThunk (start of list of names)
                    //dosStart + IMAGE_IMPORT_DESCRIPTOR.FirstThunk
                    currFirstThunkAddr = dosStart + [currImportAddr+0x10]
        
                nextThunk = [currOriginalThunkAddr]
                if nextThunk!=0:
                    while nextThunk!=0:
                        if nextThunk>=0:
                            //Get address of current process name
                            // IMAGE_IMPORT_BY_NAME.name offset 0x2
                            currProcNameAddr = dosStart+nextThunk+0x2
                            procAddr = GetProcAddress(libraryAddr, currProcNameAddr)
                        else:
                            currProcNameAddr = nextThunk & 0xffff
                            procAddr = GetProcAddress(libraryAddr, currProcNameAddr)
                        //Change first thunks to correct virtual address rather than relative address
                        [currFirstThunkAddr] = procAddr
                        retCheck = 0
                        if procAddr ==0:
                            break
                        retCheck = 1
                        //Move to next thunk value in both tables
                        currOriginalThunkAddr+=4
                        currFirstThunkAddr+=4
                        nextThunk = [currOriginalThunkAddr]
                if retCheck==0:
                    break

                //Get next name by adding size IMAGE_IMPORT_DESCRIPTOR (0x14) to move to next import
                //then adding 0xc to get next IMAGE_IMPORT_DESCRIPTOR.Name for a total of 0x20
                currImportNameVAddr= [currImportAddr+0x20]
                //Move to next import by adding size IMAGE_IMPORT_DESCRIPTOR (0x14)
                currImportAddr+=0x14
        
    return 1

useRelocTable(dosStart, baseOffset)
    peAddr = getPEHeader_d(dosStart)
    if peAddr!=0 & baseOffset!=0:
        //get _IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[5].Size (offset 0xa4)
        remainingRelocSize = [peAddr+0xa4]
    
        //get offset of relocation table 
        //_IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[5].VirtualAddress (offset 0xa0)
        relocOffset = [peAddr+0xa0]
        currBlockAddr = dosStart+relocOffset

        // IMAGE_BASE_RELOCATION.SizeOfBlock
        currSizeOfBlock = [dosStart+relocOffset+4]
    
        if (currSizeOfBlock!=0 & !(remainingRelocSize<=0)):
    
            while currBlockAddr!=0 & !(remainingRelocSize<=0):
    
                // IMAGE_BASE_RELOCATION.VirtualAddress
                currVAddr = [currBlockAddr]
    
                //Size of block -8 /2 is the number of entries in the relocation table
                remainingBlocks = (currSizeOfBlock - 8)/2
                if remainingBlocks!=0:
    
                    //currBlockAddr + size of IMAGE_BASE_RELOCATION gets next TypeOffset Addr
                    nextTypeOffsetAddr=currBlockAddr+0x8
    
                    while remainingBlocks-1!=0:
                        typeAndOffset = [nextTypeOffsetAddr]
    
                        //get first byte from typeAndOffset to get just the type
                        type = typeAndOffset >> 0xc
    
                        //get last 3 bytes from typeAndOffset to get offset
                        offset = typeAndOffset & 0xfff
    
                        if type!=0:
                            //Adds the offset to baseOffset to get correct virtual memory address for virtual memory constants
                            if (type-0x3)==0:
                                [dosStart+offset+currVAddr] = [dosStart+offset+currVAddr]+baseOffset
                            elif (type-0xA)==0:
                                //Not used here
                            else:
                                break

                        //Gets next typeOffset address as each is a WORD (0x2) length
                        nextTypeOffsetAddr+=0x2
    
                        //Decrement number of remaining blocks
                        remainingBlocks-=1
                    
                    //Moves to next block in reloc table 
                    remainingRelocSize-=currSizeOfBlock
                    currBlockAddr+=currSizeOfBlock
                    currSizeOfBlock = [currBlockAddr+4]
    return 1

//Different to non decrypted function with similar output
getPEHeader_d(mem1):
    peAddr=0
    if [mem1+0x3c]==0x4550:
        peAddr = mem1 + [mem1+0x3c]
    return peAddr

//Same as non decrypted
findKernel32FuncAddr_d(funcName):
    kernel32Addr=findKernel32_d()
    funcAddr=findFunc_d(kernel32Addr,funcName)
    return funcAddr

//Similar to non decrypted with LdrGetProcedureAddress string directly retrieved
findFunc_d(dllAddr,funcName):
    LdrGetProcedureAddress = getNTDLLFuncAddr_d("LdrGetProcedureAddress")
    ansi_string = [0,0,0]
    ansi_string[2] = funcName
    lenVar = 0x32C0_getLen(funcName)
    ansi_string[0] = lenVar
    ansi_string[1] = lenVar
    returnVar = esp+0xc
    returnVar = 0x0
    
    // stack location esp+0xc is passed to LdrGetProcedureAddress as the location to put return value
    // address of ANSI string is passed to LdrGetProcedureAddress
    funcAddr = LdrGetProcedureAddress(dllAddr,&ansi_string,0,returnVar)
    return funcAddr

getNTDLLFuncAddr_d(funcName):
    ntdllAddr = findNTDLLAddr_d() //Start of ntdll.dll
    ntDllPEAddr = getPEHeader_d(ntdllAddr) // address of IMAGE_NT_HEADERS

    //The rest is similar logic to non decrypted
                   

//same as non decrypted
findNTDLLAddr_d:
    return callfindDll_d(0x405080->"ntdll.dll")

//Same as non decrypted
findKernel32_d:
    return callfindDll_d(0x405094->"kernel32.dll")

//Slight change from non decrypted
callfindDll_d(dllName):
    dllAddr = findDll_d(dllName,0)
    return dllAddr

//Almost the same as non decrypted func
findDll_d(dllName,arg1):
    PEBAddr = getPEB_d()
    PEB_LDR_DATA_Ptr = [PEBAddr+0xC]
    firstFlink = [PEB_LDR_DATA_Ptr + 0x14] //PEB_LDR_DATA_InMemoryOrderModuleList.Flink
    nextFlink = [firstFlink] //PEB_LDR_DATA_InMemoryOrderModuleList.Flink.Flink
   //This logic is in the non decrypted func but not used
    while nextFlink!=firstFlink: // if the end of the list isn't reached
        bool1 = opt2!=0
        bool2 = dllname==0
        //nextFlink = LDR_DATA_TABLE_ENTRY.InMemoryOrderLinks (0x8)
        baseDllLen = [nextFlink+0x24] //LDR_DATA_TABLE_ENTRY.BaseDllName.Length (0x28)
        baseDllBuffPtr = [nextFlink+0x28] //LDR_DATA_TABLE_ENTRY.BaseDllName.Buffer (0x30)
        dllBaseAddrPtr = nextFlink+0x10 //LDR_DATA_TABLE_ENTRY.DllBase (0x18)
        if [dllBaseAddrPtr] == arg1 && arg1!=0:
            //Get LDR_DATA_TABLE_ENTRY start address
            return (nextFlink - 0x8)
        else:  
           //Similar enough logic to non decrypted
        nextFlink = [nextFlink]
        
   return


//More straightforward than non decrypted
getPEB_d:
    TIBAddr = getTIBAddr_d()
    return [TIBAddr+0x30]

//More straightforward than non decrypted
getTIBAddr_d:
    //Get address of TIB by looking up fs[0x18]
    return getFSOffset_d(0x18)

// same as non decrypted func
getFSOffset_d(offset):
    return fs:[offset] // value in TIB+offset

getLen_d(arg0):
    //similar logic to non decrypted func
    //Same return value of length of input
