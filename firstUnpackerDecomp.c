//Store the start state of the registers and run the next stage
0x3c40_entry:
    [0x0414DA0]  = esi (entrypoint address)
    [0x0414DA4] = edi
    [0x0414DA8] = ebx
    [0x0414DB0] = esp
    [0x0414DAC] = ebp
    0x13d0_entry2()


//Perform some anti-reversing checks the nrun the next stage
0x13d0_entry2:
    //This could've been an anti-sanbox technique but is most likely just obfuscation
    for i in 0x19600:
        if (GlobalMemoryStatus().dwTotalPhys ==0):
            return 0
    
    //Create a new event and store its handle in the stack
    h = CreateEventW(
            0x00, // Default security descriptor 
            0x00, // Auto-reset event
            0x00, // Event starts nonsignaled
            0x00) // Event has no name

    esp+0x40 = h
    esp+0x5c = h
    esp+0x50 = h
    call 0x4000_Stage2


//Perform some useless operations like copying the same null memory 
//or calculating a static value over 0x1000ea iterations
//then it moves on to the next stage passing the calulated value
0x4000_Stage2:
    var1=0
    count1=0
    count2=0
    //This loop only sets count1 = 0x1000ea, count2=3 and an array containing 0xA * [0x1000e9 & 0xff] see testStage2Loop.py
    do{
        //Copy the null values in 0x414f98 to 0x414f50 for 0x18 bytes
        0x3430_newMemcpy(0x414f50,0x414f98,0x18)
        if (count1 & 3) - 1 == 0:
            i=0
            for i in range (0xA):
                count1XOR[i] = (count1 & 0xFF)
            count2 = (count2 | 1)
            count1+=1
        else if (count1 & 3) - 2 == 0:
            count2 = (count2 | 0x2)
            count1+=1
        else:
            count1+=1
    }while(count1 < 0x1000ea)

    if (count2 == 3): //Always true see testStage2Loop.py
        count2 = 0x3960_intermediate1(count2)
    return count2

//Performs the same functionality of a memCpy
0x3430_newMemcpy(dst,src,size):
    count=0
    for count in range(size):
        dl = [src+count]
        [dst+count] = dl
    return

//Call the next stage and store the entered value
0x3960_intermediate1(arg0):
    a = 0x3 (arg0)
    0x3520_startUnpacking(arg0)

//Perform the actual unpacking and enter the next stage of unpacking
0x3520_startUnpacking:

    //Get the length of 0x40517A, always 3
    lenVar = 0x32C0_getLen(0x40517A)
    arrayOfResults = esp+0xd8
    //Decrypt data will store its return values in arrayOfResults
    0x1520_decryptData(arrayOfResults)

    //Store arrayOfResults[0] and 0x3f400 on the stack
    [esp+0x58] = arrayOfResults[0] // newRWMem+0x940f
    [esp+0x5c] = 0x3f400 (0x6CBF+0x38741)

    //Store original register values on the stack
    [esp+0x90] = [0x0414DA0] -> origEsi = 0x403c40 (entrypoint address)
    [esp+0x94] = [0x0414DA4] -> origEdi = 0x403c40
    [esp+0x98] = [0x0414DA8] -> origEbx
    [esp+0x8c] = [0x0414DAC] -> origEbp
    [esp+0x88] = [0x0414DAC] -> origEsp

    //Gets the address of the original process loaded into memory (most likely 0x0400000)
    selfAddr = 0x28f0_callfindDll(0)

    //Store that address on the stack
    [esp+0x70] = selfAddr

    //Get address of orignal process' pe header
    peOffset = 0x27D0_getPEHeaderAddr(selfAddr)
    //IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage
    selfSizeOfImage = [peOffset+0x50]
    //Store size of original process on the stack
    [esp+0x74] = selfSizeOfImage

    returnArr = esp+0x24
    // 0x1d70_DecryptedToRWX will store return values
    // arrayOfResults[2] contains newRWMem+0x6afb as generated by 0x1520_decryptData
    // newRWMem+0x6afb is the DOS header of an application

    //Function returns address of decrypted entry function (at offset 0x2830) in excutable memory
    newXMemEntry=0x1d70_DecryptedToRWX(returnArr, arrayOfResults[2] "[esp+0xe0]")

    //Enter the next stage of unpacking
    newXMemEntry(returnArr)
    return 1

//Create a new area of memory with Read Write Execute permissions and copy the decrypted memory to that address
0x1d70_DecryptedToRWX(returnArr, decryptedMem):
    VirtualAlloc = 0x2050_findKernel32FuncAddr("VirtualAlloc")
    //Maps virtual memory at address found by CPU of size 0x85000 with RWX permissions
    newXMem = VirtualAlloc(0,0x85000,0x1000,0x40)
    0x1e30_copyDecrypted(newXMem, decryptedMem)
    //Store the adress of the new executable memory on the stack along with its value-0x400000
    [returnArr+0x54] = newXMem
    [returnArr+0x58] = newXMem-0x400000

    //Return the entrypoint of the executable decrypted memory
    return newXMem+0x2830


0x1e30_copyDecrypted(newRWMem,decryptedMem):
    peAddr = 0x27D0_getPEHeaderAddr(decryptedMem)

    //_IMAGE_NT_HEADERS.FileHeader.SizeOfOptionalHeader
    optionalSize = [peAddr+0x14]

    //Get start of IMAGE_SECTION_HEADER by adding peaddr, size of IMAGE_NT_HEADERS and size of IMAGE_OPTIONAL_HEADER
    currSectionHeader = peAddr+0x18+optionalSize
    count1=0

    //_IMAGE_NT_HEADERS.FileHeader.NumberOfSections
    noOfSections = [peAddr+0x6]
    currAddr = newRWMem
    
    while count1<noOfSections:

        //Get IMAGE_SECTION_HEADER.VirtualAddress (first section is .text)
        sectionVAddr = [currSectionHeader+0xC]

        //Get Absolute address for where section should be in newRWMem
        sectionRAddr = currAddr+sectionVAddr

        //Get location of section in decrypted mem by adding decryptedMem and PointerToRawData
        //Section header offset 0x14 IMAGE_SECTION_HEADER.PointerToRawData
        rawData = decryptedMem+[currSectionHeader+0x14]

        //Section header offset 0x10 IMAGE_SECTION_HEADER.SizeOfRawData
        sizeOfData = [currSectionHeader+0x10]

        //Copy decrypted secttion to correct Virtual Offset in newRWMem
        0x3430_newMemcpy(sectionRAddr, rawData, sizeOfData)
            
        count1+=1
        //Move section header to next section header by adding size of IMAGE_SECTION_HEADER to currSectionHeader
        currSectionHeader = currSectionHeader+0x28
    
    //Get IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders
    sizeOfHeaders = [peAddr+0x54]
            
    //Copy headers to new memory
    0x3430_newMemcpy(newRWMem, decryptedMem, sizeOfHeaders)
    return newRWMem



//Gets address of the DOS header of current process
0x29A0_getSelfAddr:
    currAddr = 0x4029A0
    while True:
        currAddrBytes = [currAddr]
        // Get address with valid DOS header magic bytes
        if currAddrBytes!=0x5a4d:
            // Get value of current offset + 0x3c, the offset in DOS header for PE header 
            // "e_lfanew"
            currAddrOffsetVal = [currAddr+0x3C]
            //Get address with valid PE header magic
            if currAddrOffsetVal=="0x4550"
                return currAddr
        else:
            //Decrement to next 0x1000 section of memory
            currAddr -= 0x1000
            currAddr = currAddr & 0xfffff000


//Decrypt the packed executable and store it in a Read Write area of memory
0x1520_decryptData(arrayOfResults):
    count1=0
    size = 0
    myarr = [0x744,0]
    totalSize2 = 0

    totalSize = 0
    //This is used to get the total size of memory to be copied later so the correct size memory can be allocated
    while count1<0x44:
        size = ([0x0414a78 + count1 * 0xc] ^ [0x0414a70 + count1 * 0xc])
        totalSize = size + totalSize
        count1+=1
    // totalSize is always 0x493e0
    
    //Get the address of the kernel32 function VirtualAlloc
    VirtualAlloc = 0x2050_findKernel32FuncAddr(0x40514C ->"VirtualAlloc")

    //Maps virtual memory at address found by CPU of size 0x493e0 with RW permissions
    newRWMem = VirtualAlloc(0, totalSize "0x493e0",0x1000,4)

    count2=0
    while count2<0x44:
        size2 = ([0x0414a78 + count2 * 0xc] ^ [0x0414a70 + count2 * 0xc])
        memAddr = ([0x414a74 + count2 * 0xc])

        // Copies memory specified by 4 bytes at [0x414a74 + count2 * 0xc] 
        // to next section in newRWMem for size2 bytes
        0x3430_newMemcpy((newRWMem+totalSize),memAddr,size2)
        totalSize2 = size2 + totalSize2
        count2+=1

    //Decrypt the data copied to newRWMem
    0x1990_decryptFunc(newRWMem,newRWMem, totalSize)

    arrayOfResults[0] = newRWMem+0x940f
    arrayOfResults[1] = 0x3f400
    //This is the offset to a DOS header inside the decrypted bytes
    arrayOfResults[2] = newRWMem+0x6afb
    arrayOfResults[3] = 0x2800
    return

//Decrypt the memory using an array of offsets in 0x4050cc and values at 0x405159
//See python script for working implementation
0x1990_decryptFunc(mem1,mem2,size):
    destArr = ESP+0x80
    //store array in 0x4050cc in destArr [ESP+0x80]
    memcpy(&destArr,&DAT_004050cc,0x80);

    count1=0
    while True:
        if count1<0x20:
            //get count1 index of array as it is an array of longs
            currInt = destArr[count1*4]
            incOffset = currInt
            if incOffset<Size:
                currVal = [0x405159 + (incOffset & 0x1F)]
                newRWMemAddr = mem2+incOffset
                newRWMemVal = [newRWMemAddr]
                //get last byte of subtraction
                subtrVals = newRWMemVal - currVal
                [mem1+incOffset] = subtrVals
                incOffset+=0x20
            else:
                count+=1
        else:
            return

//Returns the address of the kernel32 function from the given string
 0x2050_findKernel32FuncAddr(funcName):
    if 0x895!=0x59DC:   //Always true
        kernel32Addr=0x2880_findKernel32() //finds the base address of kernel32.dll
        funcAddr=0x2110_findFunc(kernel32Addr,funcName)//finds the address of the kernel32 function
        return funcAddr

//Returns the address of a function from a given dll address and function name
0x2110_findFunc(dllAddr,funcName):

    //This section gets an array of bytes from memory address 0x4050B0 and decrypts them to get the string "LdrGetProcedureAddress"

    //0x4050B0 -> "E2 CA DC E9 CB DA FE DC C1 CD CB CA DB DC CB EF CA CA DC CB DD DD AE AE 00"
    bytearr=[] // ebp-0x51
    memcpy(bytearr, 0x4050B0, 0x19)
    count=0
    //Decrypt the bytes in the string
    //See python code for working implementation
    while count<0x18:
        currByte=bytearr[count1] // with sign extension
        currByte = currByte ^ 0xAE
        bytearr[count1] = currByte
        count+=1
    //bytearr-> "LdrGetProcedureAddress"

    //Get the address of the NTDLL function LdrGetProcedureAddress
    LdrGetProcedureAddress = 0x2270_getNTDLLFuncAddr(bytearr)
    ansi_string = [0,0,0]
    ansi_string[2] = funcName
    lenVar = 0x32C0_getLen(funcName)
    ansi_string[0] = lenVar
    ansi_string[1] = lenVar
    returnVar = esp+0xc
    returnVar = 0x0
    // stack location esp+0xc is passed to LdrGetProcedureAddress as the location of the return value
    // address of dll and ANSI string is passed to LdrGetProcedureAddress
    funcAddr = LdrGetProcedureAddress(dllAddr,&ansi_string,0,returnVar)
    return funcAddr

//Get the address of an NTDLL function from the given name
0x2270_getNTDLLFuncAddr(funcName):
    ntdllAddr = 0x28A0_findNTDLLAddr() //Start of ntdll.dll
    ntDllPEAddr = 0x27D0_getPEHeaderAddr(ntdllAddr) // address of IMAGE_NT_HEADERS
    imageOptionalStart = ntDLLPEAddr+0x18   // address of IMAGE_OPTIONAL_HEADER magic bytes (start)
    
    //First data dir is the Export Table containing information about function exports
    ExportTableAddr = ntdllAddr + [ntdllAddr+0x78]   // address of first OptionalHeader.DataDirectory.VirtualAddress
    ExportTableSize = [imageOptionalStart+0x64] // address of first OptionalHeader.DataDirectory.Size
    AddressOfNames = ntdllAddr + [ExportTableAddr+0x20] // IMAGE_EXPORT_DIRECTORY.AddressOfNames
    currentOrdinalAddr = ntdllAddr + [ExportTableAddr+0x24] // IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals

    currentOrdinal=-0x1
    count=0
    
    //Loop through NTDLL's export table to find the function with name matching input
    do{
        NumberOfNames = [ExportTableAddr + 0x18] //IMAGE_EXPORT_DIRECTORY.NumberOfNames
        // get the address of the [count] name in the list (addresses are 32 bit so count is *4)
        currName = ntdllAddr + [AddressOfNames][count*4] 
        count2=0
        isExpected=0
        while count2<0x20:
            currChar = currName[count2]
            if 0x81b!=0x6b2f: //always true
                expectedChar = funcName[count2]
                isExpected = ((currChar-expectedChar) == 0)
                if currChar=="\0" or expectedChar=="\0" or isExpected==0:
                    break

        if isExpected==0:
            if (0x55 | 0) != 0: //always true
                //Shift two bytes to the next ordinal value
                currentOrdinalAddr = currentOrdinalAddr+0x2
                count+=1
        else:
            break
    }while(count<NumberOfNames)
    
    currentOrdinal= [currentOrdinalAddr]
    if currentOrdinal != -0x1:
        // Get relative address of function address table IMAGE_EXPORT_DIRECTORY.AddressOfFunctions
        RelativeAddrOfFunctions =  ExportTableAddr + 0x1C
        AbsoluteAddrOfFunctions = ntdllAddr + RelativeAddrOfFunctions
        
        //Get the relative address of the function by summing the absolute address of the function table with the current ordinal*4
        AddrOfMyFunc = [AbsoluteAddrOfFunctions + currentOrdinal * 4]
        AbsoluteAddrOfMyFunc = ntdllAddr + AddrOfMyFunc
        return AbsoluteAddrOfMyFunc
    return -1
                                    
//return the 0x3C offset of address provided if it matches the IMAGE_NT_HEADER magic bytes (0x4550)
0x27D0_getPEHeaderAddr(DOSHeaderAddr):
    peAddr = [DOSHeaderAddr+0x3C] //Get address of PE header by reading PE offset at offset 0x3C
    if [peAddr] != 0x4550:
        return 0
    else:
        return peAddr

//Get address of NTDLL in virtual memory
0x28A0_findNTDLLAddr:
    return 0x28f0_callfindDll(0x405080->"ntdll.dll")

//Get address of kernel32 in virtual memory
0x2880_findKernel32:
    return 0x28f0_callfindDll(0x405094->"kernel32.dll")


//Get the adress of the given dll unless the name is NULL then get address of current process
0x28f0_callfindDll(dllName):
    if dllName==0: 
        0x29A0_getSelfAddr()
    else:
        dllAddr = 0x2b20_findDll(dllName,0)
        return dllAddr


//Find the address of a dll from the given string
0x2b20_findDll(dllName,arg1):
    PEBAddr = 0x3120_getPEB() // get the adress of the Process Environment Block
    //PEB.Ldr (0xc)
    PEB_LDR_DATA_Ptr = [PEBAddr+0xC]
    firstFlink = [PEB_LDR_DATA_Ptr + 0x14] //PEB_LDR_DATA_InMemoryOrderModuleList.Flink
    nextFlink = [firstFlink] //PEB_LDR_DATA_InMemoryOrderModuleList.Flink.Flink
    
    while firstFlink!=nextFlink: // if the end of the list isn't reached
    
        loadOrderNextFlink=nextFlink-0x8 //LDR_DATA_TABLE_ENTRY start aka start of InLoadOrderLinks
    
        baseDllLen = [nextFlink+0x24] //LDR_DATA_TABLE_ENTRY.BaseDllName.Length (0x2c)
    
        baseDllBuffPtr = [loadOrderNextFlink+0x30] //LDR_DATA_TABLE_ENTRY.BaseDllName.Buffer (0x30)
    
        dllBaseAddr = [loadOrderNextFlink+0x18] //LDR_DATA_TABLE_ENTRY.DllBase (0x18)
    
        if dllBaseAddr != arg1 && arg1!=0:
            equalsExpected=0
            count1=0
            
            while True:
                if count1<(baseDllLen//2): // if not reached the end of string
                    currChar = [baseDllBuffPtr+count1*2]
                    if currChar>=0x41 "A":
                        if currChar<=0x5A "Z":
                            currChar = currChar + 0x20 //upper case to lower case
    
                    expectedChar = dllName[count1*2]
                    equalsExpected = expectedChar == currChar
    
                    if currChar != 0:
                        if !equalsExpected:
                            break      
                        else:
                            count1+=1 //Increment char
                    else:
                        break
                else:
                    break

            if equalsExpected==0:
                nextFlink = [nextFlink] // increment dll
            else:
                //Return the base address of the dll
                dllBaseAddr = [loadOrderNextFlink+0x18]
                return dllBaseAddr
        else:
            //There is more logic here but its never used in this stage

//Get the address of the Process Environment Block of current process
0x3120_getPEB:
    TIBAddr = 0x3200_getTIBAddr()
    TIB_PEB_Ptr_Ptr = TIBAddr+0x30
    //TEB.ProcessEnvironmentBlock
    TIB_PEB_Ptr = [TIBAddr+0x30]
    return [TIB_PEB_Ptr]

//Get address of TIB by looking up fs[0x18]
0x3200_getTIBAddr:
    return 0x3220_getFSOffset(0x18)

//Return value in fs+offset
0x3220_getFSOffset(offset):
    return fs:[offset] 

//Returns the length of the entered argument
0x32C0_getLen(arg0):
    count=0
    for i in range(len(arg0)):
        if arg0[i]!="\0":
            count+=1
        else:
            return count
    return count
