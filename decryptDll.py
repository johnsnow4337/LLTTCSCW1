def getEncOut(string):
    encOut = 0
    for i in string:
        encOut = (encOut << 7 | encOut >> 0x19) ^ ord(i)
        if (len(hex(encOut)))>10:
            encOut = int(hex(encOut)[-8:],16)
    return encOut

genHashes = True
saveHashes = False
useSaved = False
useDefaultNames = True
if useDefaultNames:
    dlls = ["kernel32", "advapi32", "shell32", "netapi32", "wininet"]
    exportFiles = []
    dllExports = []
    for i in dlls:
        exportFiles.append(i+"hashes.txt")
        dllExports.append(i+"out.txt")
else:
    exportFiles = ["kernel32hashes.txt","advapi32hashes.txt", "shell32hashes.txt"]
    dllExports = ["kernel32out.txt", "advapi32out.txt", "shell32out.txt"] #Files generated from VS code's dumpbin /Export {DLL_PATH}
hashDict = []
hashDictReverse= []

if genHashes:
    for i in range(len(dllExports)):
        hashDict.append({})
        hashDictReverse.append({})
        started = False

        f = open(dllExports[i], "r")
        lines = f.readlines()
        f.close()
        if saveHashes:
            f2 = open(exportFiles[i], "w")
        for line in lines:
            lineSplit = line.split()
            if len(lineSplit)>0:
                if lineSplit[0] == "Summary":
                    break
                if started:
                    exportName = ""
                    if lineSplit[2] != "[NONAME]" and lineSplit[3][0] != "(":
                        exportName =  lineSplit[3]
                    else:
                        exportName =  lineSplit[2]

                    hashVal = getEncOut(exportName)
                    hashDict[-1][hashVal] = []
                    hashDict[-1][hashVal].append(exportName)
                    if saveHashes:
                        f2.write(exportName + " "+ hex(hashVal) + "\n")
                    hashDictReverse[-1][exportName] = []
                    hashDictReverse[-1][exportName].append(hashVal)

                if lineSplit[0] == "ordinal":
                    started = True
        if saveHashes:
            f2.close()
elif useSaved:
    for dictionary in exportFiles:
        f = open(dictionary, "r")
        lines = f.readlines()
        f.close()
        hashDict.append({})
        hashDictReverse.append({})
        for line in lines:
            lineSplit = line.split()
            if len(lineSplit)>0:
                if int(lineSplit[1],16) in hashDict[-1]:
                    hashDict[-1][int(lineSplit[1],16)].append(lineSplit[0])
                else:
                    hashDict[-1][int(lineSplit[1],16)] = [lineSplit[0]]
                if lineSplit[0] in hashDictReverse[-1]:
                    hashDictReverse[-1][lineSplit[0]].append(int(lineSplit[1],16))
                else:
                    hashDictReverse[-1][lineSplit[0]] = [int(lineSplit[1],16)]

def findHash(dictionary, key):
    errMsg = "Not Found"
    if isinstance(dictionary, list):
        for i in range(len(dictionary)):
            try:
                return [dictionary[i][key], i]
            except:
                continue
        return [errMsg,-1]
    else:
        try:
            return [dictionary[key], 0]
        except:
            return [errMsg,-1]


""" result = getEncOut("GetModuleHandleA")
print(hex(result))
print(result == 0x4b1ffe8e)
print(findHash(hashDict, 0xa48d6762))
print(findHash(hashDict, 0x72760bb8))
print(findHash(hashDictReverse, "GetModuleHandleA")) """


interactive = True
if interactive:
    while True:
        print("Enter the export or hash to find: ")
        keyInput = input()
        try:
            keyInput = int(keyInput)
        except:
            try:
                keyInput = int(keyInput,16)
            except:
                pass
        result = findHash(hashDict, keyInput)
        if useDefaultNames and result[1]!=-1:
            print("\nFound function(s) in DLL: "+dlls[result[1]])
            
            try:
                for i in result[0]:
                    print(hex(i))
            except:
                print(result[0])
        else:
            print("\n"+result[0])
        print()