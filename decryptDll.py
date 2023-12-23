def getEncOut(string):
    encOut = 0
    for i in string:
        encOut = (encOut << 7 | encOut >> 0x19) ^ ord(i)
        if (len(hex(encOut)))>10:
            encOut = int(hex(encOut)[-8:],16)
    return encOut
result = getEncOut("GetModuleHandleA")
print(hex(result))
print(result == 0x4b1ffe8e)
