#Read bytes from exe
exe = open("./ms457.exe","rb")
global exebytes
exebytes = exe.read()
exe.close()

#Store virtual memory to file offset map from section header
text = [0x1000,0x1000]
para = [0x4000,0x4000]
rdata = [0x5000,0x5000]
data = [0x6000,0x6000]
crt = [0x15000,0x59000]
CODE = [0x2e000,0x72000]
erloc = [0x47000,0x8B000]
rsrc = [0x51000,0x95000]
reloc=[0x99999999,0x99999999]
vMemBase = 0x0400000

#Convert virtual address to offset in exe
def virtualToOffset(virtAddr):
    virtAddr = virtAddr - vMemBase
    if virtAddr>=rsrc[1]:
        return virtAddr-rsrc[1]+(rsrc[0])
    elif virtAddr>=reloc[1]:
        return virtAddr-reloc[1]+reloc[0]
    elif virtAddr>=erloc[1]:
        return virtAddr-erloc[1]+(erloc[0])
    elif virtAddr>=CODE[1]:
        return virtAddr-CODE[1]+(CODE[0])
    elif virtAddr>=crt[1]:
        return virtAddr-crt[1]+(crt[0])
    elif virtAddr>=data[1]:
        return virtAddr-data[1]+(data[0])
    elif virtAddr>=rdata[1]:
        return virtAddr-rdata[1]+(rdata[0])
    elif virtAddr>=para[1]:
        return virtAddr-para[1]+para[0]
    elif virtAddr>=text[1]:
        return virtAddr-text[1]+(text[0])
    else:
        return virtAddr

#Copy bytes from exe to byte array
def newMemcpy(src,size):
    count=0
    byteArr = []
    dl = 0
    for count in range(size):
        try:
            dl = exebytes[virtualToOffset(src)+count]
        except:
            print(hex(virtualToOffset(src)+count))
        byteArr.append(dl)
    return bytes(byteArr)

#Get total size of memory to be copied
#Not used here but is in original code
xor = 0
count1 =0
for count1 in range(0x44):
    #Read little endian value from exebytes[0x14a70+count1*0xC]
    strvar1 = f'0x{exebytes[0x14a70+count1*0xC+3]:02x}{exebytes[0x14a70+count1*0xC+2]:02x}{exebytes[0x14a70+count1*0xC+1]:02x}{exebytes[0x14a70+count1*0xC]:02x}'
    var1 = int(strvar1,16)
    #Read little endian value from exebytes[0x14a78+count1*0xC]
    strvar2 = f'0x{exebytes[0x14a70+count1*0xC+11]:02x}{exebytes[0x14a70+count1*0xC+10]:02x}{exebytes[0x14a70+count1*0xC+9]:02x}{exebytes[0x14a70+count1*0xC+8]:02x}'
    var2 = int(strvar2,16)
    xor = (var1 ^ var2) + xor
print("Total Size: "+hex(xor))

print("Round2:")
count2 =0
oldvar2= 0
oldXOR= 0
startvar2 = 0
totalBytes = 0
newBytes = b""
size=0

#Get the encrypted bytes and store them in newBytes
for count2 in range(0x44):
    #Read little endian value from exebytes[0x14a70+count2*0xC]
    strvar1 = f'0x{exebytes[0x14a70+count2*0xC+3]:02x}{exebytes[0x14a70+count2*0xC+2]:02x}{exebytes[0x14a70+count2*0xC+1]:02x}{exebytes[0x14a70+count2*0xC]:02x}'
    var1 = int(strvar1,16)
    #Read little endian value from exebytes[0x14a78+count2*0xC]
    strvar3 = f'0x{exebytes[0x14a70+count2*0xC+11]:02x}{exebytes[0x14a70+count2*0xC+10]:02x}{exebytes[0x14a70+count2*0xC+9]:02x}{exebytes[0x14a70+count2*0xC+8]:02x}'
    var3 = int(strvar3,16)
    currXOR = (var1 ^ var3)
    size =  currXOR + size
    #Read little endian value from exebytes[0x14a74+count2*0xC]
    strvar2 = f'0x{exebytes[0x14a70+count2*0xC+7]:02x}{exebytes[0x14a70+count2*0xC+6]:02x}{exebytes[0x14a70+count2*0xC+5]:02x}{exebytes[0x14a70+count2*0xC+4]:02x}'
    var2 = int(strvar2,16)

    #This logic is purely to make the ouput more readable and isn't in the actual executable
    if (oldvar2+oldXOR+1)!=var2 and oldvar2!=0:
        if startvar2==0:
            startvar2=int(f'0x{exebytes[0x14a70+7]:02x}{exebytes[0x14a70+6]:02x}{exebytes[0x14a70+5]:02x}{exebytes[0x14a70+4]:02x}',16)
        print("From: "+hex(virtualToOffset(startvar2))+" To: "+hex(virtualToOffset(oldvar2+oldXOR))+" for "+hex(totalBytes)+" total bytes")
        startvar2 = var2
        totalBytes = 0
    totalBytes = currXOR + totalBytes+1

    #print("From: "+strvar2+" To: "+hex(currXOR+var2)+" for "+hex(currXOR)+" bytes")
    oldvar2 = var2
    oldXOR = currXOR

    #Store the encrypted bytes in newBytes
    newBytes+=newMemcpy(var2, currXOR)

print("Stored encrypted bytes into newBytes")
newBytes = list(newBytes)
#Store the array of longs from 0x04050cc in destVar
destVar = newMemcpy(0x04050cc, 0x80)
count=0

#Decrypt the encrypted bytes
for i in range(0x20):
    #Get the current offset from the array of longs
    currOffset = destVar[i*4]
    #print("currOffset: "+hex(currOffset))
    incOffset=currOffset
    #print(hex(exebytes[virtualToOffset(0x405159) + (incOffset & 0x1f)]-newBytes[incOffset]))


    while incOffset<size:
        currVal = exebytes[virtualToOffset(0x405159) + (incOffset & 0x1f)] #First value is exebytes[virtualToOffset(0x405159) + (incOffset & 0x1f)]
        newMemVal = newBytes[incOffset] #Second val is newBytes[incOffset]
        subtrVals = newMemVal - currVal #Decrypted value is newMemVal - currVal
        newBytes[incOffset] = int(f'{(subtrVals & 0xffffffff):02x}'[-2:],16) #Make sure to only copy the last byte of the unsigned decrypted value
        incOffset+=0x20 # increment the offset by 0x20

newBytes = bytes(newBytes)
print("\nDecrypted newBytes and stored in myFile.exe")
f = open("myFile.exe", "wb")
f.write(newBytes)
f.close
print("Decrypted bytes from start of DOS Header offset (0x6afb) stored in myFile2.exe")
f = open("myFile2.exe", "wb")
f.write(newBytes[0x6afb:])
f.close

#Get decrypted file offset
text = [0x400,0x1000]
rdata = [0x1e00,0x3000]
data = [0x2000,0x4000]
reloc = [0x2600,0x5000]
para = [0x99999999,0x99999999]
crt = [0x99999999,0x99999999]
CODE = [0x99999999,0x99999999]
erloc = [0x99999999,0x99999999]
rsrc = [0x99999999,0x99999999]

print("\nIn Once Unpacked: ")
vMemBase = 0x0AB0000
count3=0
secondPass = list(newBytes[0x940f:])
print("first decrypted bytes from 0x940f stored in secondPass representing raw encrypted bytes")
newExeBytes = list(newBytes[0x6afb:])
print("first decrypted bytes from 0x6afb stored in newExeBytes representing program in virtual memory")

#Decrypt the second packed binary
while count3!=0xff:
    incOffset = newExeBytes[virtualToOffset(0xAB4014+count3*4)] # get count3 value in long array stored in decrypted virtual memory at 0xAB4014
    while incOffset<0x3f400:
        bl = newExeBytes[virtualToOffset(0xab3063)+(incOffset&0x1f)] # get first value from decrypted virtual memory
        bh = secondPass[incOffset] # get second value from raw encrypted bytes
        secondPass[incOffset] = int(f'{((bh-bl) & 0xffffffff):02x}'[-2:],16)#decrypted value is still the last unsigned byte of firstVal-secondVal
        incOffset+=0xff #increment offset by 0xff
    count3+=1

print("\nDecrypted Second packed binary is stored in myFile3.exe")
f = open("myFile3.exe", "wb")
f.write(bytes(secondPass))
f.close