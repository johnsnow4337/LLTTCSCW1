f = open("decryptedExtensions.txt", "r")
myReadlines = f.readlines()
f.close()
f2 = open("CheckPointExtensions.txt","r")
theirReadlines = f2.readlines()
f2.close()
for i in range(len(theirReadlines)):
    theirReadlines[i] = theirReadlines[i].lower()
newReadlines = []
newTheirReadlines = []
for i in theirReadlines:
    if i not in myReadlines:
        newTheirReadlines.append(i)
for i in myReadlines:
    if i not in theirReadlines:
        newReadlines.append(i)
    
print(newReadlines)
print(newTheirReadlines)