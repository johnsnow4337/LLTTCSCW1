import base64
import requests
import json
import time
key = b'kasdfgh283'

findEncrypted = True
decrypt = False
if findEncrypted:
    from Crypto.Cipher import ARC2
    exe = open("myFile3.exe", "rb")
    exeBytes = exe.read()
    exe.close()

    #Store virtual memory to file offset map from section header
    text = [0x400,0x1000]
    para = [0x99999999,0x99999999]
    rdata = [0x2f800,0x31000]
    data = [0x3a200,0x3c000]
    crt = [0x99999999,0x99999999]
    CODE = [0x99999999,0x99999999]
    erloc = [0x99999999,0x99999999]
    rsrc = [0x99999999,0x99999999]
    reloc=[0x3c800, 0x82000]
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
    def getLen(strAddr, unicode):
        startAddr = strAddr
        while exeBytes[strAddr]!=0 and (exeBytes[strAddr+1]!=0 or not unicode):
            strAddr+=1
        return strAddr-startAddr

    def storeEncrypted(offset):
        vOffset = virtualToOffset(offset)
        length = getLen(vOffset, False)
        ciphertext = exeBytes[vOffset:vOffset+length]
        skip = 0
        
        for i in range(length):
            if ciphertext[length-i-1] == ord('='):
                skip+=1
            else:
                break
        iv = ciphertext[:4]+ciphertext[length-skip-4:length-skip]
        print(b"IV: "+iv)
        print(b"Cipher b64: "+ciphertext[4:-4-skip])
        ciphertext = base64.b64decode(ciphertext[4:-4-skip]+ b'==')
        print(b"b64 decode: " + ciphertext)
        f = open("encryptedStrs.txt","a")
        f.write(ciphertext.hex()+":::"+iv.decode("ascii")+":::\n")
        f.close()
    f = open("encryptedStrs.txt","w")
    f.close()
    
    for i in range(0x2f8//0x4):
        b = bytearray(exeBytes[virtualToOffset(0x43df08)+(i*4):virtualToOffset(0x43df08)+(i*4)+4])
        b.reverse()
        offset = int(b.hex(),16)
        storeEncrypted(offset)
    storeEncrypted(0x0434850)
    storeEncrypted(0x04347f8)
    storeEncrypted(0x04347a0)
    storeEncrypted(0x0434714)
    storeEncrypted(0x04346c8)
    storeEncrypted(0x0434670)
    storeEncrypted(0x0434628)
    storeEncrypted(0x0436b28)
    storeEncrypted(0x04348d8)

        
if decrypt:
    f = open("encryptedStrsJustNew.txt","r")
    readEncrypted = f.read()
    f.close()
    f = open("decryptedStrs.txt","w")
    f.close()
    for ciphertext in readEncrypted.split(":::\n"):
        #This should work but doesn't so I have resorted to using a website that does
        #cipher = ARC2.new(key, ARC2.MODE_CBC, iv)
        #text = cipher.decrypt(ciphertext)
        url = 'https://www.lddgo.net/api/RC2?lang=en'
        split = ciphertext.split(":::")
        payload = {
            "inputContent": split[0],
            "model": "CBC",
            "padding": "pkcs5padding",
            "inputPassword": key.decode("ascii"),
            "inputIv": split[1],
            "inputFormat": "hex",
            "outputFormat": "hex",
            "charset": "UTF-8",
            "encrypt": 'false'
        }

        headers = {
            'Content-Type': 'application/json'
        }


        while True:
            try:
                response = requests.post(url, data=json.dumps(payload), headers=headers)
                time.sleep(0.5)
                print(response.text)
                decrypted = json.loads(response.text)['data']
                decryptedStr = bytes.fromhex(decrypted).decode("ascii")
                print("decrypted: "+decryptedStr)
                f = open("decryptedStrs.txt","a")
                f.write(decryptedStr+"\n")
                f.close()
                print()
                break
            except json.decoder.JSONDecodeError:
                continue
