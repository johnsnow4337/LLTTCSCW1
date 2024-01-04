import binascii
import hashlib
from Crypto.Cipher import AES

def decrypt_data(encrypted_data):
    # Set the key and IV
    key = hashlib.sha256('0324532423723948572379453249857'.encode('utf-8')).digest()
    iv = binascii.unhexlify('FFFFAAAA0000BEEFDEAD0000BEFFFFFF')
    
    # Convert the hex-encoded encrypted data to bytes
    encrypted_data_bytes = binascii.unhexlify(encrypted_data)

    # Decrypt the data
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(encrypted_data_bytes).decode('ascii')

    # Remove padding
    padding_length = ord(decrypted_data[-1])
    decrypted_data = decrypted_data[:-padding_length]

    return decrypted_data

def from_request(request):
    dataPart = ""
    if isinstance(request, bytes):
        data = b"data="
    else:
        data = "data="
    if data in request:
        dataPart = request.split(data)[1]
        for i in dataPart:
            toCheck = (i if usebytes else ord(i))
            if not((toCheck<91 and toCheck>64) or (toCheck>47 and toCheck<58)):
                if usebytes:
                    delimiter = i.to_bytes()
                else:
                    delimiter = i
                break
        dataPart = dataPart.split(delimiter)[0]
    return dataPart
readPCAP = True
pcapName = "packetSamples\\UserPC_NetworkTraffic220107.pcap"
#pcapName = "packetSamples\\test.pcapng"
usebytes = True
if readPCAP:
    f = open(pcapName,"rb" if usebytes else "r")
    readlines = f.readlines()
    f.close()
    host = "N\A"
    for i in readlines:
        if (b"Host:" if usebytes else "Host:") in i:
            host = i.split((b"Host: " if usebytes else "Host: "))[1]
            if usebytes:
                host = host.decode("ascii")
        data = from_request(i)
        if data != "":
            print("To: "+host.strip() +" data="+ decrypt_data(data)+"\n")

else:
    decrypted = decrypt_data("E2F3A17314FF09455F2E90CFBF9994AA5EB95EB8AA38C72CA124134CB474E8B569BF672BB9776FA398A19985B3D447AA9FD7E31131314BF0B4F8C5941890BA9F7FE7A63CE967EA3EAE0CBF82FB07444B00712C466763005FF583BF48AFDC98663FC2D5953674A025FB49ABC69AD89CF93F05039821798D3399A3270B34DC31016C125CC73432302AC41F7466726698A8FB8ECE599630C2C11536B1D016870487330298EB11F93DBF37B514B99290EA2A33B716DA2CB7609C1915B3CC8A55F836F3B19D777FEA1D62CA55A9E35FE6B0F421583CCDFF562BA113C2035FC3552695C6ECE8429C48AE4095664AE8C5C4D823AE92824D35D72840E3CDBBFE5D7CBDBD236EC1F2BC52C757AA77711F9957D9D8F25140D63DE0CEEBEF2C9A4998D0FD55078BE810720ADCAE415407978BCD183D6220DF4764EE02DE25775BD90AFC83A7")
    print(decrypted)