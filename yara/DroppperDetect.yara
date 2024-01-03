rule LLTTCS_DOCM_Dropper_DocumentVariable
{
    meta:
        source = "u2150600"
        description = "Detects a malicious base64 encoded encryption key in document variables"
        origin_malware = "Teslacrypt v3.0.1"
        file_type1 = "xml"
        file_type2 = "bin"
        date = "03/Jan/2024"
        md5hash1 = "d23416409d10ffed565b071bbd84f969"
        md5hash2 = "7cbefc1d052d5ca36e928827dbdca7f9"
        
    strings:
        $docVarName = "kBQHAjmEelVSHUyT" fullword wide ascii
        $docVarVal = "c/blrFFGzJwUDWpdVBM1WO9xExkjgIB9euvb5lcOj3GFDrrKs8VGpDOyfPrp2W+tdIdIxKWVMM81wTkH2Z9unLFgc84o3/FnchOXx/GEr/bJwZW4yNYzXM0NxfmN6h+i+8lIdnPDw/y99zpDvDTK1Rvkc9O0NMCd5NOyBlLNYv2/oBJf/pk1i/ywXqz6SD+Ed4Zv+YiufwJJ2V412ghirofXNRg6HuC8oL/m7KO1Baapnn6VwCYqqtQfvBCgTy7H1aV9av5p//lHil1/JUO7blGt502yy9FBSiuqu5n+YN7rZMfPbhDYkU6EaaZ9xSRnmH5LmIf5wkQ4sImEfBeS966EKhnyxALH2FDISSEQQYpjdJb50BCoJosACu2xHyyfmXRrYBDbjXcQpk36v6HRXExJ/1Ub07jxnY2UXWxZm0+DmgaA81Hnpi02YexVWjdGN2iMJx6Wp3HK9xjPTuE8e7RRmnM=" fullword wide ascii
    condition:
        $docVarName or $docVarVal
}

rule LLTTCS_DOCM_Dropper_MacroStrings
{
    meta:
        source = "u2150600"
        description = "Detects malicious registry keys used in docm droppers"
        origin_malware = "Teslacrypt v3.0.1"
        file_type = "bin"
        date = "03/Jan/2024"
        md5hash2 = "7cbefc1d052d5ca36e928827dbdca7f9"
        
    strings:
        $registryKeys_VBAWarnings = /HKCU\\Software\\Microsoft\\Office\\[0-9]+.[0-9]+\\(Word|Excel)\\Security\\VBAWarnings/ nocase wide ascii
        $registryKeys_DisableInternetFilesInPV = /HKCU\\Software\\Microsoft\\Office\\[0-9]+.[0-9]+\\(Word|Excel)\\Security\\ProtectedView\\DisableInternetFilesInPV/ nocase wide ascii
        $registryKeys_DisableAttachementsInPV = /HKCU\\Software\\Microsoft\\Office\\[0-9]+.[0-9]+\\(Word|Excel)\\Security\\ProtectedView\\DisableAttachementsInPV/ nocase wide ascii
        $registryKeys_DisableUnsafeLocationsInPV = /HKCU\\Software\\Microsoft\\Office\\[0-9]+.[0-9]+\\(Word|Excel)\\Security\\ProtectedView\\DisableUnsafeLocationsInPV/ nocase wide ascii

    condition:
        all of ($registryKeys*)
}

rule LLTTCS_DOCM_Dropper_RunsShellAndAutoOpen
{
    meta:
        source = "u2150600"
        description = "Detects usage of shell execution in docm droppers"
        origin_malware = "Teslacrypt v3.0.1"
        file_type = "bin"
        date = "03/Jan/2024"
        md5hash2 = "7cbefc1d052d5ca36e928827dbdca7f9"
        
    strings:
        $AutoOpen = "AutoOpen" fullword ascii
        $CreateObject = "CreateObject" fullword nocase wide ascii
        $WscriptShell = "WScript.Shell" fullword nocase wide ascii 
        $exec = "exec" fullword nocase wide ascii 

    condition:
        $AutoOpen and $CreateObject and $WscriptShell and $exec
}
