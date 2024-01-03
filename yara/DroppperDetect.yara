//(evild3ad, 2016)
rule Contains_VBA_macro_code
{
	meta:
		author = "evild3ad"
		description = "Detect a MS Office document with embedded VBA macro code"
		date = "2016-01-09"
		filetype = "Office documents"
        md5hash = "8b404aca7e0ded3145f8a696e2f94a58"
        
	strings:
		$officemagic = { D0 CF 11 E0 A1 B1 1A E1 }
		$zipmagic = "PK"

		$97str1 = "_VBA_PROJECT_CUR" wide
		$97str2 = "VBAProject"
		$97str3 = { 41 74 74 72 69 62 75 74 00 65 20 56 42 5F } // Attribute VB_

		$xmlstr1 = "vbaProject.bin"
		$xmlstr2 = "vbaData.xml"

	condition:
		($officemagic at 0 and any of ($97str*)) or ($zipmagic at 0 and any of ($xmlstr*))
}

rule LLTTCS_DOCM_Dropper_DocumentVariable
{
    meta:
        source = "u2150600"
        description = "Detects a malicious base64 encoded encryption key in document variables"
        origin_malware = "Teslacrypt v3.0.1"
        file_type1 = "xml"
        file_type2 = "bin"
        date = "03/Jan/2024"
        //docm md5hash : "8b404aca7e0ded3145f8a696e2f94a58"
        md5hash_settingsxml = "d23416409d10ffed565b071bbd84f969"
        md5hash_vbaProjectbin = "7cbefc1d052d5ca36e928827dbdca7f9"
        
    strings:
        $docVarName = "kBQHAjmEelVSHUyT" fullword wide ascii
        $docVarVal = "c/blrFFGzJwUDWpdVBM1WO9xExkjgIB9euvb5lcOj3GFDrrKs8VGpDOyfPrp2W+tdIdIxKWVMM81wTkH2Z9unLFgc84o3/FnchOXx/GEr/bJwZW4yNYzXM0NxfmN6h+i+8lIdnPDw/y99zpDvDTK1Rvkc9O0NMCd5NOyBlLNYv2/oBJf/pk1i/ywXqz6SD+Ed4Zv+YiufwJJ2V412ghirofXNRg6HuC8oL/m7KO1Baapnn6VwCYqqtQfvBCgTy7H1aV9av5p//lHil1/JUO7blGt502yy9FBSiuqu5n+YN7rZMfPbhDYkU6EaaZ9xSRnmH5LmIf5wkQ4sImEfBeS966EKhnyxALH2FDISSEQQYpjdJb50BCoJosACu2xHyyfmXRrYBDbjXcQpk36v6HRXExJ/1Ub07jxnY2UXWxZm0+DmgaA81Hnpi02YexVWjdGN2iMJx6Wp3HK9xjPTuE8e7RRmnM=" fullword wide ascii
    condition:
        $docVarName or $docVarVal
}

rule LLTTCS_DOCM_Dropper_WritingRegistry
{
    meta:
        source = "u2150600"
        description = "Detects malicious registry keys used in docm droppers"
        origin_malware = "Teslacrypt v3.0.1"
        file_type = "bin"
        date = "03/Jan/2024"
        //docm md5hash : "8b404aca7e0ded3145f8a696e2f94a58"
        md5hash_vbaProjectbin = "7cbefc1d052d5ca36e928827dbdca7f9"
        
    strings:
        $registryKeys_VBAWarnings = /HKCU\\Software\\Microsoft\\Office\\[0-9]+.[0-9]+\\(Word|Excel)\\Security\\VBAWarnings/ nocase wide ascii
        $registryKeys_DisableInternetFilesInPV = /HKCU\\Software\\Microsoft\\Office\\[0-9]+.[0-9]+\\(Word|Excel)\\Security\\ProtectedView\\DisableInternetFilesInPV/ nocase wide ascii
        $registryKeys_DisableAttachementsInPV = /HKCU\\Software\\Microsoft\\Office\\[0-9]+.[0-9]+\\(Word|Excel)\\Security\\ProtectedView\\DisableAttachementsInPV/ nocase wide ascii
        $registryKeys_DisableUnsafeLocationsInPV = /HKCU\\Software\\Microsoft\\Office\\[0-9]+.[0-9]+\\(Word|Excel)\\Security\\ProtectedView\\DisableUnsafeLocationsInPV/ nocase wide ascii
        $RegWrite = "RegWrite" nocase wide ascii
    condition:
        (all of ($registryKeys*)) and $RegWrite
}

rule LLTTCS_DOCM_Dropper_AutoOpensShell
{
    meta:
        source = "u2150600"
        description = "Detects usage of shell execution in docm droppers"
        origin_malware = "Teslacrypt v3.0.1"
        file_type = "bin"
        date = "03/Jan/2024"
        //docm md5hash : "8b404aca7e0ded3145f8a696e2f94a58"
        md5hash_vbaProjectbin = "7cbefc1d052d5ca36e928827dbdca7f9"
        
    strings:
        $AutoOpen = "AutoOpen" fullword ascii
        $CreateObject = "CreateObject" fullword nocase wide ascii
        $WscriptShell = "WScript.Shell" fullword nocase wide ascii 
        $exec = "exec" fullword nocase wide ascii 

    condition:
        $AutoOpen and $CreateObject and $WscriptShell and $exec
}
