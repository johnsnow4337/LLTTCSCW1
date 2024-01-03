rule LLTTCS_DOCM_Dropper
{
    meta:
        source = "u2150600"
        description = "Detects malicous VBA macro based droppers"
        origin_malware = "Teslacrypt v3.0.1"
        file_type = "xml"
        date = "03/Jan/2024"
        md5hash = "d23416409d10ffed565b071bbd84f969"
        
    strings:
        $docVarName = "kBQHAjmEelVSHUyT" wide ascii
        $docVarVal = "c/blrFFGzJwUDWpdVBM1WO9xExkjgIB9euvb5lcOj3GFDrrKs8VGpDOyfPrp2W+tdIdIxKWVMM81wTkH2Z9unLFgc84o3/FnchOXx/GEr/bJwZW4yNYzXM0NxfmN6h+i+8lIdnPDw/y99zpDvDTK1Rvkc9O0NMCd5NOyBlLNYv2/oBJf/pk1i/ywXqz6SD+Ed4Zv+YiufwJJ2V412ghirofXNRg6HuC8oL/m7KO1Baapnn6VwCYqqtQfvBCgTy7H1aV9av5p//lHil1/JUO7blGt502yy9FBSiuqu5n+YN7rZMfPbhDYkU6EaaZ9xSRnmH5LmIf5wkQ4sImEfBeS966EKhnyxALH2FDISSEQQYpjdJb50BCoJosACu2xHyyfmXRrYBDbjXcQpk36v6HRXExJ/1Ub07jxnY2UXWxZm0+DmgaA81Hnpi02YexVWjdGN2iMJx6Wp3HK9xjPTuE8e7RRmnM" wide ascii
    condition:
        $docVarName and $docVarVal
}