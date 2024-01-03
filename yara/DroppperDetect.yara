rule LLTTCS_DOCM_Dropper
{
    meta:
        source = "u2150600"
        description = "Detects malicous VBA macro based droppers"
        origin_malware = "Teslacrypt v3.0.1"
        file_type = "docm"
        date = "03/Jan/2024"
        md5hash = "8b404aca7e0ded3145f8a696e2f94a58"
        
    strings:
        $docVarName = "kBQHAjmEelVSHUyT" wide

    condition:
        contains $docVarName
}