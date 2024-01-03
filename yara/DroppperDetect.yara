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

    condition:
        $docVarName
}