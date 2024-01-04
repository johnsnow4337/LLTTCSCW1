import "pe"

rule LLTTCS_PackedExe1_checkPDB
{
    meta:
        source = "u2150600"
        description = "Finds first packer stage from pe file objects"
        origin_malware = "Teslacrypt v3.0.1"
        indicator_strength = 60
        indicator_generality = 75
        file_type = "exe"
        date = "03/Jan/2024"
        md5hash_unpacked1exe = "1c9885ddd44974a8864019fabb51dddc"
    
    condition:
        pe.pdb_path == "E:\\Tools\\aolfed\\release\\osc.pdb/"
}