rule redline_new_bin
{
    meta:
        description = "Redline stealer"
        author = "James_inthe_box"
        reference = "https://app.any.run/tasks/4921d1fe-1a14-4bf2-9d27-c443353362a8"
        date = "2021/06"
        maltype = "Stealer"

    strings:
        $string1 = "ReleaseID" ascii
        $string2 = "TaskID" ascii
        $string3 = "geoplugin" ascii
        $string4 = "ScanSteam" ascii
        $string5 = "ScanTelegram" ascii
        $string6 = "ScanScreen" ascii
        $string7 = "Rule" ascii

    condition:
        uint16(0) == 0x5A4D and all of ($string*) and filesize < 800KB
}

rule redline_new_mem
{
    meta:
        description = "Redline stealer"
        author = "James_inthe_box"
        reference = "https://app.any.run/tasks/4921d1fe-1a14-4bf2-9d27-c443353362a8/"
        date = "2021/06"
        maltype = "Stealer"

    strings:
        $string1 = "ReleaseID" ascii
        $string2 = "TaskID" ascii
        $string3 = "geoplugin" ascii
        $string4 = "ScanSteam" ascii
        $string5 = "ScanTelegram" ascii
        $string6 = "ScanScreen" ascii
        $string7 = "Rule" ascii

    condition:
        all of ($string*) and filesize > 800KB
}
