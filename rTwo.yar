import "pe"
import "time"
rule Mal_InfoStealer_Win32_RedLine_Obfuscated_2021
{
    meta:
        description = "Detects Obfuscated RedLine Infostealer Executables (.NET)"
        author = "BlackBerry Threat Research Team"
        date = "2021-07"
    strings:
        // The file name appears to use a ramdom word and never contains numbers
        $x1 = /[a-zA-z]+.exe/
        $x2 = "Signature"
        $x3 = "callback"
        $x4 = "Protect"
        $x5 = "Replace"
        $x6 = "Sleep"
        $x7 = "GetProcAddress"
        $x8 = "LoadLibrary"
        $x9 = "FreeLibrary"
        $x10 = "FromBase64String"
        $x11 = "nCmdShow"
        $x12 = "op_Explicit"
    condition:
        //PE File
        uint16(0) == 0x5a4d and
        // Must have exactly 3 sections
        pe.number_of_sections == 3 and
        // DotNet Imports
        pe.imports("mscoree.dll", "_CorExeMain") and
        // DotNet Imphash
        pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and
        // Timestamp at least 20 years in the future (Unix Time)
        pe.timestamp > time.now() + (31556926*20) and
        // File Version 0.0.0.0
        pe.version_info["FileVersion"] == "0.0.0.0" and
        //All Strings
        all of ($x*) and
}