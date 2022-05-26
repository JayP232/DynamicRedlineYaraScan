import "pe"
import "time"

rule Mal_InfoStealer_Win32_RedLine_Unobfuscated_2021
{
    meta:
        description = "Detects Unobfuscated RedLine Infostealer Executables (.NET)"
        author = "BlackBerry Threat Research Team"
        date = "2021-07"

    strings:
        $x1 = "Account"
        $x2 = "AllWalletsRule"
        $x3 = "Autofill"
        $x4 = "BrowserExtensionsRule"
        $x5 = "BrowserVersion"
        $x6 = "CommandLineUpdate"
        $x7 = "DiscordRule"
        $x8 = "DownloadAndExecuteUpdate"
        $x9 = "FileCopier"
        $x10 = "FileScanner"
        $x11 = "Gecko"
        $x12 = "GeoInfo"
        $x13 = "RecoursiveFileGrabber"
        $x14 = "ResultFactory"
        $x15 = "ScannedBrowser"
        $x16 = "ScannedCookie"
        $x17 = "ScannedFile"
        $x18 = "StringDecrypt"
        $x19 = "SystemInfoHelper"
        $x20 = "UpdateTask"

    condition:

        //PE File
        uint16(0) == 0x5a4d and

        // DotNet Imports
        pe.imports("mscoree.dll", "_CorExeMain") and

        // DotNet Imphash
        pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and

        //All Strings
        all of ($x*)
}
