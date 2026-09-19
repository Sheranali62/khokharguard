/*
    Khokhar & Son's Antivirus - starter YARA rules: shortcut abuse.

    Windows shortcut (.lnk) and URL (.url) files that launch
    interpreters or hide the launch window are the classic USB-dropper
    technique (spec section 10: shortcut files pointing to
    scripts/executables). A .lnk that merely starts a normal
    application does NOT match.

    These rules are format-aware where practical: .lnk files carry a
    4-byte GUID magic (4C 00 00 00) and .url files are INI text, so
    conditions keep false positives near zero.
*/

rule KhokharGuard_LNK_Launches_Script_Interpreter
{
    meta:
        author      = "KhokharGuard starter rules"
        description = "Shortcut file whose target is a script interpreter (wscript/cscript/mshta/cmd) - typical USB dropper launch technique"
        severity    = "high"
        category    = "shortcut_abuse"

    strings:
        $lnk_magic  = { 4C 00 00 00 }
        $interp1    = "wscript"                     ascii wide nocase
        $interp2    = "cscript"                     ascii wide nocase
        $interp3    = "mshta"                       ascii wide nocase
        $interp4    = { 63 6D 64 2E 65 78 65 }      // cmd.exe (plain + wide handled by second)
        $interp4w   = "c\x00m\x00d\x00.\x00e\x00x\x00e" wide ascii
        $interp5    = "powershell"                  ascii wide nocase
        $script_arg = /\.(ps1|vbs|js|hta|bat|cmd)\b/ ascii wide nocase

    condition:
        filesize < 1MB and uint32(0) == 0x0000004C and $lnk_magic
        and (1 of ($interp*) or $script_arg)
}

rule KhokharGuard_LNK_Hidden_Window_Launch
{
    meta:
        author      = "KhokharGuard starter rules"
        description = "Shortcut launching a command interpreter with a hidden window (user sees nothing when the payload runs)"
        severity    = "high"
        category    = "shortcut_abuse"

    strings:
        $min    = "cmd.exe /c "                     ascii wide nocase
        $pswin  = "-WindowStyle Hidden"             ascii wide nocase
        $pswin2 = "-w hidden"                       ascii wide nocase
        $hidden = "cmd.exe /k "                     ascii wide nocase
        $style  = /WindowStyle\s*=\s*[17]/          nocase

    condition:
        filesize < 1MB and uint32(0) == 0x0000004C
        and ($min or $pswin or $pswin2 or $hidden or $style)
}

rule KhokharGuard_URL_Open_Executable_Or_Script
{
    meta:
        author      = "KhokharGuard starter rules"
        description = "Internet shortcut (.url) pointing at a local executable or script instead of a web page - unusual and often malicious on removable drives"
        severity    = "medium"
        category    = "shortcut_abuse"

    strings:
        $ini      = "[InternetShortcut]"             nocase
        // (^|[\r\n]) instead of /m - YARA has no multiline modifier.
        $file_url = /(^|[\r\n])URL\s*=\s*file:\/\/\//i
        $exe      = /\.(exe|dll|scr|com|pif|bat|cmd|ps1|vbs|js|hta)\b/i

    condition:
        filesize < 64KB and $ini and $file_url and $exe
}
