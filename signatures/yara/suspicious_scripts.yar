/*
    LocalGuard Antivirus - starter YARA rules: suspicious scripts.

    Safe, content-based rules for script-borne attack patterns. They
    detect *techniques* (download cradles, obfuscated execution,
    persistence), never specific legitimate software.

    Severity policy (matches LocalGuard's classification philosophy):

        "high"   - pattern is essentially always malicious
        "medium" - strong indicator, but occasionally used by
                   legitimate software: classified as SUSPICIOUS for
                   user review, never auto-deleted

    Add your own rules to this directory (.yar/.yara); they are picked
    up on the next scan. Validate them on the About page or with
    YaraEngine.validate_rules().
*/

rule LocalGuard_Script_PowerShell_Download_Cradle
{
    meta:
        author      = "LocalGuard starter rules"
        description = "Script downloads and executes remote content via PowerShell (common dropper pattern; some installers do this legitimately - review before acting)"
        severity    = "medium"
        category    = "suspicious_script"
        reference   = "https://attack.mitre.org/techniques/T1059/001/"

    strings:
        $ps   = /powershell(\.exe)?"?/              nocase ascii wide
        $dl1  = "DownloadString"                    nocase ascii wide
        $dl2  = "DownloadFile"                      nocase ascii wide
        $dl3  = "DownloadData"                      nocase ascii wide
        $dl4  = "Net.WebClient"                     nocase ascii wide
        $dl5  = "Invoke-WebRequest"                 nocase ascii wide
        $dl6  = "Start-BitsTransfer"                nocase ascii wide
        $ex1  = /\biex\b/                           nocase ascii wide
        $ex2  = /\binvoke-expression\b/             nocase ascii wide
        $ex3  = /\binvoke-command\b/                nocase ascii wide
        $url  = /https?:\/\//                       nocase ascii wide

    condition:
        filesize < 2MB and $ps and 1 of ($dl*) and 1 of ($ex*) and $url
}

rule LocalGuard_Script_Obfuscated_Base64_Execution
{
    meta:
        author      = "LocalGuard starter rules"
        description = "Script executes a large base64-encoded blob (typical obfuscated payload delivery; rare in legitimate scripts)"
        severity    = "medium"
        category    = "suspicious_script"

    strings:
        $ps   = /powershell(\.exe)?"?/              nocase ascii wide
        $enc1 = "-enc "                             nocase ascii wide
        $enc2 = "-encodedcommand"                   nocase ascii wide
        $enc3 = "FromBase64String"                  nocase ascii wide
        $blob = /[A-Za-z0-9+\/=]{300,}/             ascii

    condition:
        filesize < 2MB and $ps and any of ($enc*) and $blob
}

rule LocalGuard_Script_Persistence_Scheduled_Task
{
    meta:
        author      = "LocalGuard starter rules"
        description = "Script creates a scheduled task to re-run an interpreter or script (persistence pattern; verify the task before removing anything)"
        severity    = "medium"
        category    = "persistence"

    strings:
        $schtasks = "schtasks"                      nocase ascii wide
        $create   = "/create"                        nocase ascii wide
        $interp1  = "powershell"                    nocase ascii wide
        $interp2  = "wscript"                       nocase ascii wide
        $interp3  = "cscript"                       nocase ascii wide
        $interp4  = "mshta"                         nocase ascii wide
        $script   = /\.(ps1|vbs|js|bat|cmd|hta)\b/  nocase ascii wide

    condition:
        filesize < 2MB and $schtasks and $create
        and 1 of ($interp*) and $script
}

rule LocalGuard_Script_Mshta_Remote_Execution
{
    meta:
        author      = "LocalGuard starter rules"
        description = "mshta.exe executing remote or inline script payload (mshta with a URL or encoded payload is essentially always malicious)"
        severity    = "high"
        category    = "malware"

    strings:
        $mshta = "mshta"                            nocase ascii wide
        $remote = /mshta(\.exe)?\s+https?:\/\//     nocase ascii wide
        $vbscript = "vbscript:"                     nocase ascii wide

    condition:
        filesize < 2MB and $mshta and ($remote or $vbscript)
}
