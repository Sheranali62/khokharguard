/*
    Khokhar & Son's Antivirus - starter YARA rules: autorun abuse.

    Rules for autorun.inf configurations used to auto-execute payloads
    from removable drives (spec section 10). An autorun.inf that merely
    sets an icon or label does NOT match; only configurations that
    auto-run interpreters or commands with script arguments do.

    Autorun files are plain text, so these rules are cheap to evaluate
    on every USB scan.
*/

rule KhokharGuard_Autorun_Open_Script_Or_Hidden_Executable
{
    meta:
        author      = "KhokharGuard starter rules"
        description = "autorun.inf auto-opens a script, interpreter, or hidden-window executable from the drive (classic USB autoplay dropper)"
        severity    = "high"
        category    = "autorun_abuse"

    strings:
        // YARA regexes have no /m modifier; (^|[\r\n]) anchors the
        // INI key at the start of a line instead.
        $open    = /(^|[\r\n])\s*open\s*=/i
        $shellex = /(^|[\r\n])\s*shellexecute\s*=/i

        $interp1 = "wscript.exe"                    nocase
        $interp2 = "cscript.exe"                    nocase
        $interp3 = "mshta.exe"                      nocase
        $interp4 = "powershell"                     nocase
        $interp5 = "cmd.exe"                        nocase

        $hidden  = /\/c\b|\-w\s*hidden|\-windowstyle\s*hidden/i
        $script  = /\.(ps1|vbs|js|hta|bat|cmd|scr|pif)\b/i

    condition:
        filesize < 64KB and ($open or $shellex)
        and (1 of ($interp*) or $hidden or $script)
}

rule KhokharGuard_Autorun_References_Hidden_System_Attributes
{
    meta:
        author      = "KhokharGuard starter rules"
        description = "autorun.inf uses useautoplay with shellexecute on a hidden system file combination - strong USB worm indicator when paired with an executable target"
        severity    = "medium"
        category    = "autorun_abuse"

    strings:
        $shellex = /(^|[\r\n])\s*shellexecute\s*=/i
        $exe     = /\.(exe|scr|pif|com)\b/i
        $action  = /(^|[\r\n])\s*action\s*=/i

    condition:
        filesize < 64KB and $shellex and $exe and not $action
}
