/*
    LocalGuard Antivirus - demo YARA rule
    Safe, non-malicious demonstration rule. Matches EICAR test files by
    content pattern so YARA integration can be verified without any
    real malware sample being present in this repository.
*/

rule LocalGuard_EICAR_Test_File
{
    meta:
        author      = "LocalGuard"
        description = "Standard EICAR antivirus test file"
        severity    = "high"
        category    = "test"
        reference   = "https://www.eicar.org"

    strings:
        // First 26 bytes of the standard EICAR test string:
        // "X5O!P%@AP[4\\PZX54(P^)7CC)7" - verified byte-for-byte
        // against the published string (the 68-char standard string
        // with its documented tail). A 26-byte prefix is plenty for a
        // unique match.
        $eicar = { 58 35 4F 21 50 25 40 41 50 5B 34 5C 50 5A 58 35 34 28 50 5E 29 37 43 43 29 37 }

    condition:
        $eicar
}
