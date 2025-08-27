rule suspicious_pe {
    meta:
        description = "Detects suspicious PE files"
        author = "S3 Scanner"
        date = "2024-01-15"
    strings:
        $dos_header = "This program cannot be run in DOS mode"
        $pe_header = "PE"
    condition:
        $dos_header and $pe_header
}

rule suspicious_strings {
    meta:
        description = "Detects files with suspicious strings"
        author = "S3 Scanner"
    strings:
        $s1 = "cmd.exe" nocase
        $s2 = "powershell" nocase
        $s3 = "http://" nocase
        $s4 = "https://" nocase
    condition:
        any of ($s*)
}

rule large_file {
    meta:
        description = "Detects files larger than 10MB"
        author = "S3 Scanner"
    condition:
        filesize > 10MB
}
