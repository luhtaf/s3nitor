# YARA Rules Directory

This directory contains YARA rules for malware pattern matching.

## File Format
- Use `.yar` extension for YARA rule files
- One rule per file or multiple rules in a single file
- Follow YARA syntax and best practices

## Example Rules

### Basic Malware Detection
```yara
rule Malware_Example {
    meta:
        description = "Example malware detection rule"
        author = "Security Team"
        date = "2024-01-01"
    
    strings:
        $s1 = "malware_string" nocase
        $s2 = "suspicious_function" nocase
    
    condition:
        any of them
}
```

### File Type Specific
```yara
rule PE_Malware {
    meta:
        description = "PE file malware detection"
    
    condition:
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3C)) == 0x00004550
}
```

## Adding Rules
1. Create `.yar` files in this directory
2. Restart the scanner to reload rules
3. Test rules before deployment

## Resources
- [YARA Documentation](https://yara.readthedocs.io/)
- [YARA Rule Writing Guide](https://yara.readthedocs.io/en/stable/writingrules.html)
