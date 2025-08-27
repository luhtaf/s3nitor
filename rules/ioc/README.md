# IOC (Indicator of Compromise) Rules

This directory contains IOC files for hash-based malware detection.

## File Structure
- `md5.txt` - MD5 hashes (one per line)
- `sha1.txt` - SHA1 hashes (one per line)  
- `sha256.txt` - SHA256 hashes (one per line)

## Format
Each file should contain one hash per line, without any additional formatting:
```
a1b2c3d4e5f678901234567890123456
f1e2d3c4b5a678901234567890123456
```

## Example Content

### md5.txt
```
d41d8cd98f00b204e9800998ecf8427e
5d41402abc4b2a76b9719d911017c592
```

### sha1.txt
```
da39a3ee5e6b4b0d3255bfef95601890afd80709
aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
```

### sha256.txt
```
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
```

## Sources
- VirusTotal
- MalwareBazaar
- ThreatFox
- Custom analysis results

## Updating IOCs
1. Add new hashes to appropriate files
2. Remove outdated entries
3. Restart scanner to reload IOCs
4. Monitor false positive rates
