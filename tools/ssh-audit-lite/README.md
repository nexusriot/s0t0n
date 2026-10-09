# ssh-audit-lite

Read a server's SSH banner and **offered algorithms** (KEXINIT) and flag
weak/legacy ones (SHA-1, CBC, RC4, 3DES, DSA, etc). No authentication is
attempted — just the version/algorithm exchange.

> Authorized use only.

## Usage

```bash
go build -o ssh-audit-lite .
./ssh-audit-lite 10.0.0.5 22
```
