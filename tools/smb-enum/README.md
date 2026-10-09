# smb-enum

Send an **SMB2 NEGOTIATE** request and report the dialect chosen and whether
message signing is enabled/required (Go). Light recon that pairs with
`net-neighbors`.

> Authorized use only.

## Usage

```bash
go build -o smb-enum .
./smb-enum 10.0.0.5                       # default port 445
```
