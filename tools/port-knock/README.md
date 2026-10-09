# port-knock

Send a **port-knock sequence** to a host, then probe a target port (Go). Useful
for testing your own `knockd` / `fwknop` setups.

> Authorized use only.

## Usage

```bash
go build -o port-knock .
./port-knock 10.0.0.1 7000,8000,9000 22 tcp 300    # host knocks target [proto] [delay-ms]
```
