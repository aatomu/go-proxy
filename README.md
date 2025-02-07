# go-proxy
use "Proxy Protocol v2","ip tables"

```bash
#required root permission
ip rule add from 127.0.0.1/8 iif eth1 table 21263
ip route add local 0.0.0.0/0 dev eth1 table 21263
```
