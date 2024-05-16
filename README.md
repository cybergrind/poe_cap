# poe_cap


https://koobik.net/mikrotik-sniff-tzsp/

```
/ip firewall mangle add action=sniff-tzsp chain=prerouting sniff-target=192.168.88.38 sniff-target-port=37009 src-port=6112 protocol=tcp
```
