# poe_cap


https://koobik.net/mikrotik-sniff-tzsp/

```
/ip firewall mangle add action=sniff-tzsp chain=prerouting sniff-target=192.168.88.38 sniff-target-port=37009 src-port=6112 protocol=tcp
```

https://github.com/ncatlin/exileSniffer/blob/33794bb0c7ea0ae260452cba3771ea136610132b/exileSniffer/packet_processor.cpp#L655
https://github.com/ncatlin/exileSniffer/blob/33794bb0c7ea0ae260452cba3771ea136610132b/exileSniffer/key_grabber_thread.cpp#L284

https://tbinarii.blogspot.com/2018/05/reverse-engineering-path-of-exile.html



* decompile messages
* notification when preloaded monster model?


* scan for "expand 32-byte k" using scanmem


### other


```

sudo gdb -p 2498580 --batch --ex "bt" --ex detach

sudo gdb -p 2498580 --batch --ex "thread apply all bt" --ex detach

sudo gdb -p 2498580 --batch --ex "b recv" --ex "c" --ex "bt" --ex detach


sudo gdb -p $(pgrep PathOfExileStea) --batch --ex "b *0x141893d25" --ex "c" --ex "info break" --ex "del breakpoint 1" --ex "stepi 200" --ex "bt" --ex "info r" --ex detach /home/kpi/devel/github/poe_cap/poe_annotated.debug
```


find fd of connection

```
sudo lsof -p $(pgrep PathOfExileStea) | ag dtspcd

PathOfExi 2666054  kpi 287u     IPv4           25423963        0t0       TCP xx:36522->203.23.178.243:dtspcd (ESTABLISHED)

287 <- FileDescriptor


sudo gdb -p $(pgrep PathOfExileStea) --batch --ex "catch syscall sendmsg" --ex 'condition 1 $rdi == 296' --ex 'handle SIGUSR1 nostop noprint' --ex "i b" --ex "c" --ex "info break" --ex "bt" --ex "info r" --ex 'x /30x $rsi' --ex detach /home/kpi/devel/github/poe_cap/poe_annotated.debug



# User-level applications use as integer registers for passing the sequence %rdi, %rsi, %rdx, %rcx, %r8 and %r9. The kernel interface uses %rdi, %rsi, %rdx, %r10, %r8 and %r9.

# read: man 2 recvfrom

# ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);
# we're checking memory pointed by rsi register and then watch who is writing to it


sudo gdb -p $(pgrep PathOfExileStea) --batch --ex 'watch 0x0081e280' --ex "i b" --ex "c" --ex "bt" --ex "info r" --ex detach /home/kpi/devel/github/poe_cap/poe_annotated.debug
```
