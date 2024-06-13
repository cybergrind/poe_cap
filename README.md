# poe_cap

```
#define PATCHSERVER_PORT 12995
#define LOGINSERVER_PORT 20481
#define GAMESERVER_PORT 6112
```

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

https://github.com/weidai11/cryptopp


### other


```

sudo gdb -p 2498580 --batch --ex "bt" --ex detach

sudo gdb -p 2498580 --batch --ex "thread apply all bt" --ex detach

sudo gdb -p 2498580 --batch --ex "b recv" --ex "c" --ex "bt" --ex detach


sudo gdb -p $(pgrep PathOfExileStea) --batch --ex "b *0x141893d25" --ex "c" --ex "info break" --ex "del breakpoint 1" --ex "stepi 200" --ex "bt" --ex "info r" --ex detach /home/kpi/devel/github/poe_cap/poe_annotated.debug
```

windows abi

```
func1(int a, int b, int c, int d, int e, int f);
// a in RCX, b in RDX, c in R8, d in R9, f then e pushed on stack
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


gdb xxd

```
(gdb) define xxd
dump binary memory dump.bin $arg0 $arg0+$arg1
shell xxd dump.bin
end

(gdb) xxd $rsp 64 
```


poe encryption:

```
search for hex: \x8c@\x02\x00\x00fA\x0fo\x02f
rbp => <string for encryption>
r9  => size, 0x14 (20)
rax => key, 0x40 bytes (starts with expand 32-byte k)

```

poe decryption:

```
rdx => encrypted string
r9  => number of bytes
rax => pointer to used key

//Cryptopp::xorbuf 
B\x0f\xb6\x04\x122\x02\x88\x04\nH\x8dR\x01Is
// it is called from cryptopp::symmetric::processData
// hex signature: 4D 8B 0C 24 33 D2 48 8B C3 49 F7 F6
// escaped
M\x8b\x0c$3\xd2H\x8b\xc3
```


1. save some messages
2. manually find key and save key
3. decrypt saved messagesn
