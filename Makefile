.PHONY: main.exe

main.exe:
	scp admin@192.168.88.16:devel/poe_cap/other/sample_client/main.exe .
	WINEDEBUG=err-hid wine main.exe
