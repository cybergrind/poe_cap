.PHONY: main.exe

main.exe:
	scp admin@192.168.88.16:devel/poe_cap/other/sample_client/main.exe .
	scp admin@192.168.88.16:devel/poe_cap/other/sample_client/x64/Debug/main.pdb .
	WINEDEBUG=err-hid winedbg --gdb main.exe
