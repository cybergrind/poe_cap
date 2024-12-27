.PHONY: main.exe
PWD = $(shell pwd)

venv: requirements.in
	python3 -m venv venv
	./venv/bin/pip install -r requirements.in
	touch venv

main.exe:
	scp admin@192.168.88.16:devel/poe_cap/other/sample_client/main.exe .
	scp admin@192.168.88.16:devel/poe_cap/other/sample_client/x64/Debug/main.pdb .
	WINEDEBUG=err-hid winedbg --gdb main.exe


main: other/sample_client/main.exe
	wine ./other/sample_client/main.exe

other/sample_client/main.exe: other/sample_client/main.cpp other/sample_client/sample.h
	cd other/sample_client && $(MAKE) main


client: other/sample_client/*.h other/sample_client/*.cpp
	cd other/sample_client && $(MAKE) client

py-server:
	VIRTUAL_ENV=$(pwd)/venv uv run other/sample_server/test_server.py


socket_hook: other/socket_hook/socket_hook.c other/sample_client/client.exe
	$(MAKE) -C other/socket_hook socket_hook.so
	rm /tmp/socket.log
	LD_PRELOAD=$(PWD)/other/socket_hook/socket_hook.so wine64 ./other/sample_client/client.exe
	@echo
	@echo Logs:
	cat /tmp/socket.log

socket_hook32: other/socket_hook/socket_hook.c other/sample_client/client.exe
	$(MAKE) -C other/socket_hook socket_hook_x32.so
	LD_PRELOAD=$(PWD)/other/socket_hook/socket_hook_x32.so wine ./other/sample_client/client.exe

socket_hook_macos: other/socket_hook/socket_hook.c other/sample_client/client
	$(MAKE) -C other/socket_hook socket_hook.dylib
	DYLD_INSERT_LIBRARIES=$(PWD)/other/socket_hook/socket_hook.dylib DYLD_FORCE_FLAT_NAMESPACE=1 ./other/sample_client/client


dlsym_hook: other/socket_hook/dlsym_hook.so other/socket_hook/dlsym_hook.c
	$(MAKE) -C other/socket_hook dlsym_hook.so
	LD_PRELOAD=$(PWD)/other/socket_hook/dlsym_hook.so wine64 LD_PRELOAD=$(PWD)/other/socket_hook/dlsym_hook.so ./other/sample_client/client.exe

dlsym_hook32: other/socket_hook/dlsym_hook_x32.so other/socket_hook/dlsym_hook.c
	$(MAKE) -C other/socket_hook dlsym_hook_x32.so
	LD_PRELOAD=./other/socket_hook/dlsym_hook_32.so wine ./other/sample_client/client.exe
