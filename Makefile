.PHONY: main.exe

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

other/sample_client/main.exe:
	cd other/sample_client && $(MAKE) main


py-server:
	VIRTUAL_ENV=$(pwd)/venv uv run other/sample_server/test_server.py
