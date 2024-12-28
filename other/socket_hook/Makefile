
socket_hook.so: socket_hook.c
	gcc -shared -fPIC -o socket_hook.so socket_hook.c -ldl -O2

# macos
socket_hook.dylib: socket_hook.c
	clang -shared -fPIC -o socket_hook.dylib socket_hook.c -ldl

# x32 version
socket_hook_x32.so: socket_hook.c
	gcc -shared -fPIC -o socket_hook_x32.so socket_hook.c -ldl -m32

dlsym_hook.so: dlsym_hook.c
	gcc -shared -fPIC -o dlsym_hook.so dlsym_hook.c -ldl -D__x86_64__

dlsym_hook_x32.so: dlsym_hook.c
	gcc -shared -fPIC -o dlsym_hook_x32.so dlsym_hook.c -ldl -m32
