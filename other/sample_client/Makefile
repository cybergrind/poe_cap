# inclulde ../../external/cryptopp

.PHONY: main sample
# use clang
CC=clang
CXX=clang++
# crosscompile for windows params
CXXFLAGS=-O3 --target=x86_64-w64-mingw32 -static-libgcc -static-libstdc++ -Wl,-Bstatic -lstdc++ -lpthread -Wl,-Bdynamic -lws2_32 -lgdi32 -lcrypt32 -luser32 -lkernel32

# static link
main: main.cpp ../../external/cryptopp/libcryptopp.a
	# optimize and crosscompile for windows
	$(CXX) -o main main.cpp -I../../external/cryptopp -L../../external/cryptopp -lcryptopp \
		$(CXXFLAGS)
	# strip unused
	strip -s main.exe
	wine main.exe

sample: sample.cpp ../../external/cryptopp/libcryptopp.a
	g++ -o sample sample.cpp -I../../external/cryptopp -L../../external/cryptopp -lcryptopp
	./sample

../../external/cryptopp/libcryptopp.a: ../../external/cryptopp
	cd ../../external/cryptopp && make libcryptopp.a \
		CC=$(CC) CXX=$(CXX) CXXFLAGS="$(CXXFLAGS)"

../../external/cryptopp:
	cd ../../external && git clone https://github.com/weidai11/cryptopp.git cryptopp


