# inclulde ../../external/cryptopp

.PHONY: main sample clean
USE_TOOLCHAIN?=linux-clang

CXXFLAGS=-O3 -static-libgcc -static-libstdc++ -Wl,-Bstatic \
	-lstdc++ -lpthread -Wl,-Bdynamic -lws2_32 -lgdi32 -lcrypt32 -luser32 -lkernel32 -static \
	-march=native -mtune=native -fno-stack-protector -fno-strict-aliasing

#CXXFLAGS+=--target=x86_64-pc-windows-msvc
ifeq ($(USE_TOOLCHAIN), linux-clang)
	CC=/opt/llvm-mingw/bin/x86_64-w64-mingw32-gcc
	CXX=/opt/llvm-mingw/bin/x86_64-w64-mingw32-g++
	CXXFLAGS+=--target=x86_64-w64-mingw32
else ifeq ($(USE_TOOLCHAIN), windows-clang)
	CC=clang
	CXX=clang++
	CXXFLAGS+=--target=x86_64-pc-windows-msvc
else
#$(error USE_TOOLCHAIN should be linux-clang or windows-clang)
	CC=x86_64-w64-mingw32-gcc
	CXX=x86_64-w64-mingw32-g++
	AR=x86_64-w64-mingw32-gcc-ar
endif


# static link
main: main.cpp ../../external/cryptopp/libcryptopp.a
	# optimize and crosscompile for windows
	$(CXX) -o main main.cpp -I../../external/cryptopp -L../../external/cryptopp -lcryptopp \
		$(CXXFLAGS)
	# strip unused
	strip -s main.exe
	wine main.exe

sample: sample.cpp ../../external/cryptopp/libcryptopp.a
	$(CXX) -o sample sample.cpp -I../../external/cryptopp -L../../external/cryptopp -lcryptopp
	./sample

../../external/cryptopp/libcryptopp.a: ../../external/cryptopp
	cd ../../external/cryptopp && make -j18 libcryptopp.a \
		CC=$(CC) CXX=$(CXX) CXXFLAGS="$(CXXFLAGS)" AR=$(AR)

../../external/cryptopp:
	cd ../../external && git clone https://github.com/weidai11/cryptopp.git cryptopp


clean:
	rm -f main main.exe sample
	cd ../../external/cryptopp && make clean

