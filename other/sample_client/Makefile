# inclulde ../../external/cryptopp

.PHONY: main sample

# static link
main: main.cpp ../../external/cryptopp/libcryptopp.a
	g++ -o main main.cpp -I../../external/cryptopp -L../../external/cryptopp -lcryptopp
	./main

sample: sample.cpp ../../external/cryptopp/libcryptopp.a
	g++ -o sample sample.cpp -I../../external/cryptopp -L../../external/cryptopp -lcryptopp
	./sample

../../external/cryptopp/libcryptopp.a: ../../external/cryptopp
	cd ../../external/cryptopp && make libcryptopp.a

../../external/cryptopp:
	cd ../../external && git clone https://github.com/weidai11/cryptopp.git cryptopp


