all: tcp_block

tcp_block: main.o tcp_block.o
	g++ -o tcp_block main.o tcp_block.o -lpcap -ldl

tcp_block.o: tcp_block.cpp
	g++ -c -o tcp_block.o tcp_block.cpp

main.o: main.cpp
	g++ -c -o main.o main.cpp

clean:
	rm -f tcp_block *.o
