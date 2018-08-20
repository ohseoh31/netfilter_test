all : netfilter

netfilter: main.o
	gcc -g -o nfqnl_test main.o -lnetfilter_queue

main.o: header.h
	gcc -c main.c

clean:
	rm -f nfqnl_test
	rm -f *.o

