all: beacon_flood

beacon_flood: beacon_flood.o
	gcc -o beacon_flood beacon_flood.o -lpcap
beacon_flood.o: main.h main.c
	gcc -c -o beacon_flood.o main.c -lpcap
clean:
	rm -f beacon_flood
	rm -f *.o
