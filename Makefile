all: sniff.c
	gcc -g -Wall -o sniff sniff.c -lpcap

clean:
	rm -rf *.o sniff
