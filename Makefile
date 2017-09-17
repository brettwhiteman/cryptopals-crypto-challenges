CC := gcc
CFLAGS := -std=gnu99 -Wall

cryptopals: src/encoding.o src/main.o src/set_1.o src/util.o src/xor.o
	$(CC) $^ -lcrypto -o cryptopals

all: cryptopals

clean:
	rm src/*.o cryptopals
