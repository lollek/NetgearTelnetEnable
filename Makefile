CFLAGS=-Wall -Wextra -pedantic -g

all: telnetenable
.PHONY: all

telnetenable: md5.o blowfish.o telnetenable.o
	$(CC) $(CFLAGS) -o $@ $^

test: clean telnetenable
	./tests/tests.pl
.PHONY: test

clean :
	$(RM) telnetenable *.o
