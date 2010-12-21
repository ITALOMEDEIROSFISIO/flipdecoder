CC=gcc
CFLAGS=-O2 -Wall

OBJECTS=main.o base64.o ebk.o md5.o ripemd.o safer.o
PROGRAM=flipdecoder

all: $(PROGRAM)

$(PROGRAM): $(OBJECTS)
	$(CC) -o $(PROGRAM) $(OBJECTS)

clean:
	rm -f $(PROGRAM) $(OBJECTS)
