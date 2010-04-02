
CC = gcc
CFLAGS = -O3 -funroll-loops
LIBS = -lm -lpthread
SOURCES = bruteforcer.c \
	sha512.c \
	sha512-crypt.c \
	sha512test.c
EXECUTABLE = dumbbrute

dumbbrute:
	${CC} ${CFLAGS} ${LIBS} ${SOURCES} -o ${EXECUTABLE}
	
clean:
	rm dumbbrute *~
