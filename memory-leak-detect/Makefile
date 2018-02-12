
TARGET = libmemLeak.so

OBJS = memLeak.o


CC = gcc

CFLAGS += -O0 -g -Wall -fPIC -shared

LDFLAGS += -ldl -lpthread

all:$(TARGET)


$(TARGET):$(OBJS)
	$(CC) $(CFLAGS)  -o $@ $^ $(LDFLAGS)


%.o:%.c
	$(CC) -c $(CFLAGS)  $<  -o $@ 

clean:
	rm -rf $(OBJS) $(TARGET)


