
ifeq ($(dynamic),yes)
TARGET = libmemhack.so
else

TARGET = libmemhack.a

endif


OBJS = memHack.o

AR = ar 

CC = gcc

AFLAGS += cru

CFLAGS += -g -Wall -fPIC -shared

LDFLAGS += -ldl -lpthread

all:$(TARGET)


ifeq ($(dynamic),yes)

$(TARGET):$(OBJS)
	$(CC) $(CFLAGS)  -o $@ $^ $(LDFLAGS)

else

$(TARGET):$(OBJS)
	$(AR) $(AFLAGS) $@ $^

endif

%.o:%.c
	$(CC) -c $(CFLAGS)  $<  -o $@ 

clean:
	rm -rf $(OBJS) $(TARGET)


