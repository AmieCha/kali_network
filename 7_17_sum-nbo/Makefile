TARGET = sum-nbo
CFLAGS = -g

all : $(TARGET)

$(TARGET): main.o
	$(LINK.c) $^  $(LOADLIBES) $(LDLIBS) -o $@

clean :
	rm -f $(TARGET)
	rm -f *.o


