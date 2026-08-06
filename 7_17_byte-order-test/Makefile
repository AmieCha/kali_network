TARGET=byte-order-test
CXXFLAGS=-g

all: $(TARGET)

$(TARGET): byte-order-test.o
	$(LINK.cpp) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f $(TARGET)
	rm -f *.o

