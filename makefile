LDLIBS += -lnetfilter_queue

all: 1m-block

netfilter-test: 1m-block.cpp

clean:
	rm -f 1m-block *.o
