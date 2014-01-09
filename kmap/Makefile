IPHONE_IP:=
PROJECTNAME:=kmap

CC:=ios-clang

CFLAGS += -objc-arc
CFLAGS += -fblocks
CFLAGS += -g0 -O2

SRCDIR=.
OBJS+=$(patsubst %.m,%.o,$(wildcard $(SRCDIR)/*.m))
OBJS+=$(patsubst %.c,%.o,$(wildcard $(SRCDIR)/*.c))
OBJS+=$(patsubst %.cpp,%.o,$(wildcard $(SRCDIR)/*.cpp))

all:	$(PROJECTNAME)
	ldid -Sent.xml $(PROJECTNAME)

$(PROJECTNAME):	$(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(filter %.o,$^) -o $@

%.o:	%.c
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	find . -name \*.o|xargs rm -rf
	rm -f $(PROJECTNAME)

install: all
ifeq ($(IPHONE_IP),)
	echo "Please set IPHONE_IP"
else
	ssh mobile@$(IPHONE_IP) 'mkdir -p /var/mobile/Home'
	ssh mobile@$(IPHONE_IP) 'rm -f /var/mobile/Home/$(PROJECTNAME)'
	scp $(PROJECTNAME) mobile@$(IPHONE_IP):/var/mobile/Home/$(PROJECTNAME)
	echo "Application $(PROJECTNAME) installed"
endif

uninstall:
ifeq ($(IPHONE_IP),)
	echo "Please set IPHONE_IP"
else
	ssh mobile@$(IPHONE_IP) 'rm /var/mobile/Home/$(PROJECTNAME)'
	echo "Application $(PROJECTNAME) uninstalled"
endif

.PHONY: all clean
