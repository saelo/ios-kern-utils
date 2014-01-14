IPHONE_IP:=192.168.1.47
PROJECTNAME:=kdump

SYSROOT:=/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS7.0.sdk
CC:=clang -arch arm64 -isysroot $(SYSROOT)
LDID:=/Users/piotr/Documents/Projects/iphone/kernel/ldid/ldid

INCDIR=../include

CFLAGS += -objc-arc
CFLAGS += -fblocks
CFLAGS += -g0 -O2
CFLAGS += -I $(INCDIR)

SRCDIR=.
OBJS+=$(patsubst %.m,%.o,$(wildcard $(SRCDIR)/*.m))
OBJS+=$(patsubst %.c,%.o,$(wildcard $(SRCDIR)/*.c))
OBJS+=$(patsubst %.cpp,%.o,$(wildcard $(SRCDIR)/*.cpp))

all:	$(PROJECTNAME)
	$(LDID) -Sent.xml $(PROJECTNAME)

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

run: 
ifeq ($(IPHONE_IP),)
	echo "Please set IPHONE_IP"
else
	ssh root@$(IPHONE_IP) /var/mobile/Home/$(PROJECTNAME)
	echo "Application $(PROJECTNAME) was launched"
endif


.PHONY: all clean
