ARCH=$(shell uname -m)

ifeq ($(ARCH),i686)
OFMT=elf32-i386
BARCH=i386
LIBS=$(shell pkg-config --libs libssl)
endif

ifeq ($(ARCH),x86_64)
OFMT=elf64-x86-64 
BARCH=i386:x86-64 
LIBS=$(shell pkg-config --libs libssl)
endif

ifeq ($(ARCH),amd64)
OFMT=elf64-x86-64
BARCH=i386:x86-64
LIBS=-lcrypto -lz
endif

-include Makefile.local

CFLAGS?=-O2 -Wall -I/usr/local/include
LDFLAGS?=-L/usr/local/lib

OBJCOPY?=objcopy -I binary -O $(OFMT) -B $(BARCH) --rename-section .data=.rodata,alloc,load,readonly,data,contents

feedbackd: feedbackd.o http_client.o libcaptcha.o pages.a
	$(CXX) -o$@ $(LDFLAGS) $^ -levent -lctemplate $(LIBS)

%.o: %.cpp
	$(CXX) -c -o$@ $(CFLAGS) $<

%.o: %.c
	$(CC) -c -o$@ $(CFLAGS) $<

%.o: html/%.html
	cp $< tmp.html
	head -c 1 /dev/zero >> tmp.html
	 $(OBJCOPY) --redefine-sym _binary_tmp_html_start=html_default_$(shell echo $@ | sed -e 's/^default_//' -e 's/\.o//') -S -K html_default_$(shell echo $@ | sed -e 's/^default_//' -e 's/\.o//') tmp.html $@
	rm -f tmp.html

tpl_%.h: html/default_%.html
	make_tpl_varnames_h -f$@ $<

pages.a: default_ask.o default_ok.o default_skype.o
	ar cru $@ $^

clean:
	rm -f feedbackd *.o *.a tpl_*.h

tar:
	tar czf feedbackd.tar.gz feedbackd.cpp libcaptcha.[ch] html/default_*.html Makefile

skype: skype.o http_client.o
	$(CXX) -o $@ $^ -levent

http_client.o: http_client.cpp http_client.h
skype.o: skype.cpp http_client.h
feedbackd.o: feedbackd.cpp libcaptcha.h http_client.h tpl_ask.h tpl_ok.h tpl_skype.h
