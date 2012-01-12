ARCH=$(shell uname -m)

ifeq ($(ARCH),i686)
OFMT=elf32-i386
BARCH=i386
endif

ifeq ($(ARCH),x86_64)
OFMT=elf64-x86-64 
BARCH=i386:x86-64 
endif

#CFLAGS=-O0 -g -fno-inline -Wall
CFLAGS=-O2 -Wall

OBJCOPY=objcopy -I binary -O $(OFMT) -B $(BARCH) --rename-section .data=.rodata,alloc,load,readonly,data,contents

feedbackd: feedbackd.o libcaptcha.o pages.a
	$(CXX) -o$@ $^ -levent $(shell pkg-config --libs libssl)

%.o: %.cpp
	$(CXX) -c -o$@ $(CFLAGS) $<

%.o: %.c
	$(CC) -c -o$@ $(CFLAGS) $<

%.o: html/%.html
	cp $< tmp.html
	head -c 1 /dev/zero >> tmp.html
	 $(OBJCOPY) --redefine-sym _binary_tmp_html_start=html_default_$(shell echo $@ | sed -e 's/^default_//' -e 's/\.o//') -S -K html_default_$(shell echo $@ | sed -e 's/^default_//' -e 's/\.o//') tmp.html $@
	rm -f tmp.html

pages.a: default_ask.o default_ok.o default_err.o
	ar cru $@ $^

clean:
	rm -f feedbackd *.o *.a

tar:
	tar czf feedbackd.tar.gz feedbackd.cpp libcaptcha.[ch] html/default_*.html Makefile

feedbackd.o: feedbackd.cpp libcaptcha.h
libcaptcha.o: libcaptcha.c libcaptcha.h
