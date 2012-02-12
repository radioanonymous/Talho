// Version 2010-08-18 (http://github.com/ITikhonov/captcha/tree/d67c75a5042b4212877e5bb2249b2728a12913dc)
// zlib/libpng license is at the end of this file

#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <string.h>
#include "libcaptcha.h"

static int8_t *lt[];

void makegif(unsigned char im[70*200], unsigned char gif[GIFSIZE]) {
 	// tag ; widthxheight ; GCT:0:0:7 ; bgcolor + aspect // GCT
 	// Image Separator // left x top // widthxheight // Flags
	// LZW code size
	memcpy(gif,"GIF89a" "\xc8\0\x46\0" "\x83" "\0\0"
		"\x00\x00\x00"
		"\x10\x10\x10"
		"\x20\x20\x20"
		"\x30\x30\x30"
		"\x40\x40\x40"
		"\x50\x50\x50"
		"\x60\x60\x60"
		"\x70\x70\x70"
		"\x80\x80\x80"
		"\x90\x90\x90"
		"\xa0\xa0\xa0"
		"\xb0\xb0\xb0"
		"\xc0\xc0\xc0"
		"\xd0\xd0\xd0"
		"\xe0\xe0\xe0"
		"\xff\xff\xff"
		"," "\0\0\0\0" "\xc8\0\x46\0" "\0" "\x04",13+48+10+1);

	int x,y;
	unsigned char *i=im;
	unsigned char *p=gif+13+48+10+1;
	for(y=0;y<70;y++) {
		*p++=250; // Data length 5*50=250
		for(x=0;x<50;x++)
		{
			unsigned char a=i[0]>>4,b=i[1]>>4,c=i[2]>>4,d=i[3]>>4;

			p[0]=16|(a<<5);			// bbb10000
			p[1]=(a>>3)|64|(b<<7);	// b10000xb
			p[2]=b>>1;			// 0000xbbb
			p[3]=1|(c<<1);		// 00xbbbb1
			p[4]=4|(d<<3);		// xbbbb100
			i+=4;
			p+=5;
		}
	}

 	// Data length // End of LZW (b10001) // Terminator // GIF End
	memcpy(gif+GIFSIZE-4,"\x01" "\x11" "\x00" ";",4);
}

static const int8_t sw[200]={0, 4, 8, 12, 16, 20, 23, 27, 31, 35, 39, 43, 47, 50, 54, 58, 61, 65, 68, 71, 75, 78, 81, 84, 87, 90, 93, 96, 98, 101, 103, 105, 108, 110, 112, 114, 115, 117, 119, 120, 121, 122, 123, 124, 125, 126, 126, 127, 127, 127, 127, 127, 127, 127, 126, 126, 125, 124, 123, 122, 121, 120, 119, 117, 115, 114, 112, 110, 108, 105, 103, 101, 98, 96, 93, 90, 87, 84, 81, 78, 75, 71, 68, 65, 61, 58, 54, 50, 47, 43, 39, 35, 31, 27, 23, 20, 16, 12, 8, 4, 0, -4, -8, -12, -16, -20, -23, -27, -31, -35, -39, -43, -47, -50, -54, -58, -61, -65, -68, -71, -75, -78, -81, -84, -87, -90, -93, -96, -98, -101, -103, -105, -108, -110, -112, -114, -115, -117, -119, -120, -121, -122, -123, -124, -125, -126, -126, -127, -127, -127, -127, -127, -127, -127, -126, -126, -125, -124, -123, -122, -121, -120, -119, -117, -115, -114, -112, -110, -108, -105, -103, -101, -98, -96, -93, -90, -87, -84, -81, -78, -75, -71, -68, -65, -61, -58, -54, -50, -47, -43, -39, -35, -31, -27, -23, -20, -16, -12, -8, -4};


#define MAX(x,y) ((x>y)?(x):(y))

static int letter(int n, int pos, unsigned char im[70*200], unsigned char swr[200], uint8_t s1, uint8_t s2) {
	int8_t *p=lt[n];
	unsigned char *r=im+200*16+pos;
	unsigned char *i=r;
	int sk1=s1+pos;
	int sk2=s2+pos;
	int mpos=pos;
	int row=0;
	for(;*p!=-101;p++) {
		if(*p<0) {
			if(*p==-100) { r+=200; i=r; sk1=s1+pos; row++; continue; }
			i+=-*p;
			continue;
		}

		if(sk1>=200) sk1=sk1%200;
		int skew=sw[sk1]/16;
		sk1+=(swr[pos+i-r]&0x1)+1;

		if(sk2>=200) sk2=sk2%200;
		int skewh=sw[sk2]/70;
		sk2+=(swr[row]&0x1);

		unsigned char *x=i+skew*200+skewh;
		mpos=MAX(mpos,pos+i-r);
		
		if((x-im)<70*200) *x=(*p)<<4;
		i++;
	}
	return mpos-1;
}

#define NDOTS 100

uint32_t dr[NDOTS];

static void line(unsigned char im[70*200], unsigned char swr[200], uint8_t s1) {
	int x;
	int sk1=s1;
	for(x=0;x<199;x++) {
		if(sk1>=200) sk1=sk1%200;
		int skew=sw[sk1]/16;
		sk1+=swr[x]&0x3+1;
		unsigned char *i= im+(200*(45+skew)+x);
		i[0]=0; i[1]=0; i[200]=0; i[201]=0;
	}
}

static void dots(unsigned char im[70*200]) {
	int n;
	for(n=0;n<NDOTS;n++) {
		uint32_t v=dr[n];
		unsigned char *i=im+v%(200*67);
		
		i[0]=0xff;
		i[1]=0xff;
		i[2]=0xff;
		i[200]=0xff;
		i[201]=0xff;
		i[202]=0xff;
	}
}
static void blur(unsigned char im[70*200]) {
	unsigned char *i=im;
	int x,y;
	for(y=0;y<68;y++) {
               for(x=0;x<198;x++) {
			unsigned int c11=*i,c12=i[1],c21=i[200],c22=i[201];
			*i++=((c11+c12+c21+c22)/4);
               }
	}
}

//#include "en_glypths.h"
#include "num_glyphs.h"
#define NUM_GLYPHS	(sizeof(letters) / sizeof(*letters) - 1)

void captcha(unsigned char im[70*200], unsigned char l[6]) {
	unsigned char swr[200];
	uint8_t s1,s2;

	int f=open("/dev/urandom",O_RDONLY);
	read(f,l,5); read(f,swr,200); read(f,dr,sizeof(dr)); read(f,&s1,1); read(f,&s2,1);
	close(f);

	memset(im,0xff,200*70); s1=s1&0x7f; s2=s2&0x3f; l[0]%=NUM_GLYPHS; l[1]%=NUM_GLYPHS; l[2]%=NUM_GLYPHS; l[3]%=NUM_GLYPHS; l[4]%=NUM_GLYPHS; l[5]=0;
	int p=30; p=letter(l[0],p,im,swr,s1,s2); p=letter(l[1],p,im,swr,s1,s2); p=letter(l[2],p,im,swr,s1,s2); p=letter(l[3],p,im,swr,s1,s2); letter(l[4],p,im,swr,s1,s2);
	line(im,swr,s1); dots(im); blur(im);
	l[0]=letters[l[0]]; l[1]=letters[l[1]]; l[2]=letters[l[2]]; l[3]=letters[l[3]]; l[4]=letters[l[4]];
}

#ifdef CAPTCHA

int main() {
	char l[6];
	unsigned char im[70*200];
	unsigned char gif[GIFSIZE];

	captcha(im,l);
	makegif(im,gif);

	write(1,gif,GIFSIZE);
	write(2,l,5);

	return 0;
}

#endif

/*
  http://brokestream.com/captcha.html

  Copyright (C) 2009 Ivan Tikhonov

  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the authors be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.

  Ivan Tikhonov, kefeer@brokestream.com

*/
