#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#define GIFSIZE 17646

void captcha(unsigned char im[70*200], unsigned char l[6]);
void makegif(unsigned char im[70*200], unsigned char gif[GIFSIZE]);

#ifdef __cplusplus
}
#endif
