#ifndef _DIRTYCOW_H_
#define _DIRTYCOW_H_

int dirtycow(const char *dst, const char *src);
int dirtycow_memcpy(const char *dst, size_t off, size_t n, void *src);


#endif