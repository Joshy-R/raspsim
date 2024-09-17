#ifndef _TYPEDEFS_H_
#define _TYPEDEFS_H_

typedef __SIZE_TYPE__ size_t;
typedef unsigned long long W64;
typedef signed long long W64s;
typedef unsigned int W32;
typedef signed int W32s;
typedef unsigned short W16;
typedef signed short W16s;
typedef unsigned char byte;
typedef unsigned char W8;
typedef signed char W8s;
#define null NULL

#ifdef __x86_64__
typedef W64 Waddr;
#else
typedef W32 Waddr;
#endif

#endif