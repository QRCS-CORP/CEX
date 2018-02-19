#include "cpucycles.h"

long long cpucycles(void)
{
  unsigned long long result = 0;
  /*asm volatile(".byte 15;.byte 49;shlq $32,%%rdx;orq %%rdx,%%rax"
    : "=a" (result) ::  "%rdx");*/
  return result;
}
