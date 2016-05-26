// The MIT License (MIT)
// 
// Copyright (c) 2016 vtdev.com
// This file is part of the CEX Cryptographic library.
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef _CEXENGINE_SERPENT_H
#define _CEXENGINE_SERPENT_H

#include "Common.h"

// *** Serpent S-Boxes *** //

static void Sb0(uint &R0, uint &R1, uint &R2, uint &R3)
{
	uint t1 = R0 ^ R3;
	uint t2 = R2 ^ t1;
	uint t3 = R1 ^ t2;
	R3 = (R0 & R3) ^ t3;
	uint t4 = R0 ^ (R1 & t1);
	R2 = t3 ^ (R2 | t4);
	R0 = R3 & (t2 ^ t4);
	R1 = (~t2) ^ R0;
	R0 ^= (~t4);
}

static void Ib0(uint &R0, uint &R1, uint &R2, uint &R3)
{
	uint t1 = ~R0;
	uint t2 = R0 ^ R1;
	uint t3 = R3 ^ (t1 | t2);
	uint t4 = R2 ^ t3;
	R2 = t2 ^ t4;
	uint t5 = t1 ^ (R3 & t2);
	R1 = t3 ^ (R2 & t5);
	R3 = (R0 & t3) ^ (t4 | R1);
	R0 = R3 ^ (t4 ^ t5);
}

static void Sb1(uint &R0, uint &R1, uint &R2, uint &R3)
{
	uint t1 = R1 ^ (~R0);
	uint t2 = R2 ^ (R0 | t1);
	R2 = R3 ^ t2;
	uint t3 = R1 ^ (R3 | t1);
	uint t4 = t1 ^ R2;
	R3 = t4 ^ (t2 & t3);
	uint t5 = t2 ^ t3;
	R1 = R3 ^ t5;
	R0 = t2 ^ (t4 & t5);
}

static void Ib1(uint &R0, uint &R1, uint &R2, uint &R3)
{
	uint t1 = R1 ^ R3;
	uint t2 = R0 ^ (R1 & t1);
	uint t3 = t1 ^ t2;
	R3 = R2 ^ t3;
	uint t4 = R1 ^ (t1 & t2);
	R1 = t2 ^ (R3 | t4);
	uint t5 = ~R1;
	uint t6 = R3 ^ t4;
	R0 = t5 ^ t6;
	R2 = t3 ^ (t5 | t6);
}

static void Sb2(uint &R0, uint &R1, uint &R2, uint &R3)
{
	uint t1 = ~R0;
	uint t2 = R1 ^ R3;
	uint t3 = t2 ^ (R2 & t1);
	uint t4 = R2 ^ t1;
	uint t5 = R1 & (R2 ^ t3);
	uint t6 = t4 ^ t5;
	R2 = R0 ^ ((R3 | t5) & (t3 | t4));
	R1 = (t2 ^ t6) ^ (R2 ^ (R3 | t1));
	R0 = t3;
	R3 = t6;
}

static void Ib2(uint &R0, uint &R1, uint &R2, uint &R3)
{
	uint t1 = R1 ^ R3;
	uint t2 = R0 ^ R2;
	uint t3 = R2 ^ t1;
	uint t4 = R0 | ~t1;
	R0 = t2 ^ (R1 & t3);
	uint t5 = t1 ^ (t2 | (R3 ^ t4));
	uint t6 = ~t3;
	uint t7 = R0 | t5;
	R1 = t6 ^ t7;
	R2 = (R3 & t6) ^ (t2 ^ t7);
	R3 = t5;
}

static void Sb3(uint &R0, uint &R1, uint &R2, uint &R3)
{
	uint t1 = R0 ^ R1;
	uint t2 = R0 | R3;
	uint t3 = R2 ^ R3;
	uint t4 = (R0 & R2) | (t1 & t2);
	R2 = t3 ^ t4;
	uint t5 = t4 ^ (R1 ^ t2);
	R0 = t1 ^ (t3 & t5);
	uint t6 = R2 & R0;
	R3 = (R1 | R3) ^ (t3 ^ t6);
	R1 = t5 ^ t6;
}

static void Ib3(uint &R0, uint &R1, uint &R2, uint &R3)
{
	uint t1 = R1 ^ R2;
	uint t2 = R0 ^ (R1 & t1);
	uint t3 = R3 | t2;
	uint t4 = R3 ^ (t1 | t3);
	R2 = (R2 ^ t2) ^ t4;
	uint t5 = (R0 | R1) ^ t4;
	R0 = t1 ^ t3;
	R3 = t2 ^ (R0 & t5);
	R1 = R3 ^ (R0 ^ t5);
}

static void Sb4(uint &R0, uint &R1, uint &R2, uint &R3)
{
	uint t1 = R0 ^ R3;
	uint t2 = R2 ^ (R3 & t1);
	uint t3 = R1 | t2;
	R3 = t1 ^ t3;
	uint t4 = ~R1;
	uint t5 = t2 ^ (t1 | t4);
	uint t6 = t1 ^ t4;
	uint t7 = (R0 & t5) ^ (t3 & t6);
	R1 = (R0 ^ t2) ^ (t6 & t7);
	R0 = t5;
	R2 = t7;
}

static void Ib4(uint &R0, uint &R1, uint &R2, uint &R3)
{
	uint t1 = R1 ^ (R0 & (R2 | R3));
	uint t2 = R2 ^ (R0 & t1);
	uint t3 = R3 ^ t2;
	uint t4 = ~R0;
	uint t5 = t1 ^ (t2 & t3);
	uint t6 = R3 ^ (t3 | t4);
	R1 = t3;
	R0 = t5 ^ t6;
	R2 = (t1 & t6) ^ (t3 ^ t4);
	R3 = t5;
}

static void Sb5(uint &R0, uint &R1, uint &R2, uint &R3)
{
	uint t1 = ~R0;
	uint t2 = R0 ^ R1;
	uint t3 = R0 ^ R3;
	uint t4 = (R2 ^ t1) ^ (t2 | t3);
	uint t5 = R3 & t4;
	uint t6 = t5 ^ (t2 ^ t4);
	uint t7 = t3 ^ (t1 | t4);
	R2 = (t2 | t5) ^ t7;
	R3 = (R1 ^ t5) ^ (t6 & t7);
	R0 = t4;
	R1 = t6;
}

static void Ib5(uint &R0, uint &R1, uint &R2, uint &R3)
{
	uint t1 = ~R2;
	uint t2 = R3 ^ (R1 & t1);
	uint t3 = R0 & t2;
	uint t4 = t3 ^ (R1 ^ t1);
	uint t5 = R1 | t4;
	uint t6 = t2 ^ (R0 & t5);
	uint t7 = R0 | R3;
	R2 = (R1 & t7) ^ (t3 | (R0 ^ R2));
	R0 = t7 ^ (t1 ^ t5);
	R1 = t6;
	R3 = t4;
}

static void Sb6(uint &R0, uint &R1, uint &R2, uint &R3)
{
	uint t1 = R0 ^ R3;
	uint t2 = R1 ^ t1;
	uint t3 = R2 ^ (~R0 | t1);
	R1 ^= t3;
	uint t4 = R3 ^ (t1 | R1);
	R2 = t2 ^ (t3 & t4);
	uint t5 = t3 ^ t4;
	R0 = R2 ^ t5;
	R3 = (~t3) ^ (t2 & t5);
}

static void Ib6(uint &R0, uint &R1, uint &R2, uint &R3)
{
	uint t1 = ~R0;
	uint t2 = R0 ^ R1;
	uint t3 = R2 ^ t2;
	uint t4 = R3 ^ (R2 | t1);
	uint t5 = t3 ^ t4;
	uint t6 = t2 ^ (t3 & t4);
	uint t7 = t4 ^ (R1 | t6);
	uint t8 = R1 | t7;
	R0 = t6 ^ t8;
	R2 = (R3 & t1) ^ (t3 ^ t8);
	R1 = t5;
	R3 = t7;
}

static void Sb7(uint &R0, uint &R1, uint &R2, uint &R3)
{
	uint t1 = R1 ^ R2;
	uint t2 = R3 ^ (R2 & t1);
	uint t3 = R0 ^ t2;
	R1 ^= (t3 & (R3 | t1));
	uint t4 = t1 ^ (R0 & t3);
	uint t5 = t3 ^ (t2 | R1);
	R2 = t2 ^ (t4 & t5);
	R0 = (~t5) ^ (t4 & R2);
	R3 = t4;
}

static void Ib7(uint &R0, uint &R1, uint &R2, uint &R3)
{
	uint t1 = R2 | (R0 & R1);
	uint t2 = R3 & (R0 | R1);
	uint t3 = t1 ^ t2;
	uint t4 = R1 ^ t2;
	R1 = R0 ^ (t4 | (t3 ^ ~R3));
	uint t8 = (R2 ^ t4) ^ (R3 | R1);
	R2 = (t1 ^ R1) ^ (t8 ^ (R0 & t3));
	R0 = t8;
	R3 = t3;
}

#endif
