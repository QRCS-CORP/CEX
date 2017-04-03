#ifndef _CEX_INTRINSICS_H
#define _CEX_INTRINSICS_H

#include "CexConfig.h"

#if defined(CEX_COMPILER_MSC)
#	include <intrin.h>		// Microsoft C/C++ compatible compiler
#elif defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__)) 
#	include <x86intrin.h>	// GCC-compatible compiler, targeting x86/x86-64
#elif defined(__GNUC__) && defined(__ARM_NEON__) 
#	include <arm_neon.h>	// GCC-compatible compiler, targeting ARM with NEON
#elif defined(__GNUC__) && defined(__IWMMXT__)
#	include <mmintrin.h>	// GCC-compatible compiler, targeting ARM with WMMX
#elif (defined(__GNUC__) || defined(__xlC__)) && (defined(__VEC__) || defined(__ALTIVEC__)) 
#	include <altivec.h>		// XLC or GCC-compatible compiler, targeting PowerPC with VMX/VSX
#elif defined(__GNUC__) && defined(__SPE__) 
#	include <spe.h>			// GCC-compatible compiler, targeting PowerPC with SPE
#endif

#if defined(CEX_HAS_AVX2)
#	include <zmmintrin.h>
#elif defined(CEX_HAS_AVX)
#	include <immintrin.h>
#elif defined(CEX_HAS_XOP)
#	include <intrin.h>
#	include <xopintrin.h>
#endif
#if defined(CEX_HAS_SSE42)
#	include <nmmintrin.h>
#elif defined(CEX_HAS_SSE41)
#	include <smmintrin.h>
#elif defined(CEX_HAS_SSE4)
#	include <ammintrin.h>
#elif defined(CEX_HAS_SSSE3)
#	include <tmmintrin.h>
#elif defined(CEX_HAS_SSE3)
#	include <pmmintrin.h>
#elif !defined(CEX_HAS_SSE2)
#	include <emmintrin.h>
#elif defined(HAS_SSE)
#	include <xmmintrin.h>
#endif

#endif