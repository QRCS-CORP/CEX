#ifndef _CEX_INTRINSICS_H
#define _CEX_INTRINSICS_H

#include "CexConfig.h"

#if defined(__AVX__)
#	if defined(CEX_COMPILER_MSC)
#		include <intrin.h>		// Microsoft C/C++ compatible compiler
#	elif defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__)) 
#		include <x86intrin.h>	// GCC-compatible compiler, targeting x86/x86-64
#	elif defined(__GNUC__) && defined(__ARM_NEON__) 
#		include <arm_neon.h>	// GCC-compatible compiler, targeting ARM with NEON
#	elif defined(__GNUC__) && defined(__IWMMXT__)
#		include <mmintrin.h>	// GCC-compatible compiler, targeting ARM with WMMX
#	elif (defined(__GNUC__) || defined(__xlC__)) && (defined(__VEC__) || defined(__ALTIVEC__)) 
#		include <altivec.h>		// XLC or GCC-compatible compiler, targeting PowerPC with VMX/VSX
#	elif defined(__GNUC__) && defined(__SPE__) 
#		include <spe.h>			// GCC-compatible compiler, targeting PowerPC with SPE
#	endif
#endif

#endif