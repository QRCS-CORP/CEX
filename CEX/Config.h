#ifndef _CEXENGINE_CONFIG_H
#define _CEXENGINE_CONFIG_H

// much of this file borrowed from crypto++ config.h file..
#ifdef _MSC_VER
	#pragma warning(disable: 4244)
#endif

#define IS_LITTLE_ENDIAN (((union { unsigned x; unsigned char c; }){1}).c)

// define endianess of CPU
#if !defined(IS_LITTLE_ENDIAN)
#	if (defined(__sparc) || defined(__sparc__) || defined(__hppa__) || defined(__PPC__) || defined(__mips__) || (defined(__MWERKS__) && !defined(__INTEL__)))
#		define IS_BIG_ENDIAN
#else
#		define IS_LITTLE_ENDIAN
#	endif
#endif

// get register size
#if defined(__GNUC__) || defined(__MWERKS__)
	#define WORD64_AVAILABLE
	#define W64LIT(x) x##LL
#elif defined(_MSC_VER) || defined(__BCPLUSPLUS__)
	#define WORD64_AVAILABLE
	#define W64LIT(x) x##ui64
#endif

// not a 64-bit CPU
#if !defined(WORD64_AVAILABLE) && !defined(__alpha)
#	define SLOW_WORD64
#endif

// define universal data types
typedef unsigned char byte;

#if (defined(__GNUC__) && !defined(__alpha)) || defined(__MWERKS__)
	typedef unsigned int ushort;
	typedef unsigned long uint;
	typedef unsigned long long ulong;
#elif defined(_MSC_VER) || defined(__BCPLUSPLUS__)
	typedef unsigned __int16 ushort;
	typedef unsigned __int32 uint;
	typedef unsigned __int64 ulong;
#else
	typedef unsigned short ushort;
	typedef unsigned int uint;
	typedef unsigned long ulong;
#endif

// store word size
const unsigned int WORD_SIZE = sizeof(uint);
const unsigned int WORD_BITS = WORD_SIZE * 8;

// intrensics flags
#if defined(_MSC_VER) || defined(__BCPLUSPLUS__)
	#define INTEL_INTRINSICS
	#define FAST_ROTATE
#elif defined(__MWERKS__) && TARGET_CPU_PPC
	#define PPC_INTRINSICS
	#define FAST_ROTATE
#elif defined(__GNUC__) && defined(__i386__)
// GCC does peephole optimizations which should result in using rotate instructions
	#define FAST_ROTATE
#endif


#ifdef __GNUC__
	#define CEX_GCC_VERSION (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)
#endif

// Apple and LLVM's Clang. Apple Clang version 7.0 roughly equals LLVM Clang version 3.7
#if defined(__clang__ ) && !defined(__apple_build_version__)
	#define CEX_CLANG_VERSION (__clang_major__ * 10000 + __clang_minor__ * 100 + __clang_patchlevel__)
#elif defined(__clang__ ) && defined(__apple_build_version__)
	#define CEX_APPLE_CLANG_VERSION (__clang_major__ * 10000 + __clang_minor__ * 100 + __clang_patchlevel__)
#endif

#ifdef _MSC_VER
	#define CEX_MSC_VERSION (_MSC_VER)
#endif

// Need GCC 4.6/Clang 1.7/Apple Clang 2.0 or above due to "GCC diagnostic {push|pop}"
#if (CEX_GCC_VERSION >= 40600) || (CEX_CLANG_VERSION >= 10700) || (CEX_APPLE_CLANG_VERSION >= 20000)
	#define CEX_GCC_DIAGNOSTIC_AVAILABLE 1
#endif

// Clang due to "Inline assembly operands don't work with .intel_syntax", http://llvm.org/bugs/show_bug.cgi?id=24232
// TODO: supply the upper version when LLVM fixes it. We set it to 20.0 for compilation purposes.
#if (defined(CEX_CLANG_VERSION) && CEX_CLANG_VERSION <= 200000) || (defined(CEX_APPLE_CLANG_VERSION) && CEX_APPLE_CLANG_VERSION <= 200000)
	#define CEX_DISABLE_INTEL_ASM 1
#endif



#ifndef CEX_L1_CACHE_LINE_SIZE
	// This should be a lower bound on the L1 cache line size. It's used for defense against timing attacks.
	// Also see http://stackoverflow.com/questions/794632/programmatically-get-the-cache-line-size.
	#if defined(_M_X64) || defined(__x86_64__) || (__ILP32__ >= 1)
		#define CEX_L1_CACHE_LINE_SIZE 64
	#else
		// L1 cache line size is 32 on Pentium III and earlier
		#define CEX_L1_CACHE_LINE_SIZE 32
	#endif
#endif



#if defined(_MSC_VER)
	#if _MSC_VER == 1200
		#include <malloc.h>
	#endif
	#if _MSC_VER > 1200 || defined(_mm_free)
		#define CEX_MSVC6PP_OR_LATER		// VC 6 processor pack or later
	#else
		#define CEX_MSVC6_NO_PP			// VC 6 without processor pack
	#endif
#endif

#ifndef CEX_ALIGN_DATA
	#if defined(CEX_MSVC6PP_OR_LATER)
		#define CEX_ALIGN_DATA(x) __declspec(align(x))
	#elif defined(__GNUC__)
		#define CEX_ALIGN_DATA(x) __attribute__((aligned(x)))
	#else
		#define CEX_ALIGN_DATA(x)
	#endif
#endif

#ifndef CEX_SECTION_ALIGN16
	#if defined(__GNUC__) && !defined(__APPLE__)
		// the alignment attribute doesn't seem to work without this section attribute when -fdata-sections is turned on
		#define CEX_SECTION_ALIGN16 __attribute__((section ("CryptoPP_Align16")))
	#else
		#define CEX_SECTION_ALIGN16
	#endif
#endif


#ifdef CEX_DISABLE_X86ASM		// for backwards compatibility: this macro had both meanings
	#define CEX_DISABLE_ASM
	#define CEX_DISABLE_SSE2
#endif

// Apple's Clang prior to 5.0 cannot handle SSE2 (and Apple does not use LLVM Clang numbering...)
#if defined(CEX_APPLE_CLANG_VERSION) && (CEX_APPLE_CLANG_VERSION < 50000)
	#define CEX_DISABLE_ASM
#endif

#if !defined(CEX_DISABLE_ASM) && ((defined(_MSC_VER) && defined(_M_IX86)) || (defined(__GNUC__) && (defined(__i386__) || defined(__x86_64__))))
	// C++Builder 2010 does not allow "call label" where label is defined within inline assembly
	#define CEX_X86_ASM_AVAILABLE

	#if !defined(CEX_DISABLE_SSE2) && (defined(CEX_MSVC6PP_OR_LATER) || CEX_GCC_VERSION >= 30300 || defined(__SSE2__))
		#define CEX_BOOL_SSE2_ASM_AVAILABLE 1
	#else
		#define CEX_BOOL_SSE2_ASM_AVAILABLE 0
	#endif

	// SSE3 was actually introduced in GNU as 2.17, which was released 6/23/2006, but we can't tell what version of binutils is installed.
	// GCC 4.1.2 was released on 2/13/2007, so we'll use that as a proxy for the binutils version. Also see the output of
	// `gcc -dM -E -march=native - < /dev/null | grep -i SSE` for preprocessor defines available.
	#if !defined(CEX_DISABLE_SSSE3) && (_MSC_VER >= 1400 || CEX_GCC_VERSION >= 40102 || defined(__SSSE3__) || defined(__SSE3__))
		#define CEX_BOOL_SSSE3_ASM_AVAILABLE 1
	#else
		#define CEX_BOOL_SSSE3_ASM_AVAILABLE 0
	#endif
#endif

#if !defined(CEX_DISABLE_ASM) && defined(_MSC_VER) && defined(_M_X64)
	#define CEX_X64_MASM_AVAILABLE
#endif

#if !defined(CEX_DISABLE_ASM) && defined(__GNUC__) && defined(__x86_64__)
	#define CEX_X64_ASM_AVAILABLE
#endif

#if !defined(CEX_DISABLE_SSE2) && (defined(CEX_MSVC6PP_OR_LATER) || defined(__SSE2__)) && !defined(_M_ARM)
	#define CEX_BOOL_SSE2_INTRINSICS_AVAILABLE 1
#else
	#define CEX_BOOL_SSE2_INTRINSICS_AVAILABLE 0
#endif

// Intrinsics availible in GCC 4.3 (http://gcc.gnu.org/gcc-4.3/changes.html) and
//   MSVC 2008 (http://msdn.microsoft.com/en-us/library/bb892950%28v=vs.90%29.aspx)
#if !defined(CEX_DISABLE_SSE2) && !defined(CEX_DISABLE_SSE4) && (((_MSC_VER >= 1500) && !defined(_M_ARM)) || defined(__SSE4_2__))
	#define CEX_BOOL_SSE4_INTRINSICS_AVAILABLE 1
#else
	#define CEX_BOOL_SSE4_INTRINSICS_AVAILABLE 0
#endif

#if !defined(CEX_DISABLE_SSSE3) && !defined(CEX_DISABLE_AESNI) && CEX_BOOL_SSE2_INTRINSICS_AVAILABLE && (CEX_GCC_VERSION >= 40400 || _MSC_FULL_VER >= 150030729 || __INTEL_COMPILER >= 1110 || defined(__AES__))
	#define CEX_BOOL_AESNI_INTRINSICS_AVAILABLE 1
#else
	#define CEX_BOOL_AESNI_INTRINSICS_AVAILABLE 0
#endif

#if CEX_BOOL_SSE2_INTRINSICS_AVAILABLE || CEX_BOOL_SSE2_ASM_AVAILABLE || defined(CEX_X64_MASM_AVAILABLE)
	#define CEX_BOOL_ALIGN16 1
#else
	#define CEX_BOOL_ALIGN16 0
#endif

// how to allocate 16-byte aligned memory (for SSE2)
#if defined(CEX_MSVC6PP_OR_LATER)
	#define CEX_MM_MALLOC_AVAILABLE
#elif defined(__APPLE__)
	#define CEX_APPLE_MALLOC_AVAILABLE
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
	#define CEX_MALLOC_ALIGNMENT_IS_16
#elif defined(__linux__) || defined(__sun__) || defined(__CYGWIN__)
	#define CEX_MEMALIGN_AVAILABLE
#else
	#define CEX_NO_ALIGNED_ALLOC
#endif

#if CEX_BOOL_AESNI_INTRINSICS_AVAILABLE
#	define AESNI_AVAILABLE
#endif

#if defined(__SSE2__)
#	define HAS_SSE2
#endif
#if defined(__SSSE3__)
#	define HAS_SSSE3
#endif
#if defined(__SSE4_1__)
#	define HAS_SSE41
#endif
#if defined(__SSE4_2__)
#	define HAS_SSE42
#endif
#if defined(__AVX__)
#	define HAS_AVX
#endif
#if defined(__XOP__)
#	define HAS_XOP
#endif

#if defined(HAS_AVX2)
#if !defined(HAS_AVX)
#		define HAS_AVX
#	endif
#endif
#if defined(HAS_XOP)
#if !defined(HAS_AVX)
#		define HAS_AVX
#	endif
#endif
#if defined(HAS_AVX)
#if !defined(HAS_SSE41)
#		define HAS_SSE41
#	endif
#endif
#if defined(HAS_SSE41)
#if !defined(HAS_SSSE3)
#		define HAS_SSSE3
#	endif
#endif
#if defined(HAS_SSSE3)
#	define HAS_SSE2
#endif

#if defined(HAS_SSE41) || defined(HAS_SSE42)
#	define HAS_SSE4
#endif

#if defined(_MSC_VER) && !defined(HAS_SSE4) && !defined(HAS_SSSE3) && !defined(HAS_SSE2)
#	if defined(_M_AMD64) || defined(_M_X64) || _M_IX86_FP == 2
#		define HAS_SSSE3
#		define HAS_SSE2
#	elif _MSC_VER >= 1500 && _MSC_FULL_VER >= 150030729
#		define HAS_SSSE3
#		if !defined(HAS_SSE2)
#			define HAS_SSE2
#		endif
#	elif _MSC_VER > 1200 || defined(_mm_free)
#		define HAS_SSE3
#		if !defined(HAS_SSE2)
#			define HAS_SSE2
#		endif
#	endif
#endif

#if defined(HAS_SSE42) || defined(HAS_SSE41) || defined(HAS_SSSE3) || defined(HAS_SSE3)
#	define HAS_ADVINTRIN
#endif

#define CPP_EXCEPTIONS

// this flag calls rotation methods using the intrensic functions on amd and intel
// in many cases the compiler uses intrinsics by default, and forcing api 
// can actually create a slower function
//#define FORCE_ROTATION_INTRENSICS

#endif