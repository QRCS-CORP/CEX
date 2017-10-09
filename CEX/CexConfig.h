#ifndef CEX_CEXCONFIG_H
#define CEX_CEXCONFIG_H

#if !defined(__cplusplus) || __cplusplus < 199711L
#	error compiler is incompatible with this library!
#endif

#include <array>
#include <exception>
#include <iostream>
#include <memory>
#include <stdint.h>
#include <string>
#include <vector>

//////////////////////////////////////////////////////
//		 *** Constants and System Macros ***		//
// Settings in this section can not be modified		//
//////////////////////////////////////////////////////

// compiler types; not all will be supported (targets are msvc, mingw, gcc, intel, and clang)
#if defined(_MSC_VER)
#	define CEX_COMPILER_MSC
#elif defined(__MINGW32__)
#	define CEX_COMPILER_MINGW
#elif defined(__CC_ARM)
#	define CEX_COMPILER_ARM
#elif defined(__BORLANDC__)
#	define CEX_COMPILER_BORLAND
#elif defined(__clang__)
#	define CEX_COMPILER_CLANG
#elif defined(__GNUC__)
#	define CEX_COMPILER_GCC
#elif defined(__IBMC__) || defined(__IBMCPP__)
#	define CEX_COMPILER_IBM
#elif defined(__INTEL_COMPILER) || defined(__ICL)
#	define CEX_COMPILER_INTEL
#elif defined(__MWERKS__)
#	define CEX_COMPILER_MWERKS
#elif defined(__OPEN64__)
#	define CEX_COMPILER_OPEN64
#elif defined(__SUNPRO_C)
#	define CEX_COMPILER_SUNPRO
#elif defined(__TURBOC__)
#	define CEX_COMPILER_TURBO
#endif

// is a supported compiler target
#if (defined(CEX_COMPILER_MSC) || defined(CEX_COMPILER_MINGW) || defined(CEX_COMPILER_CLANG) || defined(CEX_COMPILER_GCC) || defined(CEX_COMPILER_INTEL))
#	define CEX_SUPPORTED_COMPILER
#else
#	error compiler is incompatible with this library!
#endif

// preprocessor os selection (not all OS's will be supported; targets are win/android/linux/ios)
#if defined(_WIN64) || defined(_WIN32)
#	define CEX_OS_WINDOWS
#	if defined(_WIN64)
#		define CEX_ISWIN64
#	elif defined(_WIN32)
#		define CEX_ISWIN32
#	endif
#elif defined(__ANDROID__)
#	define CEX_OS_ANDROID
#elif defined(__APPLE__) || defined(__MACH__)
#	include "TargetConditionals.h"
#	define CEX_OS_APPLE
#	if TARGET_OS_IPHONE && TARGET_IPHONE_SIMULATOR
#		define CEX_ISIPHONESIM
#	elif TARGET_OS_IPHONE
#		define CEX_ISIPHONE
#	else
#		define CEX_ISOSX
#	endif
#elif defined(__linux)
#	define CEX_OS_LINUX
#elif defined(__unix)
#	define CEX_OS_UNIX
#	if defined(__hpux) || defined(hpux)
#		define CEX_OS_HPUX
#	endif
#	if defined(__sun__) || defined(__sun) || defined(sun)
#		define CEX_OS_SUNUX
#	endif
#endif
#if defined(__posix) || defined(_POSIX_VERSION)
#	define CEX_OS_POSIX
#endif

// cpu type (only intel/amd/arm are targeted for support)
#if defined(CEX_COMPILER_MSC)
#	if defined(_M_X64) || defined(_M_AMD64)
#		define CEX_ARCH_X64
#		define CEX_ARCH_X86_X64
#		if defined(_M_AMD64)
#			define CEX_ARCH_AMD64
#		endif
#	elif defined(_M_IX86) || defined(_X86_)
#		define CEX_ARCH_IX86
#		define CEX_ARCH_X86_X64
#	elif defined(_M_ARM)
#		define CEX_ARCH_ARM
#		if defined(_M_ARM_ARMV7VE)
#			define CEX_ARCH_ARMV7VE
#		elif defined(_M_ARM_FP)
#			define CEX_ARCH_ARMFP
#		elif defined(_M_ARM64)
#			define CEX_ARCH_ARM64
#		endif
#	elif defined(_M_IA64)
#		define CEX_ARCH_IA64
#	endif
#elif defined(CEX_COMPILER_GCC)
#	if defined(__amd64__) || defined(__amd64) || defined(__x86_64__) || defined(__x86_64)
#		define CEX_ARCH_X64
#		define CEX_ARCH_X86_X64
#		if defined(_M_AMD64)
#			define CEX_ARCH_AMD64
#		endif
#	elif defined(i386) || defined(__i386) || defined(__i386__)
#		define CEX_ARCH_IX86
#		define CEX_ARCH_X86_X64
#	elif defined(__arm__)
#		define CEX_ARCH_ARM
#		if defined(__aarch64__)
#			define CEX_ARCH_ARM64
#		endif
#	elif defined(__ia64) || defined(__ia64__) || defined(__itanium__)
#		define CEX_ARCH_IA64
#	elif defined(__powerpc64__) || defined(__ppc64__) || defined(__PPC64__) || defined(__64BIT__) || defined(_LP64) || defined(__LP64__)
#		define CEX_ARCH_PPC
#	elif defined(__sparc) || defined(__sparc__)
#		define CEX_ARCH_SPARC
#		if defined(__sparc64__)
#			define CEX_ARCH_SPARC64
#		endif
#	endif
#endif

// supported os targets
#if (defined(CEX_OS_WINDOWS) || defined(CEX_OS_ANDROID) || defined(CEX_OS_APPLE) || defined(CEX_OS_POSIX))
#	define CEX_SUPPORTED_OS 1
#else
#	define CEX_SUPPORTED_OS 0
#endif

// msc specific
#if defined(_MSC_VER)
#	define CEX_MSC_VERSION (_MSC_VER)
#endif
// integer type converted to a smaller integer type
#if defined(_MSC_VER)
#	pragma warning(disable: 4244)
#endif

// detect endianess
#define IS_LITTLE_ENDIAN (((union { unsigned x; unsigned char c; }){1}).c)

// stringify helper
#define STR_HELPER(x) #x
#define TOSTRING(x) STR_HELPER(x)

// define endianess of CPU
#if !defined(IS_LITTLE_ENDIAN)
#	if (defined(__sparc) || defined(__sparc__) || defined(__hppa__) || defined(__PPC__) || defined(__mips__) || (defined(__MWERKS__) && !defined(__INTEL__)))
#		define IS_BIG_ENDIAN
#	else
#		define IS_LITTLE_ENDIAN
#	endif
#endif

// get register size
#if defined(__GNUC__) || defined(__MWERKS__)
#	define WORD64_AVAILABLE
#	define W64LIT(x) x##LL
#elif defined(_MSC_VER) || defined(__BCPLUSPLUS__)
#	define WORD64_AVAILABLE
#	define W64LIT(x) x##ui64
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

// OS intrinsics flags
#if defined(_MSC_VER) || defined(__BCPLUSPLUS__)
#	define CEX_HAS_MINSSE
#	define CEX_FAST_ROTATE
#elif defined(__MWERKS__) && TARGET_CPU_PPC
#	define CEX_PPC_INTRINSICS
#	define CEX_FAST_ROTATE
#elif defined(__GNUC__) && defined(__i386__)
	// GCC does peephole optimizations which should result in using rotate instructions
#	define CEX_FAST_ROTATE
#endif

// get the gcc version
#if defined(__GNUC__)
#	define CEX_GCC_VERSION (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)
#endif
// gcc asm support
#if !defined(CEX_USE_GCC_INLINE_ASM) && defined(__GNUG__)
#	define CEX_USE_GCC_INLINE_ASM 1
#endif

// Apple and LLVM's Clang. Apple Clang version 7.0 roughly equals LLVM Clang version 3.7
#if defined(__clang__ ) && !defined(__apple_build_version__)
#	define CEX_CLANG_VERSION (__clang_major__ * 10000 + __clang_minor__ * 100 + __clang_patchlevel__)
#elif defined(__clang__ ) && defined(__apple_build_version__)
#	define CEX_APPLE_CLANG_VERSION (__clang_major__ * 10000 + __clang_minor__ * 100 + __clang_patchlevel__)
#endif

// intrinsics support level
#if defined(__SSE2__)
#	define CEX_HAS_SSE2
#endif
#if defined(__SSE3__)
#	define CEX_HAS_SSE3
#endif
#if defined(__SSSE3__)
#	define CEX_HAS_SSSE3
#endif
#if defined(__SSE4_1__)
#	define CEX_HAS_SSE41
#endif
#if defined(__SSE4_2__)
#	define CEX_HAS_SSE42
#endif
#if defined(__AVX__)
#	define CEX_HAS_AVX
#endif
#if defined(__AVX2__)
#	define CEX_HAS_AVX2
#endif
#if defined(CEX_HAS_AVX2)
#if !defined(CEX_HAS_AVX)
#		define CEX_HAS_AVX
#	endif
#endif
#if defined(CEX_HAS_AVX)
#	if !defined(CEX_HAS_SSE4)
#		define CEX_HAS_SSE4
#	endif
#endif
#if defined(CEX_HAS_SSE41) || defined(CEX_HAS_SSE42)
#	if !defined(CEX_HAS_SSE4)
#		define CEX_HAS_SSE4
#	endif
#endif
#if defined(CEX_HAS_SSE4)
#	if !defined(CEX_HAS_SSSE3)
#		define CEX_HAS_SSSE3
#	endif
#endif
#if defined(CEX_HAS_SSSE3)
#	if !defined(CEX_HAS_SSE3)
#		define CEX_HAS_SSE3
#	endif
#endif
#if defined(CEX_HAS_SSE3)
#	if !defined(CEX_HAS_SSE2)
#		define CEX_HAS_SSE2
#	endif
#endif
#if defined(__XOP__)
#	define CEX_HAS_XOP
#endif
#if defined(CEX_OS_WINDOWS)
#	if defined(_M_AMD64) || defined(_M_X64) || _M_IX86_FP == 2
#		if !defined(CEX_HAS_SSE2)
#			define CEX_HAS_SSE2
#		endif
#	endif
#endif

// native openmp support
#if defined(_OPENMP)
#	if _OPENMP == 201511
#		define CEX_OPENMP_VERSION_45
#	elif _OPENMP == 201307
#		define CEX_OPENMP_VERSION_40
#	elif _OPENMP == 201107
#		define CEX_OPENMP_VERSION_31
#	elif _OPENMP == 200805
#		define CEX_OPENMP_VERSION_30
#	elif _OPENMP == 200505
#		define CEX_OPENMP_VERSION_25
#	elif _OPENMP == 200203
#		define CEX_OPENMP_VERSION_20
#	endif
#endif

// instructs the compiler to skip optimizations on the contained function; closed with CEX_OPTIMIZE_RESUME
#if defined(CEX_COMPILER_MSC)
#	define CEX_OPTIMIZE_IGNORE __pragma(optimize("", off))
#elif defined(CEX_COMPILER_GCC) || defined(CEX_COMPILER_MINGW)
#	define CEX_OPTIMIZE_IGNORE _Pragma(TOSTRING(GCC optimize("O0")))
#elif defined(CEX_COMPILER_CLANG)
#	define CEX_OPTIMIZE_IGNORE __attribute__((optnone))
#elif defined(CEX_COMPILER_INTEL)
#	define CEX_OPTIMIZE_IGNORE pragma optimize("", off) 
#else
#	define CEX_OPTIMIZE_IGNORE 0
#endif

// end of section; resume compiler optimizations
#if defined(CEX_COMPILER_MSC)
#	define CEX_OPTIMIZE_RESUME __pragma(optimize("", on))
#elif defined(CEX_COMPILER_GCC) || defined(CEX_COMPILER_MINGW)
#	define CEX_OPTIMIZE_RESUME _Pragma(TOSTRING(GCC pop_options))
#elif defined(CEX_COMPILER_INTEL)
#	define CEX_OPTIMIZE_RESUME pragma optimize("", on) 
#else
#	define CEX_OPTIMIZE_RESUME 0
#endif

#if !defined(_DEBUG)
#	define CEX_NO_DEBUG
#endif

inline static void CexAssert(bool Condition, const char* Message)
{
#if !defined(CEX_NO_DEBUG)
	if (!Condition)
	{
		std::cerr << "Assertion failed in " << __FILE__ << " line " << __LINE__ << ": " << Message << std::endl;
		std::terminate();
	} 
#endif
}

//////////////////////////////////////////////////
//		*** User Configurable Section ***		//
// Settings in this section can be modified		//
//////////////////////////////////////////////////

// enables/disables OS rotation intrinsics
#if defined(CEX_FAST_ROTATE) && defined(CEX_HAS_MINSSE)
#	define CEX_FASTROTATE_ENABLED
#endif

// prefetch base multiplier used by the symmetric cipher modes parallel block calculation
#define CEX_PREFETCH_BASE size_t = 2048

// pre-loads tables in rhx and thx into L1 for performance and as a timing attack counter measure
#define CEX_PREFETCH_RHX_TABLES
#define CEX_PREFETCH_THX_TABLES

// AVX512 Capabilities Check
// TODO: future expansion (if you can test it, I'll add it)
// links: 
// https://software.intel.com/en-us/intel-cplusplus-compiler-16.0-user-and-reference-guide
// https://software.intel.com/en-us/articles/compiling-for-the-intel-xeon-phi-processor-and-the-intel-avx-512-isa
// https://colfaxresearch.com/knl-avx512/
// 
// #include <immintrin.h>
// supported is 1: ex. __AVX512CD__ 1
//F		__AVX512F__					Foundation
//CD	__AVX512CD__				Conflict Detection Instructions(CDI)
//ER	__AVX512ER__				Exponential and Reciprocal Instructions(ERI)
//PF	__AVX512PF__				Prefetch Instructions(PFI)
//DQ	__AVX512DQ__				Doubleword and Quadword Instructions(DQ)
//BW	__AVX512BW__				Byte and Word Instructions(BW)
//VL	__AVX512VL__				Vector Length Extensions(VL)
//IFMA	__AVX512IFMA__				Integer Fused Multiply Add(IFMA)
//VBMI	__AVX512VBMI__				Vector Byte Manipulation Instructions(VBMI)
//VNNIW	__AVX5124VNNIW__			Vector instructions for deep learning enhanced word variable precision
//FMAPS	__AVX5124FMAPS__			Vector instructions for deep learning floating - point single precision
//VPOPCNT	__AVX512VPOPCNTDQ__		?

// Note: AVX512 is currently untested, this flag enables support on a compliant system
//#define CEX_AVX512_SUPPORTED

#if defined(__AVX512F__) && (__AVX512F__ == 1) && defined(CEX_AVX512_SUPPORTED)
#	include <immintrin.h>
#	if !defined(__AVX512__)
#		define __AVX512__
#	endif
#endif

// EOF
#endif

