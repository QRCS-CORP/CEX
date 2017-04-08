#ifndef _CEX_CEXCONFIG_H
#define _CEX_CEXCONFIG_H

// some of this file borrowed from crypto++ config.h file and Botan Buildh.in

// common headers
#include <cstring>
#include <exception>
#include <iostream>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

// library version info
static const int CEX_VERSION_MAJOR = 1; // A1 series
static const int CEX_VERSION_MINOR = 0;
static const int CEX_VERSION_PATCH = 1;
static const int CEX_VERSION_RELEASE = 1;

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
	static const int CEX_SUPPORTED_COMPILER = 1;
#else
	static const int CEX_SUPPORTED_COMPILER = 0;
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
#	define CEX_MSC_VERSION  (_MSC_VER)
#endif
#ifdef _MSC_VER
#	pragma warning(disable: 4244)
#endif

// detect endianess
#define IS_LITTLE_ENDIAN (((union { unsigned x; unsigned char c; }){1}).c)

// common functions
#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x)) 
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))
#define GETBITMASK(index, size) (((1 << (size)) - 1) << (index))
#define READBITSFROM(data, index, size) (((data) & GETBITMASK((index), (size))) >> (index))
#define WRITEBITSTO(data, index, size, value) ((data) = ((data) & (~GETBITMASK((index), (size)))) | ((value) << (index)))

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

// store word size
const unsigned int WORD_SIZE = sizeof(uint);
const unsigned int WORD_BITS = WORD_SIZE * 8;

// intrensics flags
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

// Need GCC 4.6/Clang 1.7/Apple Clang 2.0 or above due to "GCC diagnostic {push|pop}"
#if (CEX_GCC_VERSION >= 40600) || (CEX_CLANG_VERSION >= 10700) || (CEX_APPLE_CLANG_VERSION >= 20000)
#	define CEX_GCC_DIAGNOSTIC_AVAILABLE 1
#endif

// Clang due to "Inline assembly operands don't work with .intel_syntax", http://llvm.org/bugs/show_bug.cgi?id=24232
// TODO: supply the upper version when LLVM fixes it. We set it to 20.0 for compilation purposes.
#if (defined(CEX_CLANG_VERSION) && CEX_CLANG_VERSION <= 200000) || (defined(CEX_APPLE_CLANG_VERSION) && CEX_APPLE_CLANG_VERSION <= 200000)
#	define CEX_DISABLE_INTEL_ASM 1
#endif

#if !defined(CEX_L1_CACHE_LINE_SIZE)
// This should be a lower bound on the L1 cache line size. It's used for defense against timing attacks.
// Also see http://stackoverflow.com/questions/794632/programmatically-get-the-cache-line-size.
#	if defined(_M_X64) || defined(__x86_64__) || (__ILP32__ >= 1)
#		define CEX_L1_CACHE_LINE_SIZE 64
#	else
		// L1 cache line size is 32 on Pentium III and earlier
#		define CEX_L1_CACHE_LINE_SIZE 32
#	endif
#endif

#if defined(_MSC_VER)
#	if _MSC_VER == 1200
#		include <malloc.h>
#	endif
#	if _MSC_VER > 1200 || defined(_mm_free)
#		define CEX_MSVC6PP_OR_LATER		// VC 6 processor pack or later
#	else
#		define CEX_MSVC6_NO_PP		   // VC 6 without processor pack
#	endif
#endif

#if !defined(CEX_ALIGN_DATA)
#	if defined(CEX_MSVC6PP_OR_LATER)
#		define CEX_ALIGN_DATA(x) __declspec(align(x))
#	elif defined(__GNUC__)
#		define CEX_ALIGN_DATA(x) __attribute__((aligned(x)))
#	else
#		define CEX_ALIGN_DATA(x)
#	endif
#endif

#if !(CEX_SECTION_ALIGN16)
#	if defined(__GNUC__) && !defined(__APPLE__)
		// the alignment attribute doesn't seem to work without this section attribute when -fdata-sections is turned on
#		define CEX_SECTION_ALIGN16 __attribute__((section ("CryptoPP_Align16")))
#	else
#		define CEX_SECTION_ALIGN16
#	endif
#endif

// for backwards compatibility: this macro had both meanings
#if defined(CEX_DISABLE_X86ASM)	
#	define CEX_DISABLE_ASM
#	define CEX_DISABLE_SSE2
#endif

// Apple's Clang prior to 5.0 cannot handle SSE (and Apple does not use LLVM Clang numbering...)
#if defined(CEX_APPLE_CLANG_VERSION) && (CEX_APPLE_CLANG_VERSION < 50000)
#	define CEX_DISABLE_ASM
#endif

#if !defined(CEX_DISABLE_ASM) && (defined(_MSC_VER) && defined(_M_IX86) || (defined(__GNUC__) && (defined(__i386__) || defined(__x86_64__))))
	// C++Builder 2010 does not allow "call label" where label is defined within inline assembly
#	define CEX_X86_ASM_AVAILABLE
#	if !defined(CEX_DISABLE_SSE2) && (defined(CEX_MSVC6PP_OR_LATER) || CEX_GCC_VERSION >= 30300 || defined(__SSE2__))
#		define CEX_BOOL_SSE2_ASM_AVAILABLE 1
#	else
#		define CEX_BOOL_SSE2_ASM_AVAILABLE 0
#	endif
	// SSE3 was actually introduced in GNU as 2.17, which was released 6/23/2006, but we can't tell what version of binutils is installed.
	// GCC 4.1.2 was released on 2/13/2007, so we'll use that as a proxy for the binutils version. Also see the output of
	// gcc -dM -E -march=native - < /dev/null | grep -i SSE` for preprocessor defines available.
#	if !defined(CEX_DISABLE_SSSE3) && (_MSC_VER >= 1400 || CEX_GCC_VERSION >= 40102 || defined(__SSSE3__) || defined(__SSE3__))
#		define CEX_BOOL_SSSE3_ASM_AVAILABLE 1
#	else
#		define CEX_BOOL_SSSE3_ASM_AVAILABLE 0
#	endif
#endif

// x64 asm support
#if !defined(CEX_DISABLE_ASM) && defined(_MSC_VER) && defined(_M_X64)
#	define CEX_X64_MASM_AVAILABLE
#endif
#if !defined(CEX_DISABLE_ASM) && defined(__GNUC__) && defined(__x86_64__)
#	define CEX_X64_ASM_AVAILABLE
#endif

#if !defined(CEX_DISABLE_SSE2) && (defined(CEX_MSVC6PP_OR_LATER) || defined(__SSE2__)) && !defined(_M_ARM)
#	define CEX_BOOL_SSE2_INTRINSICS_AVAILABLE 1
#else
#	define CEX_BOOL_SSE2_INTRINSICS_AVAILABLE 0
#endif

// Intrinsics availible in GCC 4.3 (http://gcc.gnu.org/gcc-4.3/changes.html) and
//   MSVC 2008 (http://msdn.microsoft.com/en-us/library/bb892950%28v=vs.90%29.aspx)
#if !defined(CEX_DISABLE_SSE2) && !defined(CEX_DISABLE_SSE4) && (((_MSC_VER >= 1500) && !defined(_M_ARM)) || defined(__SSE4_2__))
#	define CEX_BOOL_SSE4_INTRINSICS_AVAILABLE 1
#else
#	define CEX_BOOL_SSE4_INTRINSICS_AVAILABLE 0
#endif

#if !defined(CEX_DISABLE_SSSE3) && !defined(CEX_DISABLE_AESNI) && CEX_BOOL_SSE2_INTRINSICS_AVAILABLE && (CEX_GCC_VERSION >= 40400 || _MSC_FULL_VER >= 150030729 || __INTEL_COMPILER >= 1110 || defined(__AES__))
#	define CEX_BOOL_AESNI_INTRINSICS_AVAILABLE 1
#else
#	define CEX_BOOL_AESNI_INTRINSICS_AVAILABLE 0
#endif

#if CEX_BOOL_SSE2_INTRINSICS_AVAILABLE || CEX_BOOL_SSE2_ASM_AVAILABLE || defined(CEX_X64_MASM_AVAILABLE)
#	define CEX_BOOL_ALIGN16 1
#else
#	define CEX_BOOL_ALIGN16 0
#endif

// how to allocate 16-byte aligned memory (for SSE)
#if defined(CEX_MSVC6PP_OR_LATER)
#		define CEX_MM_MALLOC_AVAILABLE
#	elif defined(__APPLE__)
#		define CEX_APPLE_MALLOC_AVAILABLE
#	elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#		define CEX_MALLOC_ALIGNMENT_IS_16
#	elif defined(__linux__) || defined(__sun__) || defined(__CYGWIN__)
#		define CEX_MEMALIGN_AVAILABLE
#	else
#		define CEX_NO_ALIGNED_ALLOC
#endif

#if CEX_BOOL_AESNI_INTRINSICS_AVAILABLE
#	define CEX_AESNI_AVAILABLE
#endif

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

// enables fast rotation intrinsics
#define CEX_FASTROTATE_ENABLED

#define TOSTRING(a) #a

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
#	define CEX_NODEBUG
#endif

#if !defined(CEX_NODEBUG)
#   define CEXASSERT(condition, message) \
    do { \
        if (! (condition)) { \
            std::cerr << "Assertion `" #condition "` failed in " << __FILE__ \
                      << " line " << __LINE__ << ": " << message << std::endl; \
            std::terminate(); \
        } \
    } while (false)
#else
#   define CEXASSERT(condition, message) do { } while (false)
#endif

// prefetch base offset in parallel block calculation
#define CEX_PREFETCH_BASE size_t = 2048

// EOF
#endif

