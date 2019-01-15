#ifndef CEX_CEXCONFIG_H
#define CEX_CEXCONFIG_H

/*lint -e10 */		// bogus missing brace exception caused by namespace macro
/*lint -e96 */		// masks unmatched brace reported in internal type_traits
/*lint -e537 */		// unavoidable 'repeated include file' reported because of namespace header
/*lint -e686 */		// warns that MS and VS external errors are muted
/*lint -e766 */		// bogus unused header, informational
/*lint -e974 */		// 'recursion warning' elective
/*lint -e1904 */	// 'C style comment' required by lint
/*lint -e1960 */	// unparenthesized macro parameter.. must be in here, but I can't find it

#if (!defined(__cplusplus))
#	error compiler is incompatible with this library!
#elif ((__cplusplus) < 199711L)
#	error compiler must be C++ 14 compatible!
#endif

#include <array>
#include <iostream>
#include <memory>
#include <stdint.h>
#include <string>
#include <vector>

//#include "SecureVector.h"

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
#if defined(CEX_COMPILER_MSC) || defined(CEX_COMPILER_MINGW) || defined(CEX_COMPILER_CLANG) || defined(CEX_COMPILER_GCC) || defined(CEX_COMPILER_INTEL)
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
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__bsdi__) || defined(__DragonFly__) || defined(_SYSTYPE_BSD)
#	define CEX_OS_BSD
#elif defined(__OpenBSD__)
#	define CEX_OS_OPENBSD
#elif defined(__APPLE__) || defined(__MACH__)
#	include "TargetConditionals.h"
#	define CEX_OS_APPLE
#	if defined(TARGET_OS_IPHONE) && defined(TARGET_IPHONE_SIMULATOR)
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
#	define <unistd.h>
#endif

#if defined(_WIN32)
#	define CEX_HAS_VIRTUALLOCK
#	define CEX_HAS_RTLSECUREMEMORY
#endif

#if defined(_POSIX_MEMLOCK_RANGE)
#	define CEX_HAS_POSIXMLOCK
#endif

// the secure allocator is enabled
#if defined(CEX_HAS_VIRTUALLOCK) || defined(CEX_HAS_POSIXMLOCK)
#	define CEX_SECURE_ALLOCATOR
#endif

#define CEX_SECMEMALLOC_DEFAULT 4096
#define CEX_SECMEMALLOC_MIN 16
#define CEX_SECMEMALLOC_MAX 128
#define CEX_SECMEMALLOC_MAXKB 512

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
#	elif defined(__alpha)
#		define CEX_ARCH_ALPHA
#	endif
#endif

#if defined(__GNUG__) || defined(__clang__)
#	define CEX_MALLOC_FN __attribute__((malloc))
#elif defined(_MSC_VER)
#	define CEX_MALLOC_FN __declspec(restrict)
#else
#	define CEX_MALLOC_FN
#endif

#if defined(CEX_ARCH_X64) || defined(CEX_ARCH_AMD64) || defined(CEX_ARCH_ARM64) || defined(CEX_ARCH_IA64)
#	define CEX_IS_X64
#endif

// supported os targets
#if defined(CEX_OS_WINDOWS) || defined(CEX_OS_ANDROID) || defined(CEX_OS_APPLE) || defined(CEX_OS_POSIX)
#	define CEX_SUPPORTED_OS 1
#	define CEX_OS_HASTHREADS
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
#define CEX_IS_LITTLE_ENDIAN (((union { unsigned x; unsigned char c; }){1}).c)

// define endianess of CPU
#if (!defined(CEX_IS_LITTLE_ENDIAN))
#	if defined(__sparc) || defined(__sparc__) || defined(__hppa__) || defined(__PPC__) || defined(__mips__) || defined(__MWERKS__) && (!defined(__INTEL__))
#		define CEX_IS_BIG_ENDIAN
#	else
#		if !defined(CEX_IS_LITTLE_ENDIAN)
#			define CEX_IS_LITTLE_ENDIAN
#		endif
#	endif
#endif

// define universal data types
typedef unsigned char byte;

#if (defined(__GNUC__) && (!defined(__alpha))) || defined(__MWERKS__)
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

// 128 bit unsigned integer support
#if defined(__SIZEOF_INT128__) && defined(CEX_IS_X64) && !defined(__xlc__)
#define CEX_NATIVE_UINT128

	// Prefer TI mode over __int128 as GCC rejects the latter in pedantic mode
#if defined(__GNUG__)
	typedef unsigned int uint128_t __attribute__((mode(TI)));
#else
	typedef unsigned __int128 uint128_t;
#endif
#endif

#if defined(CEX_NATIVE_UINT128)
// functions 'borrowed' from Botan ;)
#	define CEX_FAST_64X64_MUL(X,Y,Low,High)					\
	do {													\
      const uint128_t r = static_cast<uint128_t>(X) * Y;	\
      *High = (r >> 64) & 0xFFFFFFFFFFFFFFFFULL;			\
      *Low = (r) & 0xFFFFFFFFFFFFFFFFULL;					\
	} while(0)

#elif defined(CEX_COMPILER_MSC) && defined(CEX_IS_X64)
#	include <intrin.h>
#	pragma intrinsic(_umul128)
#	define CEX_FAST_64X64_MUL(X,Y,Low,High)					\
	do {													\
		*Low = _umul128(X, Y, High);						\
	} while(0)

#elif defined(CEX_COMPILER_GCC)
#	if defined(CEX_ARCH_X86_X64)
#		define CEX_FAST_64X64_MUL(X,Y,Low,High)									\
		do {																	\
		asm("mulq %3" : "=d" (*High), "=X" (*Low) : "X" (X), "rm" (Y) : "cc");	\
		} while(0)
#	elif defined(CEX_ARCH_ALPHA)
#		define CEX_FAST_64X64_MUL(X,Y,Low,High)									\
		do {																	\
		asm("umulh %1,%2,%0" : "=r" (*High) : "r" (X), "r" (Y));				\
		*Low = X * Y;															\
		} while(0)
#	elif defined(CEX_ARCH_IA64)
#		define CEX_FAST_64X64_MUL(X,Y,Low,High)									\
		do {																	\
		asm("xmpy.hu %0=%1,%2" : "=f" (*High) : "f" (X), "f" (Y));				\
		*Low = X * Y;															\
		} while(0)
#	elif defined(CEX_ARCH_PPC)
#		define CEX_FAST_64X64_MUL(X,Y,Low,High)									\
		do {																	\
		asm("mulhdu %0,%1,%2" : "=r" (*High) : "r" (X), "r" (Y) : "cc");		\
		*Low = X * Y;															\
		} while(0)
#	endif
#endif

// OS intrinsics flags
#if defined(_MSC_VER) || defined(__BCPLUSPLUS__)
#	define CEX_HAS_MINSSE
#	define CEX_FAST_ROTATE
#elif defined(__MWERKS__) && defined(TARGET_CPU_PPC)
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
#if (!defined(CEX_USE_GCC_INLINE_ASM)) && defined(__GNUG__)
#	define CEX_USE_GCC_INLINE_ASM 1
#endif

// Apple and LLVM's Clang. Apple Clang version 7.0 roughly equals LLVM Clang version 3.7
#if defined(__clang__ ) && (!defined(__apple_build_version__))
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
#if (!defined(CEX_HAS_AVX))
#		define CEX_HAS_AVX
#	endif
#endif
#if defined(CEX_HAS_AVX)
#	if (!defined(CEX_HAS_SSE4))
#		define CEX_HAS_SSE4
#	endif
#endif
#if defined(CEX_HAS_SSE41) || defined(CEX_HAS_SSE42)
#	if (!defined(CEX_HAS_SSE4))
#		define CEX_HAS_SSE4
#	endif
#endif
#if defined(CEX_HAS_SSE4)
#	if (!defined(CEX_HAS_SSSE3))
#		define CEX_HAS_SSSE3
#	endif
#endif
#if defined(CEX_HAS_SSSE3)
#	if (!defined(CEX_HAS_SSE3))
#		define CEX_HAS_SSE3
#	endif
#endif
#if defined(CEX_HAS_SSE3)
#	if (!defined(CEX_HAS_SSE2))
#		define CEX_HAS_SSE2
#	endif
#endif
#if defined(__XOP__)
#	define CEX_HAS_XOP
#endif
#if defined(CEX_OS_WINDOWS)
#	if defined(_M_AMD64) || defined(_M_X64) || (_M_IX86_FP == 2)
#		if (!defined(CEX_HAS_SSE2))
#			define CEX_HAS_SSE2
#		endif
#	endif
#endif

// native openmp support
#if defined(_OPENMP)
#	define CEX_HAS_OPENMP
#	if (_OPENMP == 201511)
#		define CEX_OPENMP_VERSION_45
#	elif (_OPENMP == 201307)
#		define CEX_OPENMP_VERSION_40
#	elif (_OPENMP == 201107)
#		define CEX_OPENMP_VERSION_31
#	elif (_OPENMP == 200805)
#		define CEX_OPENMP_VERSION_30
#	elif (_OPENMP == 200505)
#		define CEX_OPENMP_VERSION_25
#	elif (_OPENMP == 200203)
#		define CEX_OPENMP_VERSION_20
#	endif
#endif

// stringify helper TODO: verify changes on GCC
//#define CEX_STRHELPER(x) #x
//#define CEX_TO_STRING(x) CEX_STRHELPER(x)

// instructs the compiler to skip optimizations on the contained function; closed with CEX_OPTIMIZE_RESUME 
#if defined(CEX_COMPILER_MSC)
#	define CEX_OPTIMIZE_IGNORE __pragma(optimize("", off))
#elif defined(CEX_COMPILER_GCC) || defined(CEX_COMPILER_MINGW)
	_Pragma(CEX_TO_STRING(GCC optimize("O0")))
#	define CEX_OPTIMIZE_IGNORE #pragma GCC optimize ("O0"), #pragma GCC optimize ("O0")
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
//	_Pragma(CEX_TO_STRING(GCC pop_options))
#	define CEX_OPTIMIZE_RESUME #pragma GCC pop_options
#elif defined(CEX_COMPILER_INTEL)
#	define CEX_OPTIMIZE_RESUME pragma optimize("", on) 
#else
#	define CEX_OPTIMIZE_RESUME 0
#endif

// disabling
#if (!defined(_DEBUG))
#	define CEX_NO_DEBUG
#endif

#if defined(CEX_COMPILER_MSC)
#	define CEX_PRAGMA_WARNING __pragma(message("warning: the operation is not supported"))
#elif defined(CEX_COMPILER_GCC)
#	define CEX_PRAGMA_WARNING _Pragma ("warning: the operation is not supported")
#endif

// TODO: change this to a macro, not getting inlined? (test this)
/// <summary>
/// The global assertion handler template
/// </summary>
///
/// <param name="Condition">The condition, must evaluate to true or assert is invoked</param>
/// <param name="Message">The error message</param>
template<typename T>
inline static void CexAssert(bool Condition, const T Message)
{
#if (!defined(CEX_NO_DEBUG)) || defined(CEX_THROW_ASSERTIONS)
	if (!Condition)
	{
		std::cerr << "Assertion failed in " << (__FILE__) << " line " << (__LINE__) << ": " << Message << std::endl;
		std::terminate();
	} 
#endif
}

//////////////////////////////////////////////////
//		*** User Configurable Section ***		//
// Settings in this section can be modified		//
//////////////////////////////////////////////////

// enabling this value uses the volatile memset to erase array data
#define CEX_VOLATILE_MEMSET

// toggles ChaCha512 from 40 to 80 rounds of mixing
#define CEX_CHACHA512_STRONG

// toggles the 48 round implementation of SHAKE in generators, asymmetric ciphers, and signature schemes
//#define CEX_SHAKE_STRONG

// toggles the compact form for all digest permutations, used for performance and small code-cache cases
// the digests will use the unrolled (timing-neutral) form of the permutation function if this constant is removed
//#define CEX_DIGEST_COMPACT

// toggles the compact form for all stream cipher permutations, used for performance and small code-cache cases
// the ciphers will use the unrolled (timing-neutral) form of the permutation function if this constant is removed
// Note, that this may cause cache evictions on CPUs with a small code-cache, timing should be tested on the target CPU before implementing
//#define CEX_CIPHER_COMPACT

// enables/disables OS rotation intrinsics
#if defined(CEX_FAST_ROTATE) && defined(CEX_HAS_MINSSE)
#	define CEX_FASTROTATE_ENABLED
#endif

// prefetch base multiplier used by the symmetric cipher modes parallel block calculation
#define CEX_PREFETCH_BASE 2048

// pre-loads tables in rhx and thx into L1 for performance and as a timing attack counter measure
#define CEX_PREFETCH_RHX_TABLES

// enabling this value will add cpu jitter to the ACP entropy collector (slightly stronger, but much slower)
//#define CEX_ACP_JITTER

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
#	if (!defined(__AVX512__))
#		define __AVX512__
#	endif
#endif

// avx minimum verification
#if defined(CEX_HAS_AVX) || defined(CEX_HAS_AVX2) || defined(CEX_HAS_AVX512)
#	define CEX_AVX_SUPPORTED
#endif

// EOF
#endif

