#ifndef _CEXENGINE_CPUDETECT_H
#define _CEXENGINE_CPUDETECT_H

#include "Common.h"
#include <algorithm>

#if defined(_WIN32)
#	include <intrin.h>
#	include <stdio.h>
#	define cpuid(info, x)  __cpuidex(info, x, 0)
#else
#	include <cpuid.h>
	void cpuid(int info[4], int InfoType) {
		__cpuid_count(InfoType, 0, info[0], info[1], info[2], info[3]);
	}
#endif

NAMESPACE_COMMON

/// <summary>
/// Detects Cpu features and capabilities
/// </summary>
class CpuDetect
{
public:

	//~~~ Public Enums~~~//
	/// <summary>
	/// Enumeration of cpu vendors
	/// </summary>
	enum class CpuVendors : uint
	{
		UNKNOWN = 0,
		AMD = 1,
		INTEL = 2
	};

	/// <summary>
	/// Enumeration of processor feature sets
	/// </summary>
	enum class FeatureSets : uint
	{
		/// <summary>
		/// Intructions are not available
		/// </summary>
		NONE = 0,
		/// <summary>
		/// MMX instructions
		/// </summary>
		MMX = 1,
		/// <summary>
		/// Cpu is x64
		/// </summary>
		X64 = 2,
		/// <summary>
		/// Advanced Bit Manipulation
		/// </summary>
		ABM = 4,
		/// <summary>
		/// Intel Digital Random Number Generator
		/// </summary>
		RDRAND = 8,
		/// <summary>
		/// Bit Manipulation Instruction Set 1
		/// </summary>
		BMI1 = 16,
		/// <summary>
		/// Bit Manipulation Instruction Set 2
		/// </summary>
		BMI2 = 32,
		/// <summary>
		/// Intel Add-Carry Instruction Extensions
		/// </summary>
		ADX = 64,
		/// <summary>
		/// Cpu supports prefetch
		/// </summary>
		PREFETCHWT1 = 128,
		/// <summary>
		/// Streaming SIMD Extensions 1.0
		/// </summary>
		SSE = 256,
		/// <summary>
		/// Streaming SIMD Extensions 2.0
		/// </summary>
		SSE2 = 512,
		/// <summary>
		/// Streaming SIMD Extensions 3.0
		/// </summary>
		SSE3 = 1024,
		/// <summary>
		/// SSE3 E3 Merom New Instructions
		/// </summary>
		SSSE3 = 2048,
		/// <summary>
		/// Streaming SIMD Extensions 4.1
		/// </summary>
		SSE41 = 4096,
		/// <summary>
		/// Streaming SIMD Extensions 4.2
		/// </summary>
		SSE42 = 8192,
		/// <summary>
		/// AMD SSE 4A instructions
		/// </summary>
		SSE4A = 16384,
		/// <summary>
		/// AES-NI instructions
		/// </summary>
		AES = 32768,
		/// <summary>
		/// SHA instructions
		/// </summary>
		SHA = 65536,
		/// <summary>
		/// Advanced Vector Extensions
		/// </summary>
		AVX = 131072,
		/// <summary>
		/// AMD eXtended Operations
		/// </summary>
		XOP = 262144,
		/// <summary>
		/// AMD FMA 3 instructions
		/// </summary>
		FMA3 = 524288,
		/// <summary>
		/// AMD FMA 4 instructions
		/// </summary>
		FMA4 = 1048576,
		/// <summary>
		/// Advanced Vector Extensions 2
		/// </summary>
		AVX2 = 2097152,
		/// <summary>
		/// AVX512 Foundation
		/// </summary>
		AVX512F = 4194304,
		/// <summary>
		/// AVX512 Conflict Detection
		/// </summary>
		AVX512CD = 8388608,
		/// <summary>
		/// AVX512 Prefetch
		/// </summary>
		AVX512PF = 16777216,
		/// <summary>
		/// AVX512 Exponential + Reciprocal
		/// </summary>
		AVX512ER = 33554432,
		/// <summary>
		/// AVX512 Vector Length Extensions
		/// </summary>
		AVX512VL = 67108864,
		/// <summary>
		/// AVX512 Byte + Word
		/// </summary>
		AVX512BW = 134217728,
		/// <summary>
		/// AVX512 Doubleword + Quadword
		/// </summary>
		AVX512DQ = 268435456,
		/// <summary>
		/// AVX512 Integer 52-bit Fused Multiply-Add
		/// </summary>
		AVX512IFMA = 536870912,
		/// <summary>
		/// AVX512 Vector Byte Manipulation Instructions
		/// </summary>
		AVX512VBMI = 1073741824,
		/// <summary>
		/// Hardware supports hyper-threading
		/// </summary>
		HYPERTHREAD = 2147483648
	};

	/// <summary>
	/// Maps to the L2Associative cache associativity setting
	/// </summary>
	enum class CacheAssociations
	{
		Disabled = 0,
		DirectMapped = 1,
		TwoWay = 2,
		FourWay = 4,
		EightWay = 6,
		SixteenWay = 8,
		FullyAssociative = 16
	};

	//~~~ Properties~~~//

	/// <summary>
	/// Returns the L1 cache size per processer in Kilobytes
	/// </summary>
	size_t L1CacheSize;

	/// <summary>
	/// Returns the total L1 cache size for all processers in Kilobytes
	/// </summary>
	size_t L1CacheTotal;

	/// <summary>
	/// Returns the L2 cache size per processer in Kilobytes
	/// </summary>
	size_t L2CacheSize;

	/// <summary>
	/// Returns the L2 cache associativity
	/// </summary>
	CacheAssociations L2Associative;

	/// <summary>
	/// The CPU's vendor string
	/// </summary>
	std::string CpuVendor;

	/// <summary>
	/// MMX instructions available
	/// </summary>
	bool HW_MMX;
	/// <summary>
	/// Cpu is x64
	/// </summary>
	bool HW_x64;
	/// <summary>
	/// Advanced Bit Manipulation
	/// </summary>
	bool HW_ABM;
	/// <summary>
	/// Intel Digital Random Number Generator
	/// </summary>
	bool HW_RDRAND;
	/// <summary>
	/// Bit Manipulation Instruction Set 1
	/// </summary>
	bool HW_BMI1;
	/// <summary>
	/// Bit Manipulation Instruction Set 2
	/// </summary>
	bool HW_BMI2;
	/// <summary>
	/// Intel Add-Carry Instruction Extensions
	/// </summary>
	bool HW_ADX;
	/// <summary>
	/// Cpu supports prefetch
	/// </summary>
	bool HW_PREFETCHWT1;

	//  SIMD: 128-bit
	/// <summary>
	/// Streaming SIMD Extensions 1.0 available
	/// </summary>
	bool HW_SSE;
	/// <summary>
	/// Streaming SIMD Extensions 2.0 available
	/// </summary>
	bool HW_SSE2;
	/// <summary>
	/// Hardware supports hyper-threading
	/// </summary>
	bool HW_HYPER;
	/// <summary>
	/// Streaming SIMD Extensions 3.0 available
	/// </summary>
	bool HW_SSE3;
	/// <summary>
	/// SSE3 E3 Merom New Instructions available
	/// </summary>
	bool HW_SSSE3;
	/// <summary>
	/// Streaming SIMD Extensions 4.1 available
	/// </summary>
	bool HW_SSE41;
	/// <summary>
	/// Streaming SIMD Extensions 4.2 available
	/// </summary>
	bool HW_SSE42;
	/// <summary>
	/// AMD SSE 4A instructions available
	/// </summary>
	bool HW_SSE4A;
	/// <summary>
	/// AES-NI instructions available
	/// </summary>
	bool HW_AES;
	/// <summary>
	/// SHA instructions available
	/// </summary>
	bool HW_SHA;

	//  SIMD: 256-bit
	/// <summary>
	/// Advanced Vector Extensions available
	/// </summary>
	bool HW_AVX;
	/// <summary>
	/// AMD eXtended Operations available
	/// </summary>
	bool HW_XOP;
	/// <summary>
	/// AMD FMA 3 instructions available
	/// </summary>
	bool HW_FMA3;
	/// <summary>
	/// AMD FMA 4 instructions available
	/// </summary>
	bool HW_FMA4;
	/// <summary>
	/// Advanced Vector Extensions 2 available
	/// </summary>
	bool HW_AVX2;

	//  SIMD: 512-bit
	/// <summary>
	/// AVX512 Foundation
	/// </summary>
	bool HW_AVX512F;
	/// <summary>
	/// AVX512 Conflict Detection
	/// </summary>
	bool HW_AVX512CD;
	/// <summary>
	/// AVX512 Prefetch
	/// </summary>
	bool HW_AVX512PF;
	/// <summary>
	/// AVX512 Exponential + Reciprocal
	/// </summary>
	bool HW_AVX512ER;
	/// <summary>
	/// AVX512 Vector Length Extensions
	/// </summary>
	bool HW_AVX512VL;
	/// <summary>
	/// AVX512 Byte + Word
	/// </summary>
	bool HW_AVX512BW;
	/// <summary>
	/// AVX512 Doubleword + Quadword
	/// </summary>
	bool HW_AVX512DQ;
	/// <summary>
	/// AVX512 Integer 52-bit Fused Multiply-Add
	/// </summary>
	bool HW_AVX512IFMA;
	/// <summary>
	/// AVX512 Vector Byte Manipulation Instructions
	/// </summary>
	bool HW_AVX512VBMI;
	/// <summary>
	/// The total number of physical cores per processor
	/// </summary>
	size_t HW_PHYSICALCORES;
	/// <summary>
	/// The total number of virtual cores per processor (including hyperthreading)
	/// </summary>
	size_t HW_VIRTUALCORES;
	/// <summary>
	/// The maximum number of logical processors per core
	/// </summary>
	size_t HW_LOGICALPERCORE;
	/// <summary>
	/// N-core and CAP_HT is falsely set
	/// </summary>
	bool HW_AMD_CMP_LEGACY;
	/// <summary>
	/// MultiProcessing capable; reserved on AMD64
	/// </summary>
	bool HW_AMD_MP;
	/// <summary>
	/// AMD MMX extensions enabled
	/// </summary>
	bool HW_AMD_MMX_EXT;
	/// <summary>
	/// AMD 3DNOW PRO extensions enabled
	/// </summary>
	bool HW_AMD_3DNOW_PRO;
	/// <summary>
	/// AMD 3DNOW extensions enabled
	/// </summary>
	bool HW_AMD_3DNOW;

	//~~~ Constructor~~~//

	/// <summary>
	/// Initialization Detects Cpu features
	/// </summary>
	CpuDetect()
	{
		Initialize();
		Detect();
	}

	//~~~ Public Methods~~~//

	/// <summary>
	/// Detect the Cpu feature set
	/// </summary>
	void Detect();

	/// <summary>
	/// Returns true if any of the AVX512, AVX2, or AVX feature sets are detected
	/// </summary>
	bool HasAES()
	{
		return HW_AVX512F || HW_AVX2 || HW_AVX;
	}

	/// <summary>
	/// Returns true if any of the AVX512, AVX2, or AVX feature sets are detected
	/// </summary>
	bool HasAVX()
	{
		return HW_AVX512F || HW_AVX2 || HW_AVX;
	}

	/// <summary>
	/// Returns true if any of the AVX512, or AVX2 feature sets are detected
	/// </summary>
	bool HasAVX2()
	{
		return HW_AVX512F || HW_AVX2;
	}

	/// <summary>
	/// Returns true if any of the AVX512, AVX2, AVX1, or XOP feature sets are detected
	/// </summary>
	bool HasAdvancedSSE()
	{
		return HW_AVX512F || HW_AVX2 || HW_AVX || HW_XOP;
	}

	/// <summary>
	/// Returns true if SSE2 or greater is detected
	/// </summary>
	bool HasMinIntrinsics()
	{
		return HW_AVX512F || HW_AVX2 || HW_AVX || HW_XOP || HW_SSE42 || HW_SSE41 || HW_SSE4A || HW_SSSE3 || HW_SSE3 || HW_SSE2;
	}

	/// <summary>
	/// Returns true if the XOP feature set is detected
	/// </summary>
	bool HasXOP()
	{
		return HW_XOP;
	}

	/// <summary> 
	/// Returns the best available SIMD feature set
	/// </summary>
	FeatureSets HighestSSEVersion()
	{
		if (HW_AVX512F)
			return FeatureSets::AVX512F;
		else if (HW_AVX2)
			return FeatureSets::AVX2;
		else if (HW_AVX)
			return FeatureSets::AVX;
		else if (HW_XOP)
			return FeatureSets::XOP;
		else if (HW_SSE42)
			return FeatureSets::SSE42;
		else if (HW_SSE41)
			return FeatureSets::SSE41;
		else if (HW_SSE4A)
			return FeatureSets::SSE4A;
		else if (HW_SSSE3)
			return FeatureSets::SSSE3;
		else if (HW_SSE3)
			return FeatureSets::SSE3;
		else if (HW_SSE2)
			return FeatureSets::SSE2;
		else if (HW_SSE)
			return FeatureSets::SSE;
		else if (HW_MMX)
			return FeatureSets::MMX;
		else
			return FeatureSets::NONE;
	}

	/// <summary>
	/// Returns the cpu vendors enumeration value
	/// </summary>
	CpuVendors Vendor()
	{
		if (CpuVendor.size() > 0)
		{
			std::string data = CpuVendor;
			std::transform(data.begin(), data.end(), data.begin(), ::tolower);
			if (CpuVendor.find_first_of("intel") > 0)
				return CpuVendors::INTEL;
			else if (CpuVendor.find_first_of("amd") > 0)
				return CpuVendors::AMD;
		}
		return CpuVendors::UNKNOWN;
	}

private:

#if defined(_MSC_VER) && _MSC_FULL_VER >= 160040219
	bool HasAvxSupport();
	bool HasAvx2Support();
#endif
	void Initialize();
	size_t MaxCoresPerPackage();
	size_t MaxLogicalPerCore();
};

NAMESPACE_COMMONEND
#endif