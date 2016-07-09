#ifndef _CEXENGINE_CPUDETECT_H
#define _CEXENGINE_CPUDETECT_H

#include "Common.h"

#ifdef _WIN32
#	include <intrin.h>
#	include <stdio.h>
#		define cpuid(info, x)  __cpuidex(info, x, 0)
#	else
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

	/// <summary>
	/// Enumeration of processor feature sets
	/// </summary>
	enum FeatureSet : uint32_t
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
	};

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
	/// Initialization Detects Cpu features
	/// </summary>
	CpuDetect()
	{
		int info[4];
		cpuid(info, 0);
		int nIds = info[0];

		cpuid(info, 0x80000000);
		unsigned nExIds = info[0];

		//  Detect Features
		if (nIds >= 0x00000001)
		{
			cpuid(info, 0x00000001);
			HW_MMX = (info[3] & ((int)1 << 23)) != 0;
			HW_SSE = (info[3] & ((int)1 << 25)) != 0;
			HW_SSE2 = (info[3] & ((int)1 << 26)) != 0;
			HW_SSE3 = (info[2] & ((int)1 << 0)) != 0;
			HW_SSSE3 = (info[2] & ((int)1 << 9)) != 0;
			HW_SSE41 = (info[2] & ((int)1 << 19)) != 0;
			HW_SSE42 = (info[2] & ((int)1 << 20)) != 0;
			HW_AES = (info[2] & ((int)1 << 25)) != 0;
			HW_FMA3 = (info[2] & ((int)1 << 12)) != 0;
			HW_RDRAND = (info[2] & ((int)1 << 30)) != 0;
			HW_AVX = (info[2] & ((int)1 << 28)) != 0;
		}

		if (nIds >= 0x00000007)
		{
			cpuid(info, 0x00000007);
#if defined(_MSC_VER) && _MSC_FULL_VER >= 160040219
			HW_AVX2 = IsAVS2Supported();
#else
			HW_AVX2 = (info[1] & ((int)1 << 5)) != 0;
#endif
			HW_BMI1 = (info[1] & ((int)1 << 3)) != 0;
			HW_BMI2 = (info[1] & ((int)1 << 8)) != 0;
			HW_ADX = (info[1] & ((int)1 << 19)) != 0;
			HW_SHA = (info[1] & ((int)1 << 29)) != 0;
			HW_PREFETCHWT1 = (info[2] & ((int)1 << 0)) != 0;
			HW_AVX512F = (info[1] & ((int)1 << 16)) != 0;
			HW_AVX512CD = (info[1] & ((int)1 << 28)) != 0;
			HW_AVX512PF = (info[1] & ((int)1 << 26)) != 0;
			HW_AVX512ER = (info[1] & ((int)1 << 27)) != 0;
			HW_AVX512VL = (info[1] & ((int)1 << 31)) != 0;
			HW_AVX512BW = (info[1] & ((int)1 << 30)) != 0;
			HW_AVX512DQ = (info[1] & ((int)1 << 17)) != 0;
			HW_AVX512IFMA = (info[1] & ((int)1 << 21)) != 0;
			HW_AVX512VBMI = (info[2] & ((int)1 << 1)) != 0;
		}

		if (nExIds >= 0x80000001)
		{
			cpuid(info, 0x80000001);
			HW_x64 = (info[3] & ((int)1 << 29)) != 0;
			HW_ABM = (info[2] & ((int)1 << 5)) != 0;
			HW_SSE4A = (info[2] & ((int)1 << 6)) != 0;
			HW_FMA4 = (info[2] & ((int)1 << 16)) != 0;
			HW_XOP = (info[2] & ((int)1 << 11)) != 0;
		}
	}

	/// <summary>
	/// Returns true if any of the AVX512, AVX2, AVX1, or XOP feature sets are available
	/// </summary>
	bool HasAdvancedSSE()
	{
		return HW_AVX512F || HW_AVX2 || HW_AVX || HW_XOP;
	}

	/// <summary>
	/// Returns true if SSE2 or greater is available
	/// </summary>
	bool HasMinIntrinsics()
	{
		return HW_AVX512F || HW_AVX2 || HW_AVX || HW_XOP || HW_SSE42 || HW_SSE41 || HW_SSE4A || HW_SSSE3 || HW_SSE3 || HW_SSE2;
	}

	/// <summary> 
	/// Returns the best available SIMD feature set available
	/// </summary>
	FeatureSet HighestSSEVersion()
	{
		if (HW_AVX512F)
			return FeatureSet::AVX512F;
		else if (HW_AVX2)
			return FeatureSet::AVX2;
		else if (HW_AVX)
			return FeatureSet::AVX;
		else if (HW_XOP)
			return FeatureSet::XOP;
		else if (HW_SSE42)
			return FeatureSet::SSE42;
		else if (HW_SSE41)
			return FeatureSet::SSE41;
		else if (HW_SSE4A)
			return FeatureSet::SSE4A;
		else if (HW_SSSE3)
			return FeatureSet::SSSE3;
		else if (HW_SSE3)
			return FeatureSet::SSE3;
		else if (HW_SSE2)
			return FeatureSet::SSE2;
		else if (HW_SSE)
			return FeatureSet::SSE;
		else if (HW_MMX)
			return FeatureSet::MMX;
	}

private:
#if defined(_MSC_VER) && _MSC_FULL_VER >= 160040219
	bool IsAVSSupported()
	{
		bool avxSupported = false;
		int cpuInfo[4];
		__cpuid(cpuInfo, 1);

		bool osUsesXSAVE_XRSTORE = cpuInfo[2] & (1 << 27) || false;
		bool cpuAVXSuport = cpuInfo[2] & (1 << 28) || false;

		if (osUsesXSAVE_XRSTORE && cpuAVXSuport)
		{
			// Check if the OS will save the YMM registers
			unsigned long long xcrFeatureMask = _xgetbv(_XCR_XFEATURE_ENABLED_MASK);// 0xe6 avc2
			HW_AVX = (xcrFeatureMask & 0x6) || false;
		}

		return avxSupported;
	}

	bool IsAVS2Supported()
	{
		bool avx2Supported = false;
		int cpuInfo[4];
		__cpuid(cpuInfo, 1);

		bool osUsesXSAVE_XRSTORE = cpuInfo[2] & (1 << 27) || false;
		bool cpuAVXSuport = cpuInfo[2] & (1 << 28) || false;

		if (osUsesXSAVE_XRSTORE && cpuAVXSuport)
		{
			// Check if the OS will save the YMM registers
			unsigned long long xcrFeatureMask = _xgetbv(_XCR_XFEATURE_ENABLED_MASK);
			avx2Supported = (xcrFeatureMask & 0xe6) || false;
		}

		return avx2Supported;
	}
#endif
};

NAMESPACE_COMMONEND
#endif