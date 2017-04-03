#ifndef _CEX_CPUDETECT_H
#define _CEX_CPUDETECT_H

#include "CexDomain.h"

#if defined(_MSC_VER) && _MSC_FULL_VER >= 160040219
#	define MSCAVX
#endif

NAMESPACE_COMMON

/// <summary>
/// Detects Cpu features and capabilities
/// </summary>
class CpuDetect
{
public:

	/// <summary>
	/// Enumeration of cpu vendors
	/// </summary>
	enum class CpuVendors : int
	{
		UNKNOWN = 0,
		AMD = 1,
		INTEL = 2
	};

	/// <summary>
	/// The L2 cache associativity setting
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

private:

	const size_t KB1 = 1024;
	const size_t KB32 = 32 * 1024;
	const size_t KB128 = 128 * 1024;
	const size_t KB256 = 256 * 1024;

	bool m_abm;
	bool m_ads;
	bool m_aesni;
	bool m_amd3dNow;
	bool m_amd3dNowPro;
	bool m_amdCmpLegacy;
	bool m_amdMmxExt;
	bool m_amdMp;
	bool m_avx;
	bool m_avx2;
	bool m_avx5124fmaps;
	bool m_avx512bw;
	bool m_avx512cd;
	bool m_avx512dq;
	bool m_avx512er;
	bool m_avx512f;
	bool m_avx512ifma;
	bool m_avx512pf;
	bool m_avx5124vnniw;
	bool m_avx512vbmi;
	bool m_avx512vl;
	bool m_bmt1;
	bool m_bmt2;
	uint m_busSpeed;
	bool m_cmul;
	std::string m_cpuVendor;
	bool m_fma3;
	bool m_fma4;
	uint m_frequencyBase;
	uint m_frequencyMax;
	bool m_hle;
	bool m_hyperThread;
	size_t m_l1CacheSize;
	size_t m_l1CacheLineSize;
	CacheAssociations m_l2Associative;
	size_t m_l2CacheSize;
	size_t m_logicalPerCore;
	bool m_mmx;
	bool m_mpx;
	size_t m_physCores;
	bool m_pku;
	bool m_pkuos;
	bool m_pqe;
	bool m_pqm;
	bool m_prefetch;
	bool m_rdRand;
	bool m_rdSeed;
	bool m_rtm;
	bool m_rdtscp;
	std::string m_serialNumber;
	bool m_sgx;
	bool m_sha;
	bool m_smap;
	bool m_smep;
	bool m_sse1;
	bool m_sse2;
	bool m_sse3;
	bool m_ssse3;
	bool m_sse4a;
	bool m_sse41;
	bool m_sse42;
	size_t m_virtCores;
	bool m_x64;
	bool m_xop;

public:

	//~~~ Properties~~~//

	/// <summary>
	/// Advanced Bit Manipulation
	/// </summary>
	const bool ABM() { return m_abm; }

	/// <summary>
	/// Intel Add-Carry Instruction Extensions
	/// </summary>
	const bool ADS() { return m_ads; }

	/// <summary>
	/// Returns true if the AES-NI feature set is detected
	/// </summary>
	const bool AESNI() { return m_aesni; }

	/// <summary>
	/// AMD 3DNOW extensions enabled
	/// </summary>
	const bool AMD3DNOW() { return m_amd3dNow; }

	/// <summary>
	/// AMD 3DNOW PRO extensions enabled
	/// </summary>
	const bool AMD3DNOWPRO() { return m_amd3dNowPro; }

	/// <summary>
	/// N-core and CAP_HT is falsely set
	/// </summary>
	const bool AMDCMPLEGACY() { return m_amdCmpLegacy; }

	/// <summary>
	/// AMD MMX extensions enabled
	/// </summary>
	const bool AMDMMXEXT() { return m_amdMmxExt; }

	/// <summary>
	/// MultiProcessing capable; reserved on AMD64
	/// </summary>
	const bool AMDMP() { return m_amdMp; }

	/// <summary>
	/// Returns true if the Advanced Vector Extensions feature set is detected
	/// </summary>
	const bool AVX() { return m_avx; }

	/// <summary>
	/// Returns true if the Advanced Vector Extensions 2 feature set is detected
	/// </summary>
	const bool AVX2() { return m_avx2; }

	/// <summary>
	/// AVX512 Byte + Word detected
	/// </summary>
	const bool AVX512BW() { return m_avx512bw; }

	/// <summary>
	/// AVX512 Conflict Detection
	/// </summary>
	const bool AVX512CD() { return m_avx512cd; }

	/// <summary>
	/// AVX512 Doubleword + Quadword detected
	/// </summary>
	const bool AVX512DQ() { return m_avx512dq; }

	/// <summary>
	/// AVX512 Exponential + Reciprocal detected
	/// </summary>
	const bool AVX512ER() { return m_avx512er; }

	/// <summary>
	/// AVX512 Foundation detected
	/// </summary>
	const bool AVX512F() { return m_avx512f; }

	/// <summary>
	/// AVX512 Integer 52-bit Fused Multiply-Add detected
	/// </summary>
	const bool AVX512IFMA() { return m_avx512ifma; }

	/// <summary>
	/// Multiply Accumulation Single precision
	/// </summary>
	const bool AVX512IFMAPS() { return m_avx5124fmaps; }

	/// <summary>
	/// AVX512 Neural Network Instructions
	/// </summary>
	const bool AVX512NNI() { return m_avx5124vnniw; }

	/// <summary>
	/// AVX512 Prefetch detected
	/// </summary>
	const bool AVX512PF() { return m_avx512pf; }

	/// <summary>
	/// AVX512 Vector Byte Manipulation Instructions detected
	/// </summary>
	const bool AVX512VBMI() { return m_avx512vbmi; }

	/// <summary>
	/// AVX512 Vector Length Extensions detected
	/// </summary>
	const bool AVX512VL() { return m_avx512vl; }

	/// <summary>
	/// Bit Manipulation Instruction Set 1
	/// </summary>
	const bool BMT1() { return m_bmt1; }

	/// <summary>
	/// Bit Manipulation Instruction Set 2
	/// </summary>
	const bool BMT2() { return m_bmt2; }

	/// <summary>
	/// The processor bus speed (newer Intel only) 
	/// </summary>
	const size_t BusSpeed()
	{
		return m_busSpeed;
	}

	/// <summary>
	/// Intel CMUL available
	/// </summary>
	const bool CMUL() { return m_cmul; }

	/// <summary>
	/// AMD FMA 3 instructions available
	/// </summary>
	const bool FMA3() { return m_fma3; }

	/// <summary>
	/// AMD FMA 4 instructions available
	/// </summary>
	const bool FMA4() { return m_fma4; }

	/// <summary>
	/// The processor base frequency (newer Intel only)
	/// </summary>
	const size_t FrequencyBase()
	{
		return m_frequencyBase;
	}

	/// <summary>
	/// The processor maximum frequency (newer Intel only)
	/// </summary>
	const size_t FrequencyMax()
	{
		return m_frequencyMax;
	}

	/// <summary>
	/// TSE Hardware Lock Elision
	/// </summary>
	const bool HLE() { return m_hle; }

	/// <summary>
	/// Hardware supports hyper-threading
	/// </summary>
	const bool HyperThread() { return m_hyperThread; }

	/// <summary>
	/// Cpu is x64
	/// </summary>
	const bool Is64() { return m_x64; }

	/// <summary>
	/// The total L1 data/instruction cache size in bytes for each physical processor core, defaults to 32kib
	/// </summary>
	const size_t L1CacheSize() 
	{ 
		if (m_l1CacheSize == 0 || m_physCores == 0)
			return KB32;
		else
			return m_l1CacheSize * KB1; 
	}

	/// <summary>
	/// The total L1 data/instruction cache line size in bytes for each physical processor core, defaults to 64 bytes
	/// </summary>
	const size_t L1CacheLineSize()
	{
		if (m_l1CacheLineSize == 0)
			return 64;
		else
			return m_l1CacheLineSize;
	}

	/// <summary>
	/// The total L1 data/instruction cache size in bytes for all processor cores, defaults to 256kib
	/// </summary>
	const size_t L1CacheTotal() 
	{ 
		if (m_l1CacheSize == 0 || m_physCores == 0)
			return KB256;
		else
			return m_l1CacheSize * m_physCores * KB1; 
	}

	/// <summary>
	/// The total L1 data cache size in bytes for all processor cores, defaults to 256kib
	/// </summary>
	const size_t L1DataCacheTotal()
	{
		if (m_l1CacheSize == 0 || m_physCores == 0)
			return KB256;
		else
			return (m_l1CacheSize / 2) * m_physCores * KB1;
	}

	/// <summary>
	/// The total L2 cache size in bytes for each physical processor core, defaults to 128kib
	/// </summary>
	const size_t L2CacheSize() 
	{ 
		if (m_l2CacheSize == 0 || m_physCores == 0)
			return KB128;
		else
			return m_l2CacheSize * KB1; 
	}

	/// <summary>
	/// The total L2 cache size in bytes for all processor cores, defaults to 256kib
	/// </summary>
	const size_t L2CacheTotal() 
	{ 
		if (m_l2CacheSize == 0 || m_physCores == 0)
			return KB256;
		else
			return m_l2CacheSize * m_physCores * KB1; 
	}

	/// <summary>
	/// Returns the L2 cache associativity
	/// </summary>
	const CacheAssociations L2Associative() { return m_l2Associative; }

	/// <summary>
	/// The maximum number of logical processors per core
	/// </summary>
	const size_t LogicalPerCore() { return m_logicalPerCore; }

	/// <summary>
	/// MMX instructions available
	/// </summary>
	const bool MMX() { return m_mmx; }

	/// <summary>
	/// Intel Memory Protection Extensions
	/// </summary>
	const bool MPX() { return m_mpx; }

	/// <summary>
	/// The total number of physical processor cores
	/// </summary>
	const size_t PhysicalCores() { return m_physCores; }

	/// <summary>
	/// Memory Protection Keys for User-mode pages
	/// </summary>
	const bool PKU() { return m_pku; }

	/// <summary>
	/// PKU enabled by OS
	/// </summary>
	const bool PKUOS() { return m_pkuos; }

	/// <summary>
	/// Platform Quality of Service Enforcement
	/// </summary>
	const bool PQE() { return m_pqe; }

	/// <summary>
	/// Platform Quality of Service Monitoring
	/// </summary>
	const bool PQM() { return m_pqm; }

	/// <summary>
	/// Cpu supports prefetch
	/// </summary>
	const bool PREFETCH() { return m_prefetch; }

	/// <summary>
	/// Intel Digital Random Number Generator
	/// </summary>
	const bool RDRAND() { return m_rdRand; }

	/// <summary>
	/// Intel Digital Random Seed Generator
	/// </summary>
	const bool RDSEED() { return m_rdSeed; }//

	/// <summary>
	/// RDTSCP time-stamp instruction
	/// </summary>
	const bool RDTSCP() { return m_rdtscp; }

	/// <summary>
	/// TSE Restricted Transactional Memory
	/// </summary>
	const bool RTM() { return m_rtm; }

	/// <summary>
	/// The processor serial number (not supported on some processors)
	/// </summary>
	const std::string SerialNumber() { return m_serialNumber; }

	/// <summary>
	/// SHA instructions available
	/// </summary>
	const bool SHA() { return m_sha; }

	/// <summary>
	/// Software Guard Extensions
	/// </summary>
	const bool SGX() { return m_sgx; }

	/// <summary>
	/// Supervisor Mode Access Prevention
	/// </summary>
	const bool SMAP() { return m_smap; }

	/// <summary>
	/// Supervisor-Mode Execution Prevention
	/// </summary>
	const bool SMEP() { return m_smep; }

	/// <summary>
	/// Returns true if SSE2 or greater is detected
	/// </summary>
	const bool SSE() { return m_avx512f || m_avx2 || m_avx || m_xop || m_sse42 || m_sse41 || m_sse4a || m_ssse3 || m_sse3 || m_sse2; }

	/// <summary>
	/// Streaming SIMD Extensions 1.0 available
	/// </summary>
	const bool SSE1() { return m_sse1; }

	/// <summary>
	/// Streaming SIMD Extensions 2.0 available
	/// </summary>
	const bool SSE2() { return m_sse2; }

	/// <summary>
	/// Streaming SIMD Extensions 3.0 available
	/// </summary>
	const bool SSE3() { return m_sse3; }

	/// <summary>
	/// Supplemental SSE3 Merom New Instructions available
	/// </summary>
	const bool SSSE3() { return m_ssse3; }

	/// <summary>
	/// AMD SSE 4A instructions available
	/// </summary>
	const bool SSE4A() { return m_sse4a; }

	/// <summary>
	/// Streaming SIMD Extensions 4.1 available
	/// </summary>
	const bool SSE41() { return m_sse41; }

	/// <summary>
	/// Streaming SIMD Extensions 4.2 available
	/// </summary>
	const bool SSE42() { return m_sse42; }

	/// <summary>
	/// Returns the cpu vendors enumeration value
	/// </summary>
	const CpuVendors Vendor();

	/// <summary>
	/// The total number of threads available using hyperthreading
	/// </summary>
	const size_t VirtualCores() { return m_virtCores; }

	/// <summary>
	/// Returns true if the AMD eXtended Operations feature set is detected
	/// </summary>
	const bool XOP() { return m_xop; }

	//~~~ Constructor~~~//

	/// <summary>
	/// Initialization Detects Cpu features
	/// </summary>
	CpuDetect();

private:

#if defined(MSCAVX)
	bool AvxSupported();
	bool Avx2Supported();
#endif
	void Detect();
	void GetFrequency();
	void GetSerialNumber();
	size_t MaxCoresPerPackage();
	size_t MaxLogicalPerCore();
};

NAMESPACE_COMMONEND
#endif