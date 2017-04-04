#ifndef _CEX_CPUDETECT_H
#define _CEX_CPUDETECT_H

#include "CexDomain.h"

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

	enum CpuidFlags : ulong
	{
		// EAX=1
		CPUID_SSE3 = 0, // ecx 0
		CPUID_CMUL = 1, // ecx 1
		CPUID_SSSE3 = 9, // ecx 9
		CPUID_SSE41 = 19, // ecx 19
		CPUID_SSE42 = 20, // ecx 20
		CPUID_AESNI = 25, // ecx 25
		CPUID_AVX = 28, // ecx 28
		CPUID_RDRAND = 30,  // ecx 30
		CPUID_SSE2 = 32 + 26, // edx 26
		CPUID_HYPERTHREAD = 32 + 28, // edx 28
		// EAX=7
		CPUID_SGX = 64 + 2, // ebx 2
		CPUID_AVX2 = 64 + 5, // ebx 5
		CPUID_BMI2 = 64 + 8, // ebx 8
		CPUID_RTM = 64 + 11, // ebx 11
		CPUID_PQM = 64 + 12, // ebx 12
		CPUID_MPX = 64 + 14, // ebx 14
		CPUID_PQE = 64 + 15, // ebx 15
		CPUID_AVX512F = 64 + 16, // ebx 16
		CPUID_RDSEED = 64 + 18, // ebx 18
		CPUID_ADX = 64 + 19, // ebx 18
		CPUID_SMAP = 64 + 20, // ebx 20
		CPUID_SHA = 64 + 29, // ebx 29
		CPUID_PREFETCH = 64 + 32, // ebx 32
		// EAX=80000001h
		CPUID_ABM = 128 + 5, // ecx 5
		CPUID_SSE4A = 128 + 6, // ecx 6
		CPUID_XOP = 128 + 11, // ecx 11
		CPUID_FMA4 = 128 + 16, // ecx 16
		CPUID_X64 = 128 + 29, // ecx 29
		CPUID_RDTSCP = 192 + 27, // edx 29
	};

	static const size_t KB1 = 1024;
	static const size_t KB32 = 32 * 1024;
	static const size_t KB128 = 128 * 1024;
	static const size_t KB256 = 256 * 1024;

	uint m_busSpeed;
	size_t m_cacheLineSize;
	CpuVendors m_cpuVendor;
	std::string m_cpuVendorString;
	uint m_frequencyBase;
	uint m_frequencyMax;
	bool m_hyperThread;
	size_t m_l1CacheSize;
	size_t m_l1CacheLineSize;
	CacheAssociations m_l2Associative;
	size_t m_l2CacheSize;
	size_t m_logicalPerCore;
	size_t m_physCores;
	std::string m_serialNumber;
	size_t m_virtCores;
	ulong m_x86CpuFlags[4];

public:

	//~~~ Properties~~~//

	/// <summary>
	/// Advanced Bit Manipulation
	/// </summary>
	const bool ABM() { return GetFlag(CpuidFlags::CPUID_ABM); }

	/// <summary>
	/// Intel Add-Carry Instruction Extensions
	/// </summary>
	const bool ADS() { return GetFlag(CpuidFlags::CPUID_ADX); }

	/// <summary>
	/// Returns true if the AES-NI feature set is detected
	/// </summary>
	const bool AESNI() { return GetFlag(CpuidFlags::CPUID_AESNI); }

	/// <summary>
	/// Returns true if the Advanced Vector Extensions feature set is detected
	/// </summary>
	const bool AVX() { return GetFlag(CpuidFlags::CPUID_AVX); }

	/// <summary>
	/// Returns true if the Advanced Vector Extensions 2 feature set is detected
	/// </summary>
	const bool AVX2() { return GetFlag(CpuidFlags::CPUID_AVX2); }

	/// <summary>
	/// AVX512 Foundation detected
	/// </summary>
	const bool AVX512F() { return GetFlag(CpuidFlags::CPUID_AVX512F); }

	/// <summary>
	/// Bit Manipulation Instruction Set 2
	/// </summary>
	const bool BMT2() { return GetFlag(CpuidFlags::CPUID_BMI2); }

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
	const bool CMUL() { return GetFlag(CpuidFlags::CPUID_CMUL); }

	/// <summary>
	/// AMD FMA 4 instructions available
	/// </summary>
	const bool FMA4() { return GetFlag(CpuidFlags::CPUID_FMA4); }

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
	/// Hardware supports hyper-threading
	/// </summary>
	const bool HyperThread() { return GetFlag(CpuidFlags::CPUID_HYPERTHREAD); }

	/// <summary>
	/// Cpu is x64
	/// </summary>
	const bool Is64() { return GetFlag(CpuidFlags::CPUID_X64); }

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
	/// Intel Memory Protection Extensions
	/// </summary>
	const bool MPX() { return GetFlag(CpuidFlags::CPUID_MPX); }

	/// <summary>
	/// The total number of physical processor cores
	/// </summary>
	const size_t PhysicalCores() { return m_physCores; }

	/// <summary>
	/// Platform Quality of Service Enforcement
	/// </summary>
	const bool PQE() { return GetFlag(CpuidFlags::CPUID_PQE); }

	/// <summary>
	/// Platform Quality of Service Monitoring
	/// </summary>
	const bool PQM() { return GetFlag(CpuidFlags::CPUID_PQM); }

	/// <summary>
	/// Cpu supports prefetch
	/// </summary>
	const bool PREFETCH() { return GetFlag(CpuidFlags::CPUID_PREFETCH); }

	/// <summary>
	/// Intel Digital Random Number Generator
	/// </summary>
	const bool RDRAND() { return GetFlag(CpuidFlags::CPUID_RDRAND); }

	/// <summary>
	/// Intel Digital Random Seed Generator
	/// </summary>
	const bool RDSEED() { return GetFlag(CpuidFlags::CPUID_RDSEED); }

	/// <summary>
	/// RDTSCP time-stamp instruction
	/// </summary>
	const bool RDTSCP() { return GetFlag(CpuidFlags::CPUID_RDTSCP); }

	/// <summary>
	/// TSE Restricted Transactional Memory
	/// </summary>
	const bool RTM() { return GetFlag(CpuidFlags::CPUID_RTM); }

	/// <summary>
	/// The processor serial number (not supported on some processors)
	/// </summary>
	const std::string SerialNumber() { return m_serialNumber; }

	/// <summary>
	/// SHA instructions available
	/// </summary>
	const bool SHA() { return GetFlag(CpuidFlags::CPUID_SHA); }

	/// <summary>
	/// Supervisor Mode Access Prevention
	/// </summary>
	const bool SMAP() { return GetFlag(CpuidFlags::CPUID_SMAP); }

	/// <summary>
	/// Returns true if SSE2 or greater is detected
	/// </summary>
	const bool SSE() { return GetFlag(CpuidFlags::CPUID_SSE2); }

	/// <summary>
	/// Streaming SIMD Extensions 2.0 available
	/// </summary>
	const bool SSE2() { return GetFlag(CpuidFlags::CPUID_SSE2); }

	/// <summary>
	/// Streaming SIMD Extensions 3.0 available
	/// </summary>
	const bool SSE3() { return GetFlag(CpuidFlags::CPUID_SSE3); }

	/// <summary>
	/// Supplemental SSE3 Merom New Instructions available
	/// </summary>
	const bool SSSE3() { return GetFlag(CpuidFlags::CPUID_SSSE3); }

	/// <summary>
	/// AMD SSE 4A instructions available
	/// </summary>
	const bool SSE4A() { return GetFlag(CpuidFlags::CPUID_SSE4A); }

	/// <summary>
	/// Streaming SIMD Extensions 4.1 available
	/// </summary>
	const bool SSE41() { return GetFlag(CpuidFlags::CPUID_SSE41); }

	/// <summary>
	/// Streaming SIMD Extensions 4.2 available
	/// </summary>
	const bool SSE42() { return GetFlag(CpuidFlags::CPUID_SSE42); }

	/// <summary>
	/// Returns the cpu vendors enumeration value
	/// </summary>
	CpuVendors Vendor() { return m_cpuVendor; };

	/// <summary>
	/// The total number of threads available using hyperthreading
	/// </summary>
	const size_t VirtualCores() { return m_virtCores; }

	/// <summary>
	/// Returns true if the AMD eXtended Operations feature set is detected
	/// </summary>
	const bool XOP() { return GetFlag(CpuidFlags::CPUID_XOP); }

	//~~~ Constructor~~~//

	/// <summary>
	/// Initialization Detects Cpu features
	/// </summary>
	CpuDetect();

private:

	byte GetByte(size_t Index, uint Input);

	template<typename T> 
	inline byte get_byte(size_t byte_num, T input)
	{
		return static_cast<byte>(input >> (((~byte_num)&(sizeof(T) - 1)) << 3));
	}

	template<typename T> 
	inline bool CompareMem(const T* p1, const T* p2, size_t n)
	{
		volatile T difference = 0;

		for (size_t i = 0; i != n; ++i)
			difference |= (p1[i] ^ p2[i]);

		return difference == 0;
	}


	bool AvxEnabled();
	bool Avx2Enabled();
	bool GetFlag(CpuidFlags Flag);
	void GetFrequency();
	size_t GetMaxCoresPerPackage();
	size_t GetMaxLogicalPerCore();
	void GetSerialNumber();
	void GetTopology();
	void Initialize();
	const CpuVendors GetVendor(std::string &Name);
	std::string GetVendorString(uint CpuInfo[4]);
};

NAMESPACE_COMMONEND
#endif