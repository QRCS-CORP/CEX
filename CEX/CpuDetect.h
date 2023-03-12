#ifndef CEX_CPUDETECT_H
#define CEX_CPUDETECT_H

#include "CexDomain.h"

NAMESPACE_ROOT

/// <summary>
/// Detects Cpu features and capabilities
/// </summary>
class CpuDetect
{
public:

	//~~~ Enumerations~~~//

	/// <summary>
	/// Enumeration of cpu vendors
	/// </summary>
	enum class CpuVendors : uint32_t
	{
		UNKNOWN = 0,
		AMD = 1,
		INTEL = 2
	};

	/// <summary>
	/// The L2 cache associativity setting
	/// </summary>
	enum class CacheAssociations : uint32_t
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

	enum class CpuidFlags : uint32_t
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
		CPUID_X86EMU = 32 + 30, // edx 30 -index 0, 1
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
		CPUID_PREFETCH = 64 + 32, // ebx 32 -index 2, 3
		// EAX=80000001
		CPUID_ABM = 128 + 5, // ecx 5
		CPUID_SSE4A = 128 + 6, // ecx 6
		CPUID_XOP = 128 + 11, // ecx 11
		CPUID_FMA4 = 128 + 16, // ecx 16
		CPUID_RDTSCP = 160 + 27, // edx 27
		CPUID_X64 = 160 + 29, // edx 29 -index 4, 5
	};

	static const size_t KB1 = 1024;
	static const size_t KB32 = 32 * KB1;
	static const size_t KB128 = 128 * KB1;
	static const size_t KB256 = 256 * KB1;

	uint32_t m_busRefFrequency;
	size_t m_cacheLineSize;
	CpuVendors m_cpuVendor;
	std::string m_cpuVendorString;
	uint32_t m_frequencyBase;
	uint32_t m_frequencyMax;
	bool m_hyperThread;
	size_t m_l1CacheLineSize;
	size_t m_l1CacheSize;
	CacheAssociations m_l2Associative;
	size_t m_l2CacheSize;
	size_t m_logicalPerCore;
	size_t m_physCores;
	std::string m_serialNumber;
	size_t m_virtCores;
	std::vector<uint32_t> m_x86CpuFlags;

public:

	//~~~ Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	CpuDetect(const CpuDetect&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	CpuDetect& operator=(const CpuDetect&) = delete;

	/// <summary>
	/// Initialization Detects Cpu features
	/// </summary>
	CpuDetect();

	/// <summary>
	/// Finalize this class and clear resources
	/// </summary>
	~CpuDetect();

	//~~~ Properties~~~//

	/// <summary>
	/// Advanced Bit Manipulation
	/// </summary>
	///
	/// <returns>Returns true if the feature is available</returns>
	const bool ABM();

	/// <summary>
	/// Intel Add-Carry Instruction Extensions
	/// </summary>
	///
	/// <returns>Returns true if the feature is available</returns>
	const bool ADS();

	/// <summary>
	/// Returns true if the AES-NI feature set is detected
	/// </summary>
	///
	/// <returns>Returns true if the feature is available</returns>
	const bool AESNI();

	/// <summary>
	/// Returns true if the Advanced Vector Extensions feature set is detected
	/// </summary>
	///
	/// <returns>Returns true if the feature is available</returns>
	const bool AVX();

	/// <summary>
	/// Returns true if the Advanced Vector Extensions 2 feature set is detected
	/// </summary>
	///
	/// <returns>Returns true if the feature is available</returns>
	const bool AVX2();

	/// <summary>
	/// AVX512 Foundation detected
	/// </summary>
	///
	/// <returns>Returns true if the feature is available</returns>
	const bool AVX512F();

	/// <summary>
	/// Bit Manipulation Instruction Set 2
	/// </summary>
	///
	/// <returns>Returns true if the feature is available</returns>
	const bool BMT2();

	/// <summary>
	/// The bus reference frequency (newer Intel only)
	/// <para>A value of 0 is returned if the feature is not available on this cpu</para>
	/// </summary>
	///
	/// <returns>Returns the bus frequency</returns>
	const size_t BusRefFrequency();

	/// <summary>
	/// Intel CMUL available
	/// </summary>
	///
	/// <returns>Returns true if the feature is available</returns>
	const bool CMUL();

	/// <summary>
	/// AMD FMA 4 instructions available
	/// </summary>
	///
	/// <returns>Returns true if the feature is available</returns>
	const bool FMA4();

	/// <summary>
	/// The processor base frequency (newer Intel only)
	/// <para>A value of 0 is returned if the feature is not available on this cpu</para>
	/// </summary>
	///
	/// <returns>Returns the base frequency</returns>
	const size_t FrequencyBase();

	/// <summary>
	/// The processor maximum frequency (newer Intel only)
	/// <para>A value of 0 is returned if the feature is not available on this cpu</para>
	/// </summary>
	///
	/// <returns>Returns the maximum frequency</returns>
	const size_t FrequencyMax();

	/// <summary>
	/// Hardware supports hyper-threading
	/// </summary>
	///
	/// <returns>Returns true if the feature is available</returns>
	const bool HyperThread();

	/// <summary>
	/// Cpu is x64 emulating an x86 architecture
	/// </summary>
	///
	/// <returns>Returns true if the feature is available</returns>
	const bool IsX86Emulation();

	/// <summary>
	/// Cpu is x64
	/// </summary>
	///
	/// <returns>Returns true if the feature is available</returns>
	const bool IsX64();

	/// <summary>
	/// The total L1 data/instruction cache size in bytes for each physical processor core, defaults to 32kib
	/// </summary>
	///
	/// <returns>Returns the size of each L1 cache</returns>
	const size_t L1CacheSize();

	/// <summary>
	/// The total L1 data/instruction cache line size in bytes for each physical processor core, defaults to 64 bytes
	/// </summary>
	///
	/// <returns>Returns the L1 cache line size</returns>
	const size_t L1CacheLineSize();

	/// <summary>
	/// The total L1 data/instruction cache size in bytes for all processor cores, defaults to 256kib
	/// </summary>
	///
	/// <returns>Returns the total size of L1 cache memory</returns>
	const size_t L1CacheTotal();

	/// <summary>
	/// The total L1 data cache size in bytes for all processor cores, defaults to 256kib
	/// </summary>
	///
	/// <returns>Returns the total size of L1 data cache memory</returns>
	const size_t L1DataCacheTotal();

	/// <summary>
	/// The total L2 cache size in bytes for each physical processor core, defaults to 128kib
	/// </summary>
	///
	/// <returns>Returns the size of each L2 cache memory</returns>
	const size_t L2CacheSize();

	/// <summary>
	/// The total L2 cache size in bytes for all processor cores, defaults to 256kib
	/// </summary>
	///
	/// <returns>Returns the total size of L2 cache memory</returns>
	const size_t L2CacheTotal();

	/// <summary>
	/// Returns the L2 cache associativity
	/// </summary>
	///
	/// <returns>Returns the processors L2 associativity</returns>
	const CacheAssociations L2Associative();

	/// <summary>
	/// The maximum number of logical processors per core
	/// </summary>
	///
	/// <returns>Returns the number of logical processors per core</returns>
	const size_t LogicalPerCore();

	/// <summary>
	/// Intel Memory Protection Extensions
	/// </summary>
	///
	/// <returns>Returns true if the feature is available</returns>
	const bool MPX();

	/// <summary>
	/// The total number of physical processor cores
	/// </summary>
	///
	/// <returns>Returns the number of phsical processor cores</returns>
	const size_t PhysicalCores();

	/// <summary>
	/// Platform Quality of Service Enforcement
	/// </summary>
	///
	/// <returns>Returns true if the feature is available</returns>
	const bool PQE();

	/// <summary>
	/// Platform Quality of Service Monitoring
	/// </summary>
	///
	/// <returns>Returns true if the feature is available</returns>
	const bool PQM();

	/// <summary>
	/// Cpu supports prefetch
	/// </summary>
	///
	/// <returns>Returns true if the feature is available</returns>
	const bool PREFETCH();

	/// <summary>
	/// Intel Digital Random Number Generator
	/// </summary>
	///
	/// <returns>Returns true if the feature is available</returns>
	const bool RDRAND();

	/// <summary>
	/// Intel Digital Random Seed Generator
	/// </summary>
	///
	/// <returns>Returns true if the feature is available</returns>
	const bool RDSEED();

	/// <summary>
	/// RDTSCP time-stamp instruction
	/// </summary>
	///
	/// <returns>Returns true if the feature is available</returns>
	const bool RDTSCP();

	/// <summary>
	/// TSE Restricted Transactional Memory
	/// </summary>
	///
	/// <returns>Returns true if the feature is available</returns>
	const bool RTM();

	/// <summary>
	/// The processor serial number (not supported on some processors)
	/// </summary>
	///
	/// <returns>Returns the CPU serial number</returns>
	const std::string &SerialNumber();

	/// <summary>
	/// SHA instructions available
	/// </summary>
	///
	/// <returns>Returns true if the feature is available</returns>
	const bool SHA();

	/// <summary>
	/// Supervisor Mode Access Prevention
	/// </summary>
	///
	/// <returns>Returns true if the feature is available</returns>
	const bool SMAP();

	/// <summary>
	/// Returns true if SSE or greater is detected
	/// </summary>
	///
	/// <returns>Returns true if the feature is available</returns>
	const bool SSE();

	/// <summary>
	/// Streaming SIMD Extensions 2.0 available
	/// </summary>
	///
	/// <returns>Returns true if the feature is available</returns>
	const bool SSE2();

	/// <summary>
	/// Streaming SIMD Extensions 3.0 available
	/// </summary>
	///
	/// <returns>Returns true if the feature is available</returns>
	const bool SSE3();

	/// <summary>
	/// Supplemental SSE3 Merom New Instructions available
	/// </summary>
	///
	/// <returns>Returns true if the feature is available</returns>
	const bool SSSE3();

	/// <summary>
	/// AMD SSE 4A instructions available
	/// </summary>
	///
	/// <returns>Returns true if the feature is available</returns>
	const bool SSE4A();

	/// <summary>
	/// Streaming SIMD Extensions 4.1 available
	/// </summary>
	///
	/// <returns>Returns true if the feature is available</returns>
	const bool SSE41();

	/// <summary>
	/// Streaming SIMD Extensions 4.2 available
	/// </summary>
	///
	/// <returns>Returns true if the feature is available</returns>
	const bool SSE42();

	/// <summary>
	/// Returns the cpu vendors enumeration value
	/// </summary>
	///
	/// <returns>Returns the CPU vendors string</returns>
	CpuVendors Vendor();

	/// <summary>
	/// The total number of threads available using hyperthreading
	/// </summary>
	///
	/// <returns>Returns the total number of virtual and physical cores</returns>
	const size_t VirtualCores();

	/// <summary>
	/// Returns true if the AMD eXtended Operations feature set is detected
	/// </summary>
	///
	/// <returns>Returns true if the feature is available</returns>
	const bool XOP();

	/// <summary>
	/// Returns true if the AVX feature set is detected
	/// </summary>
	///
	/// <returns>Returns true if the feature is available</returns>
	static bool AvxEnabled();

	/// <summary>
	/// Returns true if the AVX2 feature set is detected
	/// </summary>
	///
	/// <returns>Returns true if the feature is available</returns>
	static bool Avx2Enabled();

private:


	void BusInfo();
	static void Cpuid(int32_t Flag, std::array<uint32_t, 4> &Output);
	static void CpuidSublevel(int32_t Flag, int32_t Level, std::array<uint32_t, 4> &Output);
	bool HasFeature(CpuidFlags Flag);
	void Initialize();
	static size_t MaxCoresPerPackage();
	size_t MaxLogicalPerCores();
	void PrintCpuStats();
	static uint32_t ReadBits(uint32_t Value, int32_t Index, int32_t Length);
	void StoreSerialNumber();
	void StoreTopology();
	const CpuVendors VendorName(std::string &Name);
	std::string VendorString(std::array<uint32_t, 4> &CpuInfo);
};

NAMESPACE_ROOTEND
#endif
