#include "CpuDetect.h"
#include <thread>
#if defined(CEX_ARCH_X86_X64)
#	if defined(CEX_COMPILER_MSC)
#		include <intrin.h>
#	elif defined(CEX_COMPILER_INTEL)
#		include <ia32intrin.h>
#	elif defined(CEX_COMPILER_GCC) || defined(CEX_COMPILER_CLANG)
#		include <cpuid.h>
#	endif
#endif

NAMESPACE_ROOT

//~~~ Constructor~~~//

CpuDetect::CpuDetect()
	:
	m_busRefFrequency(0),
	m_cacheLineSize(0),
	m_cpuVendor(CpuVendors::UNKNOWN),
	m_cpuVendorString(""),
	m_frequencyBase(0),
	m_frequencyMax(0),
	m_hyperThread(false),
	m_l1CacheSize(0),
	m_l1CacheLineSize(0),
	m_l2Associative(CacheAssociations::Disabled),
	m_l2CacheSize(0),
	m_logicalPerCore(0),
	m_physCores(0),
	m_serialNumber(""),
	m_virtCores(0),
	m_x86CpuFlags(8)
{
	Initialize();
	// Misra exception: for internal debug purposes only
	// PrintCpuStats();
}

CpuDetect::~CpuDetect()
{
	m_busRefFrequency = 0;
	m_cacheLineSize = 0;
	m_cpuVendor = CpuVendors::UNKNOWN;
	m_cpuVendorString.clear();
	m_frequencyBase = 0;
	m_frequencyMax = 0;
	m_hyperThread = false;
	m_l1CacheLineSize = 0;
	m_l1CacheSize = 0;
	m_l2Associative = CacheAssociations::Disabled;
	m_l2CacheSize = 0;
	m_logicalPerCore = 0;
	m_physCores = 0;
	m_serialNumber.clear();
	m_virtCores = 0;
	m_x86CpuFlags.clear();
}

//~~~ Properties~~~//

const bool CpuDetect::ABM() 
{
	return HasFeature(CpuidFlags::CPUID_ABM); 
}

const bool CpuDetect::ADS()
{
	return HasFeature(CpuidFlags::CPUID_ADX);
}

const bool CpuDetect::AESNI()
{ 
	return HasFeature(CpuidFlags::CPUID_AESNI);
}

const bool CpuDetect::AVX() 
{
	return HasFeature(CpuidFlags::CPUID_AVX); 
}

const bool CpuDetect::AVX2() 
{ 
	return HasFeature(CpuidFlags::CPUID_AVX2); 
}

const bool CpuDetect::AVX512F()
{
	return HasFeature(CpuidFlags::CPUID_AVX512F); 
}

const bool CpuDetect::BMT2()
{
	return HasFeature(CpuidFlags::CPUID_BMI2); 
}

const size_t CpuDetect::BusRefFrequency()
{
	return m_busRefFrequency;
}

const bool CpuDetect::CMUL() 
{ 
	return HasFeature(CpuidFlags::CPUID_CMUL);
}

const bool CpuDetect::FMA4() { return HasFeature(CpuidFlags::CPUID_FMA4); }

const size_t CpuDetect::FrequencyBase()
{
	return m_frequencyBase;
}

const size_t CpuDetect::FrequencyMax()
{
	return m_frequencyMax;
}

const bool CpuDetect::HyperThread() 
{
	return HasFeature(CpuidFlags::CPUID_HYPERTHREAD); 
}

const bool CpuDetect::IsX86Emulation()
{
	return HasFeature(CpuidFlags::CPUID_X86EMU);
}

const bool CpuDetect::IsX64() 
{
	return HasFeature(CpuidFlags::CPUID_X64);
}

const size_t CpuDetect::L1CacheSize()
{
	size_t res;

	if (m_l1CacheSize == 0 || m_physCores == 0)
	{
		res = KB32;
	}
	else
	{
		res = m_l1CacheSize * KB1;
	}

	return res;
}

const size_t CpuDetect::L1CacheLineSize()
{
	size_t res;

	if (m_l1CacheLineSize == 0)
	{
		res = 64;
	}
	else
	{
		res = m_l1CacheLineSize;
	}

	return res;
}

const size_t CpuDetect::L1CacheTotal()
{
	size_t res;

	if (m_l1CacheSize == 0 || m_physCores == 0)
	{
		res = KB256;
	}
	else
	{
		res = m_l1CacheSize * m_physCores * KB1;
	}

	return res;
}

const size_t CpuDetect::L1DataCacheTotal()
{
	size_t res;

	if (m_l1CacheSize == 0 || m_physCores == 0)
	{
		res = KB256;
	}
	else
	{
		res = (m_l1CacheSize / 2) * m_physCores * KB1;
	}

	return res;
}

const size_t CpuDetect::L2CacheSize()
{
	size_t res;

	if (m_l2CacheSize == 0 || m_physCores == 0)
	{
		res = KB128;
	}
	else
	{
		res = m_l2CacheSize * KB1;
	}

	return res;
}

const size_t CpuDetect::L2CacheTotal()
{
	size_t res;

	if (m_l2CacheSize == 0 || m_physCores == 0)
	{
		res = KB256;
	}
	else
	{
		res = m_l2CacheSize * m_physCores * KB1;
	}

	return res;
}

const CpuDetect::CacheAssociations CpuDetect::L2Associative()
{ 
	return m_l2Associative; 
}

const size_t CpuDetect::LogicalPerCore() 
{ 
	return m_logicalPerCore;
}

const bool CpuDetect::MPX() 
{ 
	return HasFeature(CpuidFlags::CPUID_MPX); 
}

const size_t CpuDetect::PhysicalCores()
{ 
	return m_physCores;
}

const bool CpuDetect::PQE() 
{ 
	return HasFeature(CpuidFlags::CPUID_PQE);
}

const bool CpuDetect::PQM()
{ 
	return HasFeature(CpuidFlags::CPUID_PQM);
}

const bool CpuDetect::PREFETCH() 
{ 
	return HasFeature(CpuidFlags::CPUID_PREFETCH);
}

const bool CpuDetect::RDRAND()
{
	return HasFeature(CpuidFlags::CPUID_RDRAND);
}

const bool CpuDetect::RDSEED() 
{ 
	return HasFeature(CpuidFlags::CPUID_RDSEED); 
}

const bool CpuDetect::RDTSCP() 
{ 
	return HasFeature(CpuidFlags::CPUID_RDTSCP);
}

const bool CpuDetect::RTM() 
{
	return HasFeature(CpuidFlags::CPUID_RTM); 
}

const std::string &CpuDetect::SerialNumber() 
{
	return m_serialNumber;
}

const bool CpuDetect::SHA() 
{ 
	return HasFeature(CpuidFlags::CPUID_SHA);
}

const bool CpuDetect::SMAP() 
{ 
	return HasFeature(CpuidFlags::CPUID_SMAP); 
}

const bool CpuDetect::SSE()
{ 
	return HasFeature(CpuidFlags::CPUID_SSE2); 
}

const bool CpuDetect::SSE2() 
{ 
	return HasFeature(CpuidFlags::CPUID_SSE2); 
}

const bool CpuDetect::SSE3()
{
	return HasFeature(CpuidFlags::CPUID_SSE3);
}

const bool CpuDetect::SSSE3()
{ 
	return HasFeature(CpuidFlags::CPUID_SSSE3);
}

const bool CpuDetect::SSE4A()
{
	return HasFeature(CpuidFlags::CPUID_SSE4A);
}

const bool CpuDetect::SSE41() 
{
	return HasFeature(CpuidFlags::CPUID_SSE41);
}

const bool CpuDetect::SSE42()
{ 
	return HasFeature(CpuidFlags::CPUID_SSE42); 
}

CpuDetect::CpuVendors CpuDetect::Vendor()
{ 
	return m_cpuVendor; 
}

const size_t CpuDetect::VirtualCores()
{ 
	return m_virtCores; 
}

const bool CpuDetect::XOP() 
{ 
	return HasFeature(CpuidFlags::CPUID_XOP);
}

bool CpuDetect::AvxEnabled()
{
	std::array<uint, 4> cpuInfo;
	Cpuid(1, cpuInfo);
	bool status = false;

	// check if os saves the ymm registers
	if (((cpuInfo[2] & (1UL << 27)) != 0) && ((cpuInfo[2] & (1UL << 28)) != 0))
	{
		status = (_xgetbv(_XCR_XFEATURE_ENABLED_MASK) & 0x06) != 0;
	}

	return status;
}

bool CpuDetect::Avx2Enabled()
{
	std::array<uint, 4> cpuInfo;
	Cpuid(1, cpuInfo);
	bool status = false;

	if (((cpuInfo[2] & (1UL << 27)) != 0) && (cpuInfo[2] & (1UL << 28)) != 0)
	{
		status = (_xgetbv(_XCR_XFEATURE_ENABLED_MASK) & 0xE6) != 0;
	}

	return status;
}

//~~~Private Functions~~~//

void CpuDetect::BusInfo()
{
	std::array<uint, 4> cpuInfo;
	Cpuid(0, cpuInfo);

	if (cpuInfo[0] >= 0x16)
	{
		std::memset(&cpuInfo[0], 0, 16);
		Cpuid(0x16, cpuInfo);
		m_frequencyBase = cpuInfo[0];
		m_frequencyMax = cpuInfo[1];
		m_busRefFrequency = cpuInfo[2];
	}
}

void CpuDetect::Cpuid(int Flag, std::array<uint, 4> &Output)
{
#if defined(CEX_ARCH_X86_X64)
#	if defined(CEX_COMPILER_MSC)
	__cpuid(reinterpret_cast<int*>(Output.data()), Flag);
#	elif defined(CEX_COMPILER_GCC) || defined(CEX_COMPILER_CLANG)
	__get_cpuid(Flag, Output[0], Output[1], Output[2], Output[3]);
#	endif
#endif
}

void CpuDetect::CpuidSublevel(int Flag, int Level, std::array<uint, 4> &Output)
{
#if defined(CEX_ARCH_X86_X64)
#	if defined(CEX_COMPILER_MSC)
	__cpuidex(reinterpret_cast<int*>(Output.data()), Flag, Level);
#	elif defined(CEX_COMPILER_GCC) || defined(CEX_COMPILER_CLANG)
	__cpuid_count(Flag, Level, Output[0], Output[1], Output[2], Output[3]);
#	endif
#endif
}

bool CpuDetect::HasFeature(CpuidFlags Flag)
{
	uint f = static_cast<uint>(Flag);
	return static_cast<bool>(ReadBits(m_x86CpuFlags[(f / 32)], (f % 32), 1));
}

void CpuDetect::Initialize()
{
	std::array<uint, 4> cpuInfo;
	Cpuid(0, cpuInfo);
	const uint SUBLVL = cpuInfo[0];

	if (SUBLVL != 0)
	{
		m_cpuVendorString = VendorString(cpuInfo);
		m_cpuVendor = VendorName(m_cpuVendorString);

		std::memset(cpuInfo.data(), 0, 4);
		Cpuid(1, cpuInfo);

		m_hyperThread = ReadBits(cpuInfo[3], 28, 1) != 0;
		// safest way on multi-platform
		m_virtCores = std::thread::hardware_concurrency();
		// yes, ht might be disabled in bios, but who does that?
		m_physCores = (m_hyperThread == true && m_virtCores > 1) ? (m_virtCores / 2) : m_virtCores;
		m_logicalPerCore = (m_virtCores > m_physCores) ? (m_virtCores / m_physCores) : 1;
		// f1 ecx, edx
		std::memcpy(&m_x86CpuFlags[0], &cpuInfo[2], 2 * sizeof(ulong));

		if (m_cpuVendor == CpuVendors::INTEL)
		{
			m_cacheLineSize = static_cast<size_t>(ReadBits(cpuInfo[1], 16, 8)) * 8UL;
		}

		if (SUBLVL >= 7)
		{
			std::memset(cpuInfo.data(), 0, 16);
			CpuidSublevel(7, 0, cpuInfo);
			// f7 ebx, ecx
			std::memcpy(&m_x86CpuFlags[2], &cpuInfo[1], 2 * sizeof(ulong));
		}

		if (SUBLVL >= 5)
		{
			std::memset(cpuInfo.data(), 0, 16);
			Cpuid(0x80000005UL, cpuInfo);

			if (m_cpuVendor == CpuVendors::AMD)
			{
				m_cacheLineSize = ReadBits(cpuInfo[2], 24, 8);
			}

			std::memset(cpuInfo.data(), 0, 16);
			Cpuid(0x80000001UL, cpuInfo);
			// f8..1 ecx, edx
			std::memcpy(&m_x86CpuFlags[4], &cpuInfo[2], 2 * sizeof(ulong));
			StoreTopology();
		}
	}

	// fallbacks, required by parallel auto-size feature
	if (m_l1CacheSize == 0 || m_l1CacheSize % 8 != 0)
	{
		m_l1CacheSize = 64;
	}

	if (m_l1CacheLineSize == 0 || m_l1CacheLineSize % 8 != 0)
	{
		m_l1CacheLineSize = 64;
	}

	if (m_l2CacheSize == 0 || m_l2CacheSize % 8 != 0)
	{
		m_l2CacheSize = 256;
	}
}

size_t CpuDetect::MaxCoresPerPackage()
{
	return std::thread::hardware_concurrency();
}

size_t CpuDetect::MaxLogicalPerCores()
{
	size_t maxLogical = 1;

	if (m_hyperThread)
	{
		std::array<uint, 4> cpuInfo;
		Cpuid(1, cpuInfo);

		size_t logical = static_cast<size_t>(ReadBits(cpuInfo[0], 16, 8));
		size_t cores = MaxCoresPerPackage();

		if (logical % cores == 0)
		{
			maxLogical = logical / cores;
		}
	}

	return maxLogical;
}

void CpuDetect::PrintCpuStats()
{
	// prints current config (internal tests)
	auto BoolStr = [](auto res) { return res ? "True" : "False"; };

	std::cout << "ABM: " << BoolStr(ABM()) << std::endl;
	std::cout << "ADS: " << BoolStr(ADS()) << std::endl;
	std::cout << "AESNI: " << BoolStr(AESNI()) << std::endl;
	std::cout << "AVX: " << BoolStr(AVX()) << std::endl;
	std::cout << "AVX2: " << BoolStr(AVX2()) << std::endl;
	std::cout << "AVX512F: " << BoolStr(AVX512F()) << std::endl;
	std::cout << "AESNI: " << BoolStr(AESNI()) << std::endl;
	std::cout << "BMT2: " << BoolStr(BMT2()) << std::endl;
	std::cout << "BusRefFrequency: " << BusRefFrequency() << std::endl;
	std::cout << "CMUL: " << BoolStr(CMUL()) << std::endl;
	std::cout << "FMA4: " << BoolStr(FMA4()) << std::endl;
	std::cout << "FrequencyBase: " << FrequencyBase() << std::endl;
	std::cout << "FrequencyMax: " << FrequencyMax() << std::endl;
	std::cout << "HyperThread: " << BoolStr(HyperThread()) << std::endl;
	std::cout << "IsX86Emulation: " << BoolStr(IsX86Emulation()) << std::endl;
	std::cout << "IsX64: " << BoolStr(IsX64()) << std::endl;
	std::cout << "L1CacheSize: " << L1CacheSize() << std::endl;
	std::cout << "L1CacheLineSize: " << L1CacheLineSize() << std::endl;
	std::cout << "L1CacheTotal: " << L1CacheTotal() << std::endl;
	std::cout << "L1DataCacheTotal: " << L1DataCacheTotal() << std::endl;
	std::cout << "L2CacheSize: " << L2CacheSize() << std::endl;
	std::cout << "L2CacheTotal: " << L2CacheTotal() << std::endl;
	std::cout << "L2CacheSize: " << L2CacheSize() << std::endl;
	std::cout << "L2CacheTotal: " << L2CacheTotal() << std::endl;
	std::cout << "L2Associative: " << static_cast<uint>(L2Associative()) << std::endl;
	std::cout << "LogicalPerCore: " << LogicalPerCore() << std::endl;
	std::cout << "MPX: " << BoolStr(MPX()) << std::endl;
	std::cout << "PhysicalCores: " << PhysicalCores() << std::endl;
	std::cout << "PQE: " << BoolStr(PQE()) << std::endl;
	std::cout << "PQM: " << BoolStr(PQM()) << std::endl;
	std::cout << "PREFETCH: " << BoolStr(PREFETCH()) << std::endl;
	std::cout << "RDRAND: " << BoolStr(RDRAND()) << std::endl;
	std::cout << "RDSEED: " << BoolStr(RDSEED()) << std::endl;
	std::cout << "RDTSCP: " << BoolStr(RDTSCP()) << std::endl;
	std::cout << "RTM: " << BoolStr(RTM()) << std::endl;
	std::cout << "SerialNumber: " << ((SerialNumber().size() == 0) ? "N/A" : SerialNumber()) << std::endl;
	std::cout << "SHA: " << BoolStr(SHA()) << std::endl;
	std::cout << "SMAP: " << BoolStr(SMAP()) << std::endl;
	std::cout << "SSE: " << BoolStr(SSE()) << std::endl;
	std::cout << "SSE2: " << BoolStr(SSE2()) << std::endl;
	std::cout << "SSE3: " << BoolStr(SSE3()) << std::endl;
	std::cout << "SSSE3: " << BoolStr(SSSE3()) << std::endl;
	std::cout << "SSE4A: " << BoolStr(SSE4A()) << std::endl;
	std::cout << "SSE41: " << BoolStr(SSE41()) << std::endl;
	std::cout << "SSE42: " << BoolStr(SSE42()) << std::endl;
	std::cout << "Vendor: " << ((Vendor() == CpuVendors::UNKNOWN) ? "Unknown" : ((Vendor() == CpuVendors::AMD) ? "AMD" : "Intel")) << std::endl;
	std::cout << "VirtualCores: " << VirtualCores() << std::endl;
	std::cout << "XOP: " << BoolStr(XOP()) << std::endl;
}

uint CpuDetect::ReadBits(uint Value, int Index, int Length)
{
	int mask = ((static_cast<int>(1) << Length) - 1) << Index;
	return (Value & mask) >> Index;
}

void CpuDetect::StoreSerialNumber()
{
	std::array<uint, 4> cpuInfo;
	Cpuid(0x00000003, cpuInfo);

	std::array<char, 8> prcId;
	std::memset(prcId.data(), 0, sizeof(prcId));
	std::memcpy(&prcId[0], &cpuInfo[3], 4);
	std::memcpy(&prcId[4], &cpuInfo[2], 4);

	m_serialNumber = std::string(prcId.data());
}

void CpuDetect::StoreTopology()
{
	m_virtCores = std::thread::hardware_concurrency();
	m_physCores = m_hyperThread == true && m_virtCores > 1 ? m_virtCores / 2 : m_virtCores;
	BusInfo();
	StoreSerialNumber();

	std::array<uint, 4> cpuInfo;
	Cpuid(0x80000006UL, cpuInfo);

	m_l1CacheSize = static_cast<size_t>(ReadBits(cpuInfo[2], 0, 8));
	m_l1CacheLineSize = static_cast<size_t>(ReadBits(cpuInfo[2], 0, 11));
	m_l2Associative = static_cast<CacheAssociations>(ReadBits(cpuInfo[2], 12, 4));
	m_l2CacheSize = static_cast<size_t>(ReadBits(cpuInfo[2], 16, 16));
}

const CpuDetect::CpuVendors CpuDetect::VendorName(std::string &Name)
{
	CpuVendors vendor = CpuVendors::UNKNOWN;

	if (Name.size() > 0)
	{
		std::string data = Name;
		std::transform(data.begin(), data.end(), data.begin(), ::tolower);

		if (data.find("intel", 0) != std::string::npos)
		{
			vendor = CpuVendors::INTEL;
		}
		else if (data.find("amd", 0) != std::string::npos)
		{
			vendor = CpuVendors::AMD;
		}
		else
		{
			vendor = CpuVendors::UNKNOWN;
		}
	}

	return vendor;
}

std::string CpuDetect::VendorString(std::array<uint, 4> &CpuInfo)
{
	// cpu vendor name
	std::array<char, 0x20> vendId;
	std::memset(vendId.data(), 0, sizeof(vendId));
	std::memcpy(&vendId[0], &CpuInfo[1], 4);
	std::memcpy(&vendId[4], &CpuInfo[3], 4);
	std::memcpy(&vendId[8], &CpuInfo[2], 4);

	return std::string(vendId.data());
}

NAMESPACE_ROOTEND
