#include "CpuDetect.h"
#include <algorithm>
#include <thread>

#if defined(CEX_ARCH_X86_X64)
#	if defined(CEX_COMPILER_MSC)
#		include <intrin.h>
#		define X86_CPUID(type, out) do { __cpuid((int*)out, type); } while(0)
#		define X86_CPUID_SUBLEVEL(type, level, out) do { __cpuidex((int*)out, type, level); } while(0)
#	elif defined(CEX_COMPILER_INTEL)
#		include <ia32intrin.h>
#		define X86_CPUID(type, out) do { __cpuid(out, type); } while(0)
#		define X86_CPUID_SUBLEVEL(type, level, out) do { __cpuidex((int*)out, type, level); } while(0)
#	elif defined(CEX_ARCH_X64) && defined(CEX_USE_GCC_INLINE_ASM)
#		define X86_CPUID(type, out)															\
			asm("cpuid\n\t" : "=a" (out[0]), "=b" (out[1]), "=c" (out[2]), "=d" (out[3])	\
				: "0" (type))
#		define X86_CPUID_SUBLEVEL(type, level, out)											\
			asm("cpuid\n\t" : "=a" (out[0]), "=b" (out[1]), "=c" (out[2]), "=d" (out[3])	\
				: "0" (type), "2" (level))
#	elif defined(CEX_COMPILER_GCC) || defined(CEX_COMPILER_CLANG)
#		include <cpuid.h>
#		define X86_CPUID(type, out) do { __get_cpuid(type, out, out+1, out+2, out+3); } while(0)
#		define X86_CPUID_SUBLEVEL(type, level, out)											\
			do { __cpuid_count(type, level, out[0], out[1], out[2], out[3]); } while(0)
#	else
#		warning "No way of calling cpuid for this compiler"
#		define X86_CPUID(type, out) do { clear_mem(out, 4); } while(0)
#		define X86_CPUID_SUBLEVEL(type, level, out) do { clear_mem(out, 4); } while(0)
#	endif
#else
#	warning "No way of calling cpuid for this compiler"
#endif

NAMESPACE_COMMON

//~~~ Properties~~~//

const bool CpuDetect::ABM() 
{
	return GetFlag(CpuidFlags::CPUID_ABM); 
}

const bool CpuDetect::ADS()
{
	return GetFlag(CpuidFlags::CPUID_ADX);
}

const bool CpuDetect::AESNI()
{ 
	return GetFlag(CpuidFlags::CPUID_AESNI);
}

const bool CpuDetect::AVX() 
{
	return GetFlag(CpuidFlags::CPUID_AVX); 
}

const bool CpuDetect::AVX2() 
{ 
	return GetFlag(CpuidFlags::CPUID_AVX2); 
}

const bool CpuDetect::AVX512F()
{
	return GetFlag(CpuidFlags::CPUID_AVX512F); 
}

const bool CpuDetect::BMT2()
{
	return GetFlag(CpuidFlags::CPUID_BMI2); 
}

const size_t CpuDetect::BusSpeed()
{
	return m_busSpeed;
}

const bool CpuDetect::CMUL() 
{ 
	return GetFlag(CpuidFlags::CPUID_CMUL);
}

const bool CpuDetect::FMA4() { return GetFlag(CpuidFlags::CPUID_FMA4); }

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
	return GetFlag(CpuidFlags::CPUID_HYPERTHREAD); 
}

const bool CpuDetect::IsX64() 
{
	return GetFlag(CpuidFlags::CPUID_X64);
}

const size_t CpuDetect::L1CacheSize()
{
	if (m_l1CacheSize == 0 || m_physCores == 0)
		return KB32;
	else
		return m_l1CacheSize * KB1;
}

const size_t CpuDetect::L1CacheLineSize()
{
	if (m_l1CacheLineSize == 0)
		return 64;
	else
		return m_l1CacheLineSize;
}

const size_t CpuDetect::L1CacheTotal()
{
	if (m_l1CacheSize == 0 || m_physCores == 0)
		return KB256;
	else
		return m_l1CacheSize * m_physCores * KB1;
}

const size_t CpuDetect::L1DataCacheTotal()
{
	if (m_l1CacheSize == 0 || m_physCores == 0)
		return KB256;
	else
		return (m_l1CacheSize / 2) * m_physCores * KB1;
}

const size_t CpuDetect::L2CacheSize()
{
	if (m_l2CacheSize == 0 || m_physCores == 0)
		return KB128;
	else
		return m_l2CacheSize * KB1;
}

const size_t CpuDetect::L2CacheTotal()
{
	if (m_l2CacheSize == 0 || m_physCores == 0)
		return KB256;
	else
		return m_l2CacheSize * m_physCores * KB1;
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
	return GetFlag(CpuidFlags::CPUID_MPX); 
}

const size_t CpuDetect::PhysicalCores()
{ 
	return m_physCores;
}

const bool CpuDetect::PQE() 
{ 
	return GetFlag(CpuidFlags::CPUID_PQE);
}

const bool CpuDetect::PQM()
{ 
	return GetFlag(CpuidFlags::CPUID_PQM);
}

const bool CpuDetect::PREFETCH() 
{ 
	return GetFlag(CpuidFlags::CPUID_PREFETCH);
}

const bool CpuDetect::RDRAND()
{
	return GetFlag(CpuidFlags::CPUID_RDRAND);
}

const bool CpuDetect::RDSEED() 
{ 
	return GetFlag(CpuidFlags::CPUID_RDSEED); 
}

const bool CpuDetect::RDTSCP() 
{ 
	return GetFlag(CpuidFlags::CPUID_RDTSCP);
}

const bool CpuDetect::RTM() 
{
	return GetFlag(CpuidFlags::CPUID_RTM); 
}

const std::string &CpuDetect::SerialNumber() 
{
	return m_serialNumber;
}

const bool CpuDetect::SHA() 
{ 
	return GetFlag(CpuidFlags::CPUID_SHA);
}

const bool CpuDetect::SMAP() 
{ 
	return GetFlag(CpuidFlags::CPUID_SMAP); 
}

const bool CpuDetect::SSE()
{ 
	return GetFlag(CpuidFlags::CPUID_SSE2); 
}

const bool CpuDetect::SSE2() 
{ 
	return GetFlag(CpuidFlags::CPUID_SSE2); 
}

const bool CpuDetect::SSE3()
{
	return GetFlag(CpuidFlags::CPUID_SSE3);
}

const bool CpuDetect::SSSE3()
{ 
	return GetFlag(CpuidFlags::CPUID_SSSE3);
}

const bool CpuDetect::SSE4A()
{
	return GetFlag(CpuidFlags::CPUID_SSE4A);
}

const bool CpuDetect::SSE41() 
{
	return GetFlag(CpuidFlags::CPUID_SSE41);
}

const bool CpuDetect::SSE42()
{ 
	return GetFlag(CpuidFlags::CPUID_SSE42); 
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
	return GetFlag(CpuidFlags::CPUID_XOP);
}

//~~~ Constructor~~~//

CpuDetect::CpuDetect()
	:
	m_busSpeed(0),
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
	m_virtCores(0)
{
	Initialize();
}

//~~~Private Functions~~~//

bool CpuDetect::AvxEnabled()
{
	uint cpuInfo[4];

	X86_CPUID(1, cpuInfo);

	// check if os saves the ymm registers
	if ((cpuInfo[2] & (1 << 27)) && (cpuInfo[2] & (1 << 28)))
		return (_xgetbv(_XCR_XFEATURE_ENABLED_MASK) & 0x6) != 0;

	return false;
}

bool CpuDetect::Avx2Enabled()
{
	uint cpuInfo[4];

	X86_CPUID(1, cpuInfo);

	if ((cpuInfo[2] & (1 << 27)) && (cpuInfo[2] & (1 << 28)))
		return (_xgetbv(_XCR_XFEATURE_ENABLED_MASK) & 0xe6) != 0;

	return false;
}

void CpuDetect::Initialize()
{
	uint cpuInfo[4] = { 0 };
	X86_CPUID(0, cpuInfo);

	m_cpuVendorString = GetVendorString(cpuInfo);
	m_cpuVendor = GetVendor(m_cpuVendorString);

	const uint maxSublevel = cpuInfo[0];

	if (maxSublevel == 0)
		return;

	memset(cpuInfo, 0, 4);
	X86_CPUID(1, cpuInfo);

	m_hyperThread = READBITSFROM(cpuInfo[3], 28, 1) != 0;
	// safest way
	m_virtCores = std::thread::hardware_concurrency();
	// yes, ht might be disabled in bios, but who does that?
	m_physCores = m_hyperThread == true && m_virtCores > 1 ? m_virtCores / 2 : m_virtCores;

	m_x86CpuFlags[0] = (static_cast<ulong>(cpuInfo[3]) << 32) | cpuInfo[2]; // f1 ecx, edx

	if (m_cpuVendor == CpuVendors::INTEL)
		m_cacheLineSize = 8 * READBITSFROM(cpuInfo[1], 16, 8);

	if (maxSublevel >= 7)
	{
		memset(cpuInfo, 0, 16);
		X86_CPUID_SUBLEVEL(7, 0, cpuInfo);
		m_x86CpuFlags[1] = (static_cast<ulong>(cpuInfo[2]) << 32) | cpuInfo[1]; // f7 ebx, ecx
	}

	if (maxSublevel >= 5)
	{
		memset(cpuInfo, 0, 16);
		X86_CPUID(0x80000005, cpuInfo);
		if (m_cpuVendor == CpuVendors::AMD)
			m_cacheLineSize = READBITSFROM(cpuInfo[2], 24, 8);

		memset(cpuInfo, 0, 16);
		X86_CPUID(0x80000001, cpuInfo);
		m_x86CpuFlags[2] = (static_cast<ulong>(cpuInfo[3]) << 32) | cpuInfo[2]; // f8..1 ecx, edx

		GetTopology();
	}

	// fallbacks
	if (m_l1CacheSize == 0 || m_l1CacheSize % 8 != 0)
		m_l1CacheSize = 64;
	if (m_l1CacheLineSize == 0 || m_l1CacheLineSize % 8 != 0)
		m_l1CacheLineSize = 64;
	if (m_l2CacheSize == 0 || m_l2CacheSize % 8 != 0)
		m_l2CacheSize = 256;
}

bool CpuDetect::GetFlag(CpuidFlags Flag)
{
	return ((m_x86CpuFlags[Flag / 64] >> (Flag % 64)) & 1);
}

void CpuDetect::GetFrequency()
{
	uint cpuInfo[4];
	X86_CPUID(0, cpuInfo);

	if (cpuInfo[0] >= 0x16)
	{
		memset(cpuInfo, 0, 16);
		X86_CPUID(0x16, cpuInfo);
		m_frequencyBase = cpuInfo[0];
		m_frequencyMax = cpuInfo[1];
		m_busSpeed = cpuInfo[2];
	}
}

void CpuDetect::GetSerialNumber()
{
	uint cpuInfo[4];
	X86_CPUID(0x00000003, cpuInfo);

	char prcId[8];
	memset(prcId, 0, sizeof(prcId));
	*((int*)(prcId)) = cpuInfo[3];
	*((int*)(prcId + 4)) = cpuInfo[2];

	m_serialNumber = std::string(prcId);
}

size_t CpuDetect::GetMaxCoresPerPackage()
{
	return std::thread::hardware_concurrency();
}

size_t CpuDetect::GetMaxLogicalPerCore()
{
	if (!m_hyperThread)
		return 1;

	uint cpuInfo[4];
	X86_CPUID(1, cpuInfo);

	size_t logical = static_cast<size_t>(READBITSFROM(cpuInfo[0], 16, 8));
	size_t cores = GetMaxCoresPerPackage();

	if (logical % cores == 0)
		return logical / cores;

	return 1;
}

void CpuDetect::GetTopology()
{
	m_virtCores = std::thread::hardware_concurrency();
	m_physCores = m_hyperThread == true && m_virtCores > 1 ? m_virtCores / 2 : m_virtCores;
	GetFrequency();
	GetSerialNumber();

	uint cpuInfo[4];
	X86_CPUID(0x80000006, cpuInfo);

	m_l1CacheSize = static_cast<size_t>(READBITSFROM(cpuInfo[2], 0, 8));
	m_l1CacheLineSize = static_cast<size_t>(READBITSFROM(cpuInfo[2], 0, 11));
	m_l2Associative = static_cast<CacheAssociations>(READBITSFROM(cpuInfo[2], 12, 4));
	m_l2CacheSize = static_cast<size_t>(READBITSFROM(cpuInfo[2], 16, 16));
}

const CpuDetect::CpuVendors CpuDetect::GetVendor(std::string &Name)
{
	if (Name.size() > 0)
	{
		std::string data = Name;
		std::transform(data.begin(), data.end(), data.begin(), ::tolower);
		if (data.find("intel", 0) != std::string::npos)
			return CpuVendors::INTEL;
		else if (data.find("amd", 0) != std::string::npos)
			return CpuVendors::AMD;
	}

	return CpuVendors::UNKNOWN;
}

std::string CpuDetect::GetVendorString(uint CpuInfo[4])
{
	// cpu vendor name
	char vendId[0x20];

	memset(vendId, 0, sizeof(vendId));
	*((int*)vendId) = CpuInfo[1];
	*((int*)(vendId + 4)) = CpuInfo[3];
	*((int*)(vendId + 8)) = CpuInfo[2];

	return std::string(vendId);
}

NAMESPACE_COMMONEND