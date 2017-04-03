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
#		define X86_CPUID(type, out)                                                    \
			asm("cpuid\n\t" : "=a" (out[0]), "=b" (out[1]), "=c" (out[2]), "=d" (out[3]) \
				: "0" (type))
#		define X86_CPUID_SUBLEVEL(type, level, out)                                    \
			asm("cpuid\n\t" : "=a" (out[0]), "=b" (out[1]), "=c" (out[2]), "=d" (out[3]) \
				: "0" (type), "2" (level))
#	elif defined(CEX_COMPILER_GCC) || defined(CEX_COMPILER_CLANG)
#		include <cpuid.h>
#		define X86_CPUID(type, out) do { __get_cpuid(type, out, out+1, out+2, out+3); } while(0)
#		define X86_CPUID_SUBLEVEL(type, level, out) \
			do { __cpuid_count(type, level, out[0], out[1], out[2], out[3]); } while(0)
#	else
#		warning "No way of calling cpuid for this compiler"
#		define X86_CPUID(type, out) do { clear_mem(out, 4); } while(0)
#		define X86_CPUID_SUBLEVEL(type, level, out) do { clear_mem(out, 4); } while(0)
#	endif
#endif
NAMESPACE_COMMON

//~~~ Constructor~~~//

CpuDetect::CpuDetect()
	:
	m_abm(false),
	m_ads(false),
	m_aesni(false),
	m_amd3dNow(false),
	m_amd3dNowPro(false),
	m_amdCmpLegacy(false),
	m_amdMmxExt(false),
	m_amdMp(false),
	m_avx(false),
	m_avx2(false),
	m_avx5124fmaps(false),
	m_avx512bw(false),
	m_avx512cd(false),
	m_avx512dq(false),
	m_avx512er(false),
	m_avx512f(false),
	m_avx512ifma(false),
	m_avx512pf(false),
	m_avx5124vnniw(false),
	m_avx512vbmi(false),
	m_avx512vl(false),
	m_bmt1(false),
	m_bmt2(false),
	m_busSpeed(0),
	m_cpuVendor(""),
	m_fma3(false),
	m_fma4(false),
	m_frequencyBase(0),
	m_frequencyMax(0),
	m_hle(false),
	m_hyperThread(false),
	m_l1CacheSize(0),
	m_l1CacheLineSize(0),
	m_l2Associative(CacheAssociations::Disabled),
	m_l2CacheSize(0),
	m_logicalPerCore(0),
	m_mmx(false),
	m_mpx(false),
	m_physCores(0),
	m_pku(false),
	m_pkuos(false),
	m_pqe(false),
	m_pqm(false),
	m_prefetch(false),
	m_rdRand(false),
	m_rdSeed(false),
	m_rdtscp(false),
	m_rtm(false),
	m_serialNumber(""),
	m_sgx(false),
	m_sha(false),
	m_smap(false),
	m_smep(false),
	m_sse1(false),
	m_sse2(false),
	m_sse3(false),
	m_sse41(false),
	m_sse42(false),
	m_sse4a(false),
	m_ssse3(false),
	m_virtCores(0),
	m_x64(false),
	m_xop(false)
{
	Detect();
}

//~~~Private Functions~~~//

#if defined(MSCAVX)
	bool CpuDetect::AvxSupported()
	{
		uint cpuInfo[4];

		X86_CPUID(1, cpuInfo);

		// check if os saves the ymm registers
		if ((cpuInfo[2] & (1 << 27)) && (cpuInfo[2] & (1 << 28)))
			return (_xgetbv(_XCR_XFEATURE_ENABLED_MASK) & 0x6) != 0;

		return false;
	}

	bool CpuDetect::Avx2Supported()
	{
		uint cpuInfo[4];

		X86_CPUID(1, cpuInfo);

		if ((cpuInfo[2] & (1 << 27)) && (cpuInfo[2] & (1 << 28)))
			return (_xgetbv(_XCR_XFEATURE_ENABLED_MASK) & 0xe6) != 0;

		return false;
	}
#endif

void CpuDetect::Detect()
{
	uint cpuInfo[4];
	X86_CPUID(0, cpuInfo);
	uint nIds = cpuInfo[0];

	// cpu vendor name
	char vendId[0x20];
	memset(vendId, 0, sizeof(vendId));
	*((int*)vendId) = cpuInfo[1];
	*((int*)(vendId + 4)) = cpuInfo[3];
	*((int*)(vendId + 8)) = cpuInfo[2];
	m_cpuVendor = std::string(vendId);

	X86_CPUID(0x80000000, cpuInfo);
	unsigned nExIds = cpuInfo[0];

	//  detect Features
	if (nIds >= 0x00000001)
	{
		X86_CPUID(0x00000001, cpuInfo);

		m_amdMp = READBITSFROM(cpuInfo[0], 19, 1) != 0;
		m_amdMmxExt = READBITSFROM(cpuInfo[0], 22, 1) != 0;
		m_amd3dNowPro = READBITSFROM(cpuInfo[0], 30, 1) != 0;
		m_amd3dNow = READBITSFROM(cpuInfo[0], 31, 1) != 0;

		m_amdCmpLegacy = (cpuInfo[1], 1, 1) != 0;

		m_sse3 = READBITSFROM(cpuInfo[2], 0, 1) != 0;
		m_cmul = READBITSFROM(cpuInfo[2], 1, 1) != 0;
		m_ssse3 = READBITSFROM(cpuInfo[2], 9, 1) != 0;
		m_fma3 = READBITSFROM(cpuInfo[2], 12, 1) != 0;
		m_sse41 = READBITSFROM(cpuInfo[2], 19, 1) != 0;
		m_sse42 = READBITSFROM(cpuInfo[2], 20, 1) != 0;
		m_aesni = READBITSFROM(cpuInfo[2], 25, 1) != 0;

#if defined(MSCAVX)
		m_avx = AvxSupported();
#else
		m_avx = READBITSFROM(cpuInfo[2], 28, 1) != 0;
#endif
		m_rdRand = READBITSFROM(cpuInfo[2], 30, 1) != 0;

		m_mmx = READBITSFROM(cpuInfo[3], 23, 1) != 0;
		m_sse1 = READBITSFROM(cpuInfo[3], 25, 1) != 0;
		m_sse2 = READBITSFROM(cpuInfo[3], 26, 1) != 0;
		m_rdtscp = READBITSFROM(cpuInfo[3], 27, 1) != 0;
		m_hyperThread = READBITSFROM(cpuInfo[3], 28, 1) != 0;
	}

	// extended features
	if (nIds >= 0x00000007)
	{
		X86_CPUID(0x00000007, cpuInfo);

		m_sgx = READBITSFROM(cpuInfo[1], 2, 1) != 0;
		m_bmt1 = READBITSFROM(cpuInfo[1], 3, 1) != 0;
		m_hle = READBITSFROM(cpuInfo[1], 4, 1) != 0;
#if defined(MSCAVX)
		m_avx2 = Avx2Supported();
#else
		m_avx2 = (cpuInfo[1], 5, 1) != 0;
#endif
		m_smep = READBITSFROM(cpuInfo[1], 7, 1) != 0;
		m_bmt2 = READBITSFROM(cpuInfo[1], 8, 1) != 0;
		m_rtm = READBITSFROM(cpuInfo[1], 11, 1) != 0;
		m_pqm = READBITSFROM(cpuInfo[1], 12, 1) != 0;
		m_mpx = READBITSFROM(cpuInfo[1], 14, 1) != 0;
		m_pqe = READBITSFROM(cpuInfo[1], 15, 1) != 0;
		m_avx512f = READBITSFROM(cpuInfo[1], 16, 1) != 0;
		m_avx512dq = READBITSFROM(cpuInfo[1], 17, 1) != 0;
		m_rdSeed = READBITSFROM(cpuInfo[1], 18, 1) != 0;
		m_ads = READBITSFROM(cpuInfo[1], 19, 1) != 0;
		m_smap = READBITSFROM(cpuInfo[1], 20, 1) != 0;
		m_avx512ifma = READBITSFROM(cpuInfo[1], 21, 1) != 0;
		m_avx512pf = READBITSFROM(cpuInfo[1], 26, 1) != 0;
		m_avx512er = READBITSFROM(cpuInfo[1], 27, 1) != 0;
		m_avx512cd = READBITSFROM(cpuInfo[1], 28, 1) != 0;
		m_sha = READBITSFROM(cpuInfo[1], 29, 1) != 0;
		m_avx512bw = READBITSFROM(cpuInfo[1], 30, 1) != 0;
		m_avx512vl = READBITSFROM(cpuInfo[1], 31, 1) != 0;

		m_prefetch = READBITSFROM(cpuInfo[2], 0, 1) != 0;
		m_avx512vbmi = READBITSFROM(cpuInfo[2], 1, 1) != 0;
		m_pku = READBITSFROM(cpuInfo[2], 3, 1) != 0;
		m_pkuos = READBITSFROM(cpuInfo[2], 4, 1) != 0;

		m_avx5124vnniw = READBITSFROM(cpuInfo[3], 2, 1) != 0;
		m_avx5124fmaps = READBITSFROM(cpuInfo[3], 3, 1) != 0;
	}

	if (nExIds >= 0x80000001)
	{
		X86_CPUID(0x80000001, cpuInfo);

		m_abm = READBITSFROM(cpuInfo[2], 5, 1) != 0;
		m_sse4a = READBITSFROM(cpuInfo[2], 6, 1) != 0;
		m_xop = READBITSFROM(cpuInfo[2], 11, 1) != 0;
		m_fma4 = READBITSFROM(cpuInfo[2], 16, 1) != 0;
		m_x64  = READBITSFROM(cpuInfo[3], 29, 1) != 0;
	}

	// topology
	m_virtCores = MaxCoresPerPackage();
	m_physCores = m_hyperThread == true && m_virtCores > 1 ? m_virtCores / 2 : m_virtCores;
	m_logicalPerCore = MaxLogicalPerCore();
	GetFrequency();
	GetSerialNumber();
	
	// TODO: AMD
	// cache info
	if ((nExIds & 0xFF) > 5)
	{
		X86_CPUID(0x80000006, cpuInfo);

		m_l1CacheSize = static_cast<size_t>(READBITSFROM(cpuInfo[2], 0, 8));
		m_l1CacheLineSize = static_cast<size_t>(READBITSFROM(cpuInfo[2], 0, 11)); // ?
		m_l2Associative = static_cast<CacheAssociations>(READBITSFROM(cpuInfo[2], 12, 4));
		m_l2CacheSize = static_cast<size_t>(READBITSFROM(cpuInfo[2], 16, 16));
	}

	// TODO:
	//http://www.cyberciti.biz/faq/linux-cpuid-command-read-cpuid-instruction-on-linux-for-cpu/
	/*L3 cache information(0x80000006 / edx) :
	line size(bytes) = 0x0 (0)
	lines per tag = 0x0 (0)
	associativity = L2 off(0)
	size(in 512Kb units) = 0x0 (0)*/
}

void CpuDetect::GetFrequency()
{
	uint cpuInfo[4];
	X86_CPUID(0, cpuInfo);

	if (cpuInfo[0] >= 0x16)
	{
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

size_t CpuDetect::MaxCoresPerPackage()
{
	size_t maxCores = 1;
	uint cpuInfo[4];

	switch (Vendor())
	{
	case CpuVendors::INTEL:
		X86_CPUID(4, cpuInfo);
		maxCores = static_cast<size_t>(READBITSFROM(cpuInfo[0], 26, 8) + 1);
		break;
	case CpuVendors::AMD:
		X86_CPUID(0x80000008, cpuInfo);
		maxCores = static_cast<size_t>(READBITSFROM(cpuInfo[2], 0, 8) + 1);
		//maxCores = std::thread::hardware_concurrency();
		break;
	default:
		break;
	}

	return maxCores;
}

size_t CpuDetect::MaxLogicalPerCore()
{
	if (!m_hyperThread)
		return 1;
	if (Vendor() == CpuVendors::AMD && m_amdCmpLegacy)
		return 1;

	uint cpuInfo[4];
	X86_CPUID(1, cpuInfo);

	size_t logical = static_cast<size_t>(READBITSFROM(cpuInfo[0], 16, 8));
	size_t cores = MaxCoresPerPackage();

	if (logical % cores == 0)
		return logical / cores;

	return 1;
}

const CpuDetect::CpuVendors CpuDetect::Vendor()
{
	if (m_cpuVendor.size() > 0)
	{
		std::string data = m_cpuVendor;
		std::transform(data.begin(), data.end(), data.begin(), ::tolower);
		if (data.find("intel", 0) != std::string::npos)
			return CpuVendors::INTEL;
		else if (data.find("amd", 0) != std::string::npos)
			return CpuVendors::AMD;
	}
	return CpuVendors::UNKNOWN;
}

NAMESPACE_COMMONEND