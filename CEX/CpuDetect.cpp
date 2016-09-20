#include "CpuDetect.h"

NAMESPACE_COMMON

//~~~ Public Methods~~~//

void CpuDetect::Detect()
{
	int info[4];
	cpuid(info, 0);
	int nIds = info[0];

	// cpu vendor name
	char vendId[0x20];
	memset(vendId, 0, sizeof(vendId));
	*((int*)vendId) = info[1];
	*((int*)(vendId + 4)) = info[3];
	*((int*)(vendId + 8)) = info[2];
	CpuVendor = std::string(vendId);

	cpuid(info, 0x80000000);
	unsigned nExIds = info[0];

	//  detect Features
	if (nIds >= 0x00000001)
	{
		cpuid(info, 0x00000001);
		HW_MMX = (info[3] & ((int)1 << 23)) != 0;
		HW_SSE = (info[3] & ((int)1 << 25)) != 0;
		HW_SSE2 = (info[3] & ((int)1 << 26)) != 0;
		HW_HYPER = (info[3] & ((int)1 << 28)) != 0;
		HW_SSE3 = (info[2] & ((int)1 << 0)) != 0;
		HW_SSSE3 = (info[2] & ((int)1 << 9)) != 0;
		HW_SSE41 = (info[2] & ((int)1 << 19)) != 0;
		HW_SSE42 = (info[2] & ((int)1 << 20)) != 0;
		HW_AES = (info[2] & ((int)1 << 25)) != 0;
		HW_FMA3 = (info[2] & ((int)1 << 12)) != 0;
		HW_RDRAND = (info[2] & ((int)1 << 30)) != 0;


#if defined(_MSC_VER) && _MSC_FULL_VER >= 160040219
		HW_AVX = HasAvxSupport();
#else
		HW_AVX = (info[2] & ((int)1 << 28)) != 0;
#endif

		HW_AMD_CMP_LEGACY = (info[1] & ((int)1 << 1)) != 0;
		HW_AMD_MP = (info[0] & ((int)1 << 19)) != 0;
		HW_AMD_MMX_EXT = (info[0] & ((int)1 << 22)) != 0;
		HW_AMD_3DNOW_PRO = (info[0] & ((int)1 << 30)) != 0;
		HW_AMD_3DNOW = (info[0] & ((int)1 << 31)) != 0;
	}

	// extended features
	if (nIds >= 0x00000007)
	{
		cpuid(info, 0x00000007);
#if defined(_MSC_VER) && _MSC_FULL_VER >= 160040219
		HW_AVX2 = HasAvx2Support();
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

	// topology
	HW_VIRTUALCORES = MaxCoresPerPackage();
	HW_PHYSICALCORES = HW_HYPER == true && HW_VIRTUALCORES > 1 ? HW_VIRTUALCORES / 2 : HW_VIRTUALCORES;
	HW_LOGICALPERCORE = MaxLogicalPerCore();

	// cache info
	if ((nExIds & 0xFF) > 5)
	{
		cpuid(info, 0x80000006);
		L1CacheSize = READBITSFROM(info[2], 0, 8);
		L1CacheTotal = HW_PHYSICALCORES * L1CacheSize;
		L2CacheSize = READBITSFROM(info[2], 16, 16);
		L2Associative = (CacheAssociations)READBITSFROM(info[2], 12, 4);
	}
}


//~~~ Private Methods~~~//

#if defined(_MSC_VER) && _MSC_FULL_VER >= 160040219
	bool CpuDetect::HasAvxSupport()
	{
		bool support = false;
		int cpuInfo[4];
		__cpuid(cpuInfo, 1);

		bool osUsesXSave = cpuInfo[2] & (1 << 27) || false;
		bool cpuAVXSuport = cpuInfo[2] & (1 << 28) || false;

		if (osUsesXSave && cpuAVXSuport)
		{
			// Check if the OS will save the YMM registers
			unsigned long long xcrFeatureMask = _xgetbv(_XCR_XFEATURE_ENABLED_MASK);
			support = (xcrFeatureMask & 0x6) || false;
		}

		return support;
	}

	bool CpuDetect::HasAvx2Support()
	{
		bool support = false;
		int cpuInfo[4];
		__cpuid(cpuInfo, 1);

		bool osUsesXSAVE_XRSTORE = cpuInfo[2] & (1 << 27) || false;
		bool cpuAVXSuport = cpuInfo[2] & (1 << 28) || false;

		if (osUsesXSAVE_XRSTORE && cpuAVXSuport)
		{
			// Check if the OS will save the YMM registers
			unsigned long long xcrFeatureMask = _xgetbv(_XCR_XFEATURE_ENABLED_MASK);
			support = (xcrFeatureMask & 0xe6) || false;
		}

		return support;
	}
#endif

void CpuDetect::Initialize()
{
	L1CacheSize = 0;
	L1CacheTotal = 0;
	L2CacheSize = 0;
	CpuVendor = "";
	L2Associative = CacheAssociations::Disabled;

	HW_MMX = false;
	HW_x64 = false;
	HW_ABM = false;
	HW_RDRAND = false;
	HW_BMI1 = false;
	HW_BMI2 = false;
	HW_ADX = false;
	HW_PREFETCHWT1 = false;
	HW_SSE = false;
	HW_SSE2 = false;
	HW_HYPER = false;
	HW_SSE3 = false;
	HW_SSSE3 = false;
	HW_SSE41 = false;
	HW_SSE42 = false;
	HW_SSE4A = false;
	HW_AES = false;
	HW_SHA = false;
	HW_AVX = false;
	HW_XOP = false;
	HW_FMA3 = false;
	HW_FMA4 = false;
	HW_AVX2 = false;
	HW_AVX512F = false;
	HW_AVX512CD = false;
	HW_AVX512PF = false;
	HW_AVX512ER = false;
	HW_AVX512VL = false;
	HW_AVX512BW = false;
	HW_AVX512DQ = false;
	HW_AVX512IFMA = false;
	HW_AVX512VBMI = false;
	HW_AMD_CMP_LEGACY = false;
	HW_AMD_MP = false;
	HW_AMD_MMX_EXT = false;
	HW_AMD_3DNOW_PRO = false;
	HW_AMD_3DNOW = false;
	HW_VIRTUALCORES = 0;
	HW_PHYSICALCORES = 0;
	HW_LOGICALPERCORE = 0;
}

size_t CpuDetect::MaxCoresPerPackage()
{
	size_t maxCores = 1;

	int info[4];
	switch (Vendor())
	{
	case CpuVendors::INTEL:
		cpuid(info, 4);
		maxCores = READBITSFROM(info[0], 26, 8) + 1;
		break;
	case CpuVendors::AMD:
		cpuid(info, 0x80000008);
		maxCores = READBITSFROM(info[0], 0, 8) + 1;
		break;
	default:
		break;
	}

	return maxCores;
}

size_t CpuDetect::MaxLogicalPerCore()
{
	if (!HW_HYPER)
		return 1;
	if (Vendor() == CpuVendors::AMD && HW_AMD_CMP_LEGACY)
		return 1;

	int info[4];
	cpuid(info, 1);
	size_t logical = READBITSFROM(info[0], 16, 8);
	size_t cores = MaxCoresPerPackage();

	if (logical % cores == 0)
		return logical / cores;

	return 1;
}

NAMESPACE_COMMONEND