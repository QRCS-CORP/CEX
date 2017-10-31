#include "ParallelOptions.h"
#include "CpuDetect.h"
#include "CryptoProcessingException.h"

NAMESPACE_COMMON

//~~~Constructor~~~//

ParallelOptions::ParallelOptions(size_t BlockSize, bool SimdMultiply, size_t ReservedCache, bool SplitChannel, size_t ParallelMaxDegree)
	:
	m_autoInit(true),
	m_blockSize(BlockSize != 0 && BlockSize % 2 == 0 ? BlockSize :
		throw Exception::CryptoProcessingException("ParallelOptions:Ctor", "The BlockSize must be a positive even number!")),
	m_hasPrefetch(false),
	m_hasSHA2(false),
	m_hasSimd128(false),
	m_hasSimd256(false),
	m_hasSimd512(false),
	m_isParallel(false),
	m_l1DataCacheReserved(ReservedCache),
	m_l1DataCacheTotal(0),
	m_overrideMaxDegree(false),
	m_parallelBlockSize(0),
	m_parallelMaxDegree(ParallelMaxDegree),
	m_parallelMinimumSize(0),
	m_physicalCores(0),
	m_processorCount(0),
	m_simdDetected(SimdProfiles::None),
	m_simdMultiply(SimdMultiply),
	m_splitChannel(SplitChannel),
	m_virtualCores(0),
	m_wideBlock(false)
{
	Detect();
	Calculate();
	StoreDefaults();
}

ParallelOptions::ParallelOptions(size_t BlockSize, bool Parallel, size_t ParallelBlockSize, size_t ParallelMaxDegree, bool SimdMultiply, size_t ReservedCache, bool SplitChannel)
	:
	m_autoInit(false),
	m_blockSize(BlockSize != 0 && BlockSize % 2 == 0 ? BlockSize :
		throw Exception::CryptoProcessingException("ParallelOptions:Ctor", "The BlockSize must be a positive even number!")),
	m_defaultParams(),
	m_hasPrefetch(false),
	m_hasSHA2(false),
	m_hasSimd128(false),
	m_hasSimd256(false),
	m_hasSimd512(false),
	m_isParallel(Parallel),
	m_l1DataCacheReserved(ReservedCache),
	m_l1DataCacheTotal(0),
	m_overrideMaxDegree(false),
	m_parallelBlockSize(ParallelBlockSize),
	m_parallelMaxDegree(ParallelMaxDegree),
	m_parallelMinimumSize(0),
	m_physicalCores(0),
	m_processorCount(0),
	m_simdDetected(SimdProfiles::None),
	m_simdMultiply(SimdMultiply),
	m_splitChannel(SplitChannel),
	m_virtualCores(0),
	m_wideBlock(false)
{
	Detect();
	Calculate();
	StoreDefaults();
}

ParallelOptions::~ParallelOptions()
{
	Reset();
}

//~~~Accessors~~~//

const bool ParallelOptions::IsDefault()
{
	return (m_defaultParams.IsParallel == m_isParallel &&
		m_defaultParams.MaxDegree == m_parallelMaxDegree &&
		m_defaultParams.ParallelBlockSize == m_parallelBlockSize);
}

const size_t ParallelOptions::BlockSize() 
{
	return m_blockSize;
}

const bool ParallelOptions::HasPrefetch() 
{ 
	return m_hasPrefetch; 
}

const bool ParallelOptions::HasSHA2()
{ 
	return m_hasSHA2; 
}

const bool ParallelOptions::HasSimd128() 
{ 
	return m_hasSimd128;
}

const bool ParallelOptions::HasSimd256() 
{ 
	return m_hasSimd256; 
}

const size_t ParallelOptions::L1DataCacheTotalSize()
{ 
	return m_l1DataCacheTotal;
}

const size_t ParallelOptions::L1DataCacheReserved() 
{
	return m_l1DataCacheReserved;
}

bool &ParallelOptions::IsParallel()
{
	return m_isParallel;
}

size_t &ParallelOptions::ParallelBlockSize() 
{
	return m_parallelBlockSize;
}

const size_t ParallelOptions::ParallelMaximumSize() 
{ 
	return MAX_PRLALLOC; 
}

const size_t ParallelOptions::ParallelMinimumSize() 
{ 
	return m_parallelMinimumSize; 
}

const size_t ParallelOptions::ParallelMaxDegree() 
{ 
	return m_parallelMaxDegree; 
}

const size_t ParallelOptions::PhysicalCores() 
{ 
	return m_physicalCores; 
}

const size_t ParallelOptions::ProcessorCount()
{
	return m_virtualCores != 0 ? m_virtualCores : m_physicalCores;
}

const SimdProfiles ParallelOptions::SimdProfile() 
{ 
	return m_simdDetected;
}

const size_t ParallelOptions::VirtualCores() 
{ 
	return m_virtualCores; 
}

bool &ParallelOptions::WideBlock() 
{
	return m_wideBlock; 
}

//~~~Public Functions~~~//

void ParallelOptions::Calculate()
{
	if (m_parallelMaxDegree > m_processorCount && !m_overrideMaxDegree || m_parallelMaxDegree == 0)
	{
		m_parallelMaxDegree = m_processorCount;
	}

	m_parallelMinimumSize = m_parallelMaxDegree * m_blockSize;

	if (m_simdMultiply)
	{
#if defined(__AVX512__)
		m_parallelMinimumSize *= 16;
#elif defined(__AVX2__)
		m_parallelMinimumSize *= 8;
#elif defined(__AVX__)
		m_parallelMinimumSize *= 4;
#endif
	}

	// first init is auto
	if (m_autoInit)
	{
		m_parallelBlockSize = (m_l1DataCacheTotal - m_l1DataCacheReserved);

		// split channels in/out by halving available cache
		if (m_splitChannel)
		{
			m_parallelBlockSize /= 2;
		}

		// default to capability
		m_isParallel = (m_processorCount > 1);
		// on init only
		m_autoInit = false;
	}
	else if (m_isParallel)
	{
		// user defined
		if (m_parallelBlockSize == 0)
		{
			m_parallelBlockSize = DEF_DATACACHE * m_parallelMaxDegree;
		}

		if (m_parallelBlockSize < m_parallelMinimumSize)
		{
			m_parallelBlockSize = m_parallelMinimumSize;
		}
	}

	// round it off
	if (m_parallelBlockSize != 0)
	{
		m_parallelBlockSize = m_parallelBlockSize - (m_parallelBlockSize % m_parallelMinimumSize);
	}
}

void ParallelOptions::Calculate(bool Parallel, size_t ParallelBlockSize, size_t MaxDegree)
{
	m_isParallel = (Parallel == false) ? false : (m_processorCount > 1);

	if (ParallelBlockSize != 0)
	{
		m_parallelBlockSize = ParallelBlockSize;
	}

	if (MaxDegree != 0)
	{
		m_parallelMaxDegree = MaxDegree;
	}

	Calculate();
}

void ParallelOptions::Reset()
{
	m_autoInit = false;
	m_blockSize = 0;
	m_defaultParams.IsParallel = false;
	m_defaultParams.MaxDegree = 0;
	m_defaultParams.ParallelBlockSize = 0;
	m_hasPrefetch = false;
	m_hasSHA2 = false;
	m_hasSimd128 = false;
	m_hasSimd256 = false;
	m_hasSimd512 = false;
	m_isParallel = false;
	m_l1DataCacheReserved = 0;
	m_l1DataCacheTotal = 0;
	m_overrideMaxDegree = false;
	m_parallelBlockSize = 0;
	m_parallelMaxDegree = 0;
	m_parallelMinimumSize = 0;
	m_physicalCores = 0;
	m_processorCount = 0;
	m_simdDetected = SimdProfiles::None;
	m_simdMultiply = false;
	m_splitChannel = false;
	m_virtualCores = 0;
	m_wideBlock = false;
}

void ParallelOptions::SetMaxDegree(size_t MaxDegree)
{
	if (MaxDegree == 0)
	{
		throw Exception::CryptoProcessingException("ParallelOptions:Ctor", "The MaxDegree must be a positive even number!");
	}

	m_overrideMaxDegree = true;
	m_parallelMaxDegree = MaxDegree;
	Calculate();
}

//~~~Private Functions~~~//

void ParallelOptions::Detect()
{
	Common::CpuDetect detect;

	m_hasPrefetch = detect.PREFETCH();
	m_hasSHA2 = detect.SHA();
	m_hasSimd128 = detect.AVX();
	m_hasSimd256 = detect.AVX2();
	m_hasSimd512 = detect.AVX512F();
	m_physicalCores = detect.PhysicalCores();
	m_simdDetected = (m_hasSimd256) ? SimdProfiles::Simd256 : (m_hasSimd128) ? SimdProfiles::Simd128 : SimdProfiles::None;
	m_virtualCores = detect.VirtualCores();
	m_processorCount = (m_virtualCores > m_physicalCores) ? m_virtualCores : m_physicalCores;

	if (m_processorCount > 1 && m_processorCount % 2 != 0)
	{
		m_processorCount--;
	}

	if (m_parallelMaxDegree > m_processorCount)
	{
		m_parallelMaxDegree = m_processorCount;
	}

	m_isParallel = (m_processorCount > 1);
	m_l1DataCacheTotal = detect.L1DataCacheTotal();
}

void ParallelOptions::StoreDefaults()
{
	m_defaultParams.IsParallel = m_isParallel;
	m_defaultParams.MaxDegree = m_parallelMaxDegree;
	m_defaultParams.ParallelBlockSize = m_parallelBlockSize;
}

NAMESPACE_COMMONEND