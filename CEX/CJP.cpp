#include "CJP.h"
#include "CpuDetect.h"
#include "IntUtils.h"
#include "SysUtils.h"

NAMESPACE_PROVIDER

const std::string CJP::CLASS_NAME("CJP");

//~~~Constructor~~~//

CJP::CJP()
	:
	m_enableAccess(true),
	m_enableDebias(true),
	m_hasTsc(Utility::SysUtils::HasRdtsc()),
	m_isAvailable(false),
	m_lastDelta(0),
	m_lastDelta2(0),
	m_memAccessLoops(MEMORY_ACCESSLOOPS),
	m_memBlocks(MEMORY_BLOCKS),
	m_memBlockSize(MEMORY_BLOCKSIZE),
	m_memPosition(0),
	m_memTotalSize(MEMORY_SIZE),
	m_memState(0),
	m_overSampleRate(OVRSMP_RATE_MIN),
	m_prevTime(0),
	m_rndState(0),
	m_secureCache(true),
	m_stirPool(true),
	m_stuckTest(1)
{
	m_isAvailable = TimerCheck();

	if (m_isAvailable)
	{
		Detect();
		Prime();
	}
}

CJP::~CJP()
{
	Utility::IntUtils::ClearVector(m_memState);
	m_enableAccess = false;
	m_enableDebias = false;
	m_hasTsc = false;
	m_isAvailable = false;
	m_lastDelta = 0;
	m_lastDelta2 = 0;
	m_memAccessLoops = 0;
	m_memBlocks = 0;
	m_memBlockSize = 0;
	m_memPosition = 0;
	m_memTotalSize = 0;
	m_overSampleRate = 0;
	m_prevTime = 0;
	m_rndState = 0;
	m_secureCache = false;
	m_stirPool = false;
	m_stuckTest = 0;
}

//~~~Accessors~~~//

bool &CJP::EnableAccess()
{ 
	return m_enableAccess;
}

bool &CJP::EnableDebias() 
{ 
	return m_enableDebias; 
}

const Enumeration::Providers CJP::Enumeral()
{
	return Enumeration::Providers::CJP;
}

const bool CJP::IsAvailable()
{
	return m_isAvailable;
}

const std::string CJP::Name()
{ 
	return CLASS_NAME; 
}

uint &CJP::OverSampleRate() 
{
	return m_overSampleRate; 
}

bool &CJP::SecureCache()
{
	return m_secureCache;
}

//~~~Public Functions~~~//

void CJP::GetBytes(std::vector<byte> &Output)
{
	if (!m_isAvailable)
	{
		throw CryptoRandomException("CJP:GetBytes", "High resolution timer not available or too coarse for RNG!");
	}

	Generate(Output, 0, Output.size());
}

void CJP::GetBytes(std::vector<byte> &Output, size_t Offset, size_t Length)
{
	CexAssert(Offset + Length <= Output.size(), "the array is too small to fulfill this request");

	if (!m_isAvailable)
	{
		throw CryptoRandomException("CJP:GetBytes", "High resolution timer not available or too coarse for RNG!");
	}

	Generate(Output, Offset, Length);
}

std::vector<byte> CJP::GetBytes(size_t Length)
{
	if (!m_isAvailable)
	{
		throw CryptoRandomException("CJP:GetBytes", "High resolution timer not available or too coarse for RNG!");
	}

	std::vector<byte> rnd(Length);
	Generate(rnd, 0, rnd.size());

	return rnd;
}

uint CJP::Next()
{
	if (!m_isAvailable)
	{
		throw CryptoRandomException("CJP:Next", "High resolution timer not available or too coarse for RNG!");
	}

	std::vector<byte> rnd(sizeof(uint));
	Generate(rnd, 0, rnd.size());
	uint rnd32 = 0;
	Utility::MemUtils::CopyToValue(rnd, 0, rnd32, sizeof(uint));

	return rnd32;
}

void CJP::Reset()
{
	try
	{
		Prime();
	}
	catch (std::exception &ex)
	{
		throw CryptoRandomException("CJP:Reset", "Entropy collection has failed!", std::string(ex.what()));
	}
}

//~~~Private Functions~~~//

CEX_OPTIMIZE_IGNORE
void CJP::AccessMemory()
{
	// this is a noise source based on variations in memory access times
	// this function performs memory accesses which will add to the timing variations due to an unknown amount of CPU wait states that need to be
	// added when accessing memory.
	// the memory size should be larger than the L1 caches as outlined in the documentation and the associated testing.
	// the L1 cache has a very high bandwidth, albeit its access rate is usually slower than accessing CPU registers. 
	// therefore, L1 accesses only add minimal variations as the CPU has hardly to wait. 
	// starting with L2, significant variations are added because L2 typically does not belong to the CPU any more and therefore a wider range of CPU wait states is necessary for accesses.
	// L3 and real memory accesses have even a wider range of wait states. However, to reliably access either L3 or memory, the ec->m_memState memory must be quite large which is usually not desirable.

	byte tmpState;
	const uint WRPLEN = m_memBlockSize * m_memBlocks;
	const size_t ACLCNT = (m_memAccessLoops + ShuffleLoop(ACC_LOOP_BIT_MAX, ACC_LOOP_BIT_MIN));

	for (size_t i = 0; i < ACLCNT; ++i)
	{
		tmpState = m_memState[m_memPosition];
		// memory access; just add 1 to one byte, wrap at 255; memory access implies read from and write to memory location
		tmpState = (tmpState + 1) & 0xFF;
		m_memState[m_memPosition] = tmpState;
		// addition of memBlockSize - 1 to pointer with wrap around logic to ensure that every memory location is hit evenly
		m_memPosition = m_memPosition + m_memBlockSize - 1;
		m_memPosition = m_memPosition % WRPLEN;
	}
}
CEX_OPTIMIZE_RESUME

ulong CJP::DebiasBit()
{
	// Von Neuman unbias function as explained in RFC 4086 section 4.2.
	do
	{
		ulong a = MeasureJitter();
		ulong b = MeasureJitter();

		if (a == b)
		{
			continue;
		}
		else
		{
			return a;
		}
	} 
	while (1);
}

void CJP::Detect()
{
	try
	{
		Common::CpuDetect detect;

		if (detect.L1CacheTotal() != 0)
		{
			m_memBlockSize = static_cast<uint>(detect.L1CacheLineSize());
			m_memBlocks = (static_cast<uint>(detect.L1CacheTotal()) / static_cast<uint>(detect.VirtualCores()) / m_memBlockSize);
			m_memTotalSize = m_memBlocks * m_memBlockSize;
			m_memAccessLoops = (m_memTotalSize / m_memBlockSize) * 2;
		}
	}
	catch (std::exception&)
	{
		m_memBlocks = MEMORY_BLOCKS;
		m_memBlockSize = MEMORY_BLOCKSIZE;
		m_memTotalSize = MEMORY_SIZE;
		m_memAccessLoops = MEMORY_ACCESSLOOPS;
	}
}

CEX_OPTIMIZE_IGNORE
void CJP::FoldTime(ulong TimeStamp, ulong &Folded)
{
	// CPU jitter noise source; this is the noise source based on the CPU execution time jitter.
	// This function not only acts as folding operation, but this function's execution is used to measure the CPU execution time jitter. 

	const size_t FLDCNT = ShuffleLoop(FOLD_LOOP_BIT_MAX, FOLD_LOOP_BIT_MIN);
	ulong fldTmp = 0;

	for (size_t j = 0; j < FLDCNT; ++j)
	{
		fldTmp = 0;
		for (size_t i = 1; (DATA_SIZE_BITS) >= i; ++i)
		{
			ulong tmp = TimeStamp << (DATA_SIZE_BITS - i);
			tmp = tmp >> (DATA_SIZE_BITS - 1);
			fldTmp ^= tmp;
		}
	}

	Folded = fldTmp;
}
CEX_OPTIMIZE_RESUME

size_t CJP::Generate(std::vector<byte> &Output, size_t Offset, size_t Length)
{
	const size_t RNDLEN = sizeof(ulong);

	do
	{
		size_t rmdLen = (Length < RNDLEN) ? Length : RNDLEN;
		Generate64();
		Utility::MemUtils::CopyFromValue(m_rndState, Output, Offset, rmdLen);
		Length -= rmdLen;
		Offset += rmdLen;
	} 
	while (Length != 0);

	// To be on the safe side, we generate one more round of entropy which we do not give out to the caller. 
	// That round shall ensure that in case the calling application crashes, memory dumps, pages out, 
	// or due to the CPU Jitter RNG lingering in memory for a long time without being moved and an attacker cracks the application,
	// all he reads in the entropy pool is a value that is never to be used. 
	// Thus, he does NOT see the previous value that was returned to the caller for cryptographic purposes.
	// If we use secured memory, do not use this precaution as the secure memory protects the entropy pool. 
	// Moreover, note that using this call reduces the speed of the RNG by up to half
	if (m_secureCache)
	{
		Generate64();
	}

	return Length;
}

void CJP::Generate64()
{
	// priming of the m_prevTime value
	MeasureJitter();

	uint smpCtr = 0;

	while (true)
	{
		ulong jitter = 0;

		if (m_enableDebias)
		{
			jitter = DebiasBit();
		}
		else
		{
			jitter = MeasureJitter();
		}

		// Fibonacci LSFR with polynom of 64, 63, 61, 60; the shift values are the polynom values minus one due to counting bits from 0 to 63. 
		m_rndState ^= jitter;
		m_rndState ^= ((m_rndState >> 63) & 1);
		m_rndState ^= ((m_rndState >> 62) & 1);
		m_rndState ^= ((m_rndState >> 60) & 1);
		m_rndState ^= ((m_rndState >> 59) & 1);
		// the current position is always the LSB, the polynom only needs to shift data in from the left without wrap
		m_rndState = Utility::IntUtils::RotL64(m_rndState, 1);

		// enforce the StuckCheck test
		if (m_stuckTest)
		{
			m_stuckTest = 0;
			continue;
		}

		// multiply the loop value with OverSampleRate to obtain the oversampling rate requested by the caller
		if (++smpCtr >= (DATA_SIZE_BITS * m_overSampleRate))
		{
			break;
		}
	}

	if (m_stirPool)
	{
		StirPool();
	}
}

ulong CJP::GetTimeStamp()
{
	return Utility::SysUtils::TimeStamp(m_hasTsc);
}

ulong CJP::MeasureJitter()
{
	// The heart of the entropy generation process; calculate time deltas and use the CPU jitter in the time deltas.
	// The jitter is folded into one bit; this function is the "random bit generator" as it produces one random bit per invocation.
	ulong delta = 0;
	ulong folded = 0;

	// Invoke one noise source before time measurement to add variations
	if (m_enableAccess)
	{
		AccessMemory();
	}
	// Get time stamp and calculate time delta to previous invocation to measure the timing variations
	ulong time = GetTimeStamp();
	delta = time - m_prevTime;
	m_prevTime = time;
	// Now call the next noise sources which also folds the data
	FoldTime(delta, folded);
	// Check whether we have a stuck test measurement; the enforcement is performed after the stuck test value has been mixed into the entropy pool
	StuckCheck(delta);

	return folded;
}

void CJP::Prime()
{
	// this is a reset
	if (m_memState.size() != 0 && m_memTotalSize != 0)
	{
		m_rndState = 0;
		std::memset(m_memState.data(), 0, m_memTotalSize);
		m_memPosition = 0;
		m_lastDelta = 0;
		m_lastDelta2 = 0;
		m_prevTime = 0;
		m_stuckTest = 1;
	}

	m_memState.resize(m_memTotalSize, 0);

	// verify oversampling rate; minimum sampling rate is 1
	if (m_overSampleRate == 0)
	{
		m_overSampleRate = 1;
	}

	// fill the state with non-zero values
	Generate64();
}

size_t CJP::ShuffleLoop(uint LowBits, uint MinShift)
{
	// update of the loop count used for the next round of an entropy collection
	const uint SHFMSK = (1 << LowBits) - 1;
	ulong shuffle = 0;

	// store the timestamp
	ulong time = GetTimeStamp();
	// mix the current state of the random number into the shuffle calculation to balance that shuffle a bit more
	time ^= m_rndState;

	// fold the time value as much as possible to ensure that as many bits of the time stamp are included as possible
	for (size_t i = 0; (DATA_SIZE_BITS / LowBits) > i; ++i)
	{
		shuffle ^= time & SHFMSK;
		time = time >> LowBits;
	}

	// add a lower boundary value to ensure we have a minimum RNG loop count
	return (static_cast<size_t>(shuffle) + (static_cast<size_t>(1) << MinShift));
}

void CJP::StirPool()
{
	// TODO: replace unions

	// Shuffle the pool by mixing some value with a bijective function (XOR) into the pool.
	// This function generates a mixer value that depends on the bits set and the
	// location of the set bits in the random number generated by the entropy source.
	// Therefore, based on the generated random number, this mixer value can have 2**64 different values.
	// That mixer value is initialized with the first two SHA-1 constants.
	// After obtaining the mixer value, it is XORed into the random number.
	// The mixer value is not assumed to contain any entropy,
	// but due to the XOR operation, it can also not destroy any entropy present in the entropy pool.
	union c
	{
		ulong u64;
		uint u32[2];
	};

	// This constant is derived from the first two 32 bit initialization vectors of SHA-1 as defined in FIPS 180-4 section 5.3.1
	union c constant;
	// The start value of the mixer variable is derived from the third and fourth 32 bit initialization vector of SHA-1 as defined in FIPS 180-4 section 5.3.1
	union c mixer;

	// Store the SHA-1 constants in reverse order to make up the 64 bit value; this applies to a little endian system, on a big endian system, 
	// it reverses as expected. But this really does not matter as we do not rely on the specific numbers. 
	// We just pick the SHA-1 constants as they have a good mix of bit set and unset.
	constant.u32[1] = 0x67452301UL;
	constant.u32[0] = 0xEFCDAB89UL;
	mixer.u32[1] = 0x98BADCFEUL;
	mixer.u32[0] = 0x10325476UL;

	for (size_t i = 0; i < DATA_SIZE_BITS; ++i)
	{
		// get the i-th bit of the input random number and only XOR the constant into the mixer value when that bit is set
		if ((m_rndState >> i) & 1)
		{
			mixer.u64 ^= constant.u64;
		}

		mixer.u64 = Utility::IntUtils::RotL64(mixer.u64, 1);
	}

	m_rndState ^= mixer.u64;
}

void CJP::StuckCheck(ulong CurrentDelta)
{
	// Checks the 1st derivation of the jitter measurement (time delta), 
	// 2nd derivation of the jitter measurement (delta of time deltas),
	// and the 3rd derivation of the jitter measurement (delta of delta of time deltas).
	// A 0 jitter measurement not stuck test (good bit), 1 jitter measurement stuck test (reject bit).
	const ulong DELTA2 = m_lastDelta - CurrentDelta;
	const ulong DELTA3 = DELTA2 - m_lastDelta2;

	m_lastDelta = CurrentDelta;
	m_lastDelta2 = DELTA2;

	if (CurrentDelta == 0 || DELTA2 == 0 || DELTA3 == 0)
	{
		m_stuckTest = 1;
	}
}

bool CJP::TimerCheck()
{
	ulong sumDelta = 0;
	ulong oldDelta = 0;
	size_t backCtr = 0;
	size_t varCtr = 0;
	size_t modCtr = 0;
	bool result = false;

	for (size_t i = 0; (LOOP_TEST_COUNT + CLEARCACHE) > i; i++)
	{
		ulong delta = 0;
		ulong folded = 0;

		ulong time = Utility::SysUtils::TimeStamp(m_hasTsc);
		FoldTime(time, folded);
		ulong time2 = Utility::SysUtils::TimeStamp(m_hasTsc);

		// test whether timer works
		if (time == 0 || time2 == 0)
		{
			break;
		}

		delta = time2 - time;
		// test whether timer is fine grained enough to provide delta even when called shortly after each other; 
		// this implies that we also have a high resolution timer
		if (delta == 0)
		{
			break;
		}

		// up to here we did not modify any variable that will be evaluated later, but we already performed some work;
		// thus we already have had an impact on the caches, branch prediction, etc. with the goal to clear it to get the worst case measurements
		if (i < CLEARCACHE)
		{
			continue;
		}

		// test whether we have an increasing timer
		if (time2 <= time)
		{
			backCtr++;
		}
		if (delta % 100 == 0)
		{
			modCtr++;
		}

		// ensure that we have a varying delta timer which is necessary for the calculation of entropy;
		// perform this check only after the first loop is executed as we need to prime the oldDelta value
		if (i != 0)
		{
			if (delta != oldDelta)
			{
				varCtr++;
			}
			if (delta > oldDelta)
			{
				sumDelta += (delta - oldDelta);
			}
			else
			{
				sumDelta += (oldDelta - delta);
			}
		}

		oldDelta = delta;
	}

	// we allow up to three times the time running backwards. CLOCK_REALTIME is affected by adjtime and NTP operations. 
	// Thus, if such an operation just happens to interfere with our test, it should not fail. The value of 3 should cover the NTP case being performed during our test run.
	if (3 >= backCtr && sumDelta > 1 && ((LOOP_TEST_COUNT / 10) * 9) >= modCtr)
	{
		result = true;
	}

	return result;
}

NAMESPACE_PROVIDEREND
