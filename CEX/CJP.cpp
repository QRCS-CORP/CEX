#include "CJP.h"
#include "CpuDetect.h"
#include "IntegerTools.h"
#include "SystemTools.h"

NAMESPACE_PROVIDER

using Tools::IntegerTools;
using Tools::MemoryTools;
using Enumeration::ProviderConvert;
using Tools::SystemTools;

const bool CJP::OS_HAS_TSC = SystemTools::HasRdtsc();

class CJP::JitterState
{
public:

	std::vector<uint8_t> MemoryState;
	uint64_t LastDelta;
	uint64_t LastDelta2;
	uint64_t PreviousTime;
	uint64_t RandomState;
	size_t MemoryBlocks;
	size_t MemoryBlockSize;
	size_t MemoryIterations;
	size_t MemoryPosition;
	size_t MemoryTotalSize;
	size_t OverSampleRate;
	bool SecureCache;

	JitterState()
		:
		MemoryState(0),
		LastDelta(0),
		LastDelta2(0),
		PreviousTime(0),
		RandomState(0),
		MemoryBlocks(0),
		MemoryBlockSize(0),
		MemoryIterations(0),
		MemoryPosition(0),
		MemoryTotalSize(0),
		OverSampleRate(0),
		SecureCache(false)
	{
	}

	~JitterState()
	{
		Reset();
	}

	void Reset()
	{
		LastDelta = 0;
		LastDelta2 = 0;
		MemoryBlocks = 0;
		MemoryBlockSize = 0;
		MemoryIterations = 0;
		MemoryPosition = 0;
		MemoryTotalSize = 0;
		OverSampleRate = 0;
		PreviousTime = 0;
		RandomState = 0;
		SecureCache;

		if (MemoryState.size() != 0)
		{
			IntegerTools::Clear(MemoryState);
		}
	}
};

//~~~Constructor~~~//

CJP::CJP()
	:
#if defined(CEX_FIPS140_ENABLED)
	m_pvdSelfTest(new ProviderSelfTest),
#endif
	ProviderBase(OS_HAS_TSC, Providers::CJP, ProviderConvert::ToName(Providers::CJP)),
	m_pvdState(Prime())
{
}

CJP::~CJP()
{
	if (m_pvdSelfTest != nullptr)
	{
		m_pvdSelfTest.reset(nullptr);
	}

	if (m_pvdState != nullptr)
	{
		m_pvdState->Reset();
		m_pvdState.reset(nullptr);
	}
}

//~~~Accessors~~~//

size_t &CJP::OverSampleRate() 
{
	return m_pvdState->OverSampleRate;
}

bool &CJP::SecureCache()
{
	return m_pvdState->SecureCache;
}

//~~~Public Functions~~~//

void CJP::Generate(std::vector<uint8_t> &Output)
{
	if (IsAvailable() == false)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The random provider is not available!"), ErrorCodes::NotFound);
	}
	if (FipsTest() == false)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The random provider has failed the self test!"), ErrorCodes::InvalidState);
	}

	Generate(m_pvdState, Output.data(), Output.size());
}

void CJP::Generate(std::vector<uint8_t> &Output, size_t Offset, size_t Length)
{
	if (IsAvailable() == false)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The random provider is not available!"), ErrorCodes::NotFound);
	}
	if ((Output.size() - Offset) < Length)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The output buffer is too small!"), ErrorCodes::InvalidSize);
	}
	if (FipsTest() == false)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The random provider has failed the self test!"), ErrorCodes::InvalidState);
	}

	Generate(m_pvdState, &Output[Offset], Length);
}

void CJP::Generate(SecureVector<uint8_t> &Output)
{
	if (IsAvailable() == false)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The random provider is not available!"), ErrorCodes::NotFound);
	}
	if (FipsTest() == false)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The random provider has failed the self test!"), ErrorCodes::InvalidState);
	}

	Generate(m_pvdState, Output.data(), Output.size());
}

void CJP::Generate(SecureVector<uint8_t> &Output, size_t Offset, size_t Length)
{
	if (IsAvailable() == false)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The random provider is not available!"), ErrorCodes::NotFound);
	}
	if ((Output.size() - Offset) < Length)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The output buffer is too small!"), ErrorCodes::InvalidSize);
	}
	if (FipsTest() == false)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The random provider has failed the self test!"), ErrorCodes::InvalidState);
	}

	Generate(m_pvdState, &Output[Offset], Length);
}

void CJP::Reset()
{
	try
	{
		m_pvdState = Prime();
	}
	catch (std::exception &ex)
	{
		throw CryptoRandomException(Name(), std::string("Reset"), std::string(ex.what()), ErrorCodes::UnKnown);
	}
}

bool CJP::FipsTest()
{
	bool fail;

	fail = false;

#if defined(CEX_FIPS140_ENABLED)

	SecureVector<uint8_t> smp(m_pvdSelfTest->SELFTEST_LENGTH);

	Generate(m_pvdState, smp.data(), smp.size());

	if (!m_pvdSelfTest->SelfTest(smp))
	{
		fail = true;
	}

#endif

	return (fail == false);
}

CEX_OPTIMIZE_IGNORE
void CJP::FoldTime(std::unique_ptr<JitterState> &State, uint64_t TimeStamp)
{
	// CPU jitter noise source; this is the noise source based on the CPU execution time jitter
	// this function not only acts as folding operation, but this function's execution is used to measure the CPU execution time jitter
	const size_t FLDCNT = ShuffleLoop(State, FOLD_LOOP_BIT_MAX, FOLD_LOOP_BIT_MIN);
	uint64_t fldt;
	uint64_t tmpt;
	size_t i;
	size_t j;

	fldt = 0;

	for (i = 0; i < FLDCNT; ++i)
	{
		fldt = State->RandomState;

		for (j = 1; DATA_SIZE_BITS >= j; ++j)
		{
			tmpt = TimeStamp << (DATA_SIZE_BITS - j);
			tmpt = tmpt >> (DATA_SIZE_BITS - 1);
			tmpt ^= ((fldt >> 63) & 1);
			tmpt ^= ((fldt >> 60) & 1);
			tmpt ^= ((fldt >> 55) & 1);
			tmpt ^= ((fldt >> 30) & 1);
			tmpt ^= ((fldt >> 27) & 1);
			tmpt ^= ((fldt >> 22) & 1);
			fldt <<= 1;
			fldt ^= tmpt;
		}
	}

	State->RandomState = fldt;
}
CEX_OPTIMIZE_RESUME

void CJP::Generate(std::unique_ptr<JitterState> &State)
{
	size_t k;

	// priming of the PreviousTime value
	MeasureJitter(State);
	k = 0;

	while (true) 
	{
		// if a stuck measurement is received, repeat measurement
		if (MeasureJitter(State) != 0)
		{
			continue;
		}

		++k;
		// we multiply the loop value with ->osr to obtain the oversampling rate requested by the caller
		if (k >= (DATA_SIZE_BITS * State->OverSampleRate))
		{
			break;
		}
	}
}

void CJP::Generate(std::unique_ptr<JitterState> &State, uint8_t* Output, size_t Length)
{
	if (!TimerCheck(State))
	{
		throw CryptoRandomException(std::string("CJP"), std::string("Generate"), std::string("The timer evaluation check has failed!"), ErrorCodes::NotSupported);
	}

	size_t i;
	size_t poff;

	if (Length != 0)
	{
		poff = 0;

		do
		{
			Generate(State);

			const size_t RMDLEN = (Length > sizeof(uint64_t)) ? sizeof(uint64_t) : Length;

			for (i = 0; i < RMDLEN; ++i)
			{
				Output[poff + i] = static_cast<uint8_t>(State->RandomState >> (i * 8));
			}

			Length -= RMDLEN;
			poff += RMDLEN;
		} 
		while (Length != 0);

		if (State->SecureCache)
		{
			Generate(State);
		}
	}
}

uint64_t CJP::GetTime()
{
	return SystemTools::TimeStamp(OS_HAS_TSC);
}

bool CJP::MeasureJitter(std::unique_ptr<JitterState> &State)
{
	uint64_t delta;

	// the heart of the entropy generation process; calculate time deltas and use the CPU jitter in the time deltas
	// the jitter is folded into one bit; this function is the "random bit generator" as it produces one random bit per invocation
	delta = 0;

	// invoke one noise source before time measurement to add variations
	MemoryJitter(State);

	// get time stamp and calculate time delta to previous invocation to measure the timing variations
	uint64_t time = GetTime();
	delta = time - State->PreviousTime;
	State->PreviousTime = time;
	// call the next noise sources which also folds the data
	FoldTime(State, delta);

	// check whether we have a stuck test measurement; the enforcement is performed after the stuck test value has been mixed into the entropy pool
	return StuckCheck(State, delta);
}

CEX_OPTIMIZE_IGNORE
void CJP::MemoryJitter(std::unique_ptr<JitterState> &State)
{
	const size_t WRPLEN = State->MemoryBlockSize * State->MemoryBlocks;
	const size_t ACLCNT = State->MemoryIterations + ShuffleLoop(State, ACC_LOOP_BIT_MAX, ACC_LOOP_BIT_MIN);
	size_t i;
	uint8_t tmps;

	for (i = 0; i < ACLCNT; ++i)
	{
		tmps = State->MemoryState[State->MemoryPosition];
		// memory access; just add 1 to one uint8_t, wrap at 255; memory access implies read from and write to memory location
		tmps = (tmps + 1) & 0xFF;
		State->MemoryState[State->MemoryPosition] = tmps;
		// addition of memBlockSize - 1 to pointer with wrap around logic to ensure that every memory location is hit evenly
		State->MemoryPosition = State->MemoryPosition + State->MemoryBlockSize - 1;
		State->MemoryPosition = State->MemoryPosition % WRPLEN;
	}
}
CEX_OPTIMIZE_RESUME

std::unique_ptr<CJP::JitterState> CJP::Prime()
{
	std::unique_ptr<JitterState> state(new JitterState());

	state->LastDelta = 0;
	state->LastDelta2 = 0;
	state->MemoryPosition = 0;
	state->OverSampleRate = OVRSMP_RATE_MIN;
	state->PreviousTime = 0;
	state->RandomState = 0;
	state->SecureCache = true;

	CpuDetect dtc;

	if (dtc.L1CacheTotal() != 0)
	{
		state->MemoryBlockSize = static_cast<uint32_t>(dtc.L1CacheLineSize());
		state->MemoryBlocks = (dtc.L1CacheTotal() / dtc.VirtualCores() / state->MemoryBlockSize);
		state->MemoryTotalSize = state->MemoryBlocks * state->MemoryBlockSize;
		state->MemoryIterations = (state->MemoryTotalSize / state->MemoryBlockSize) * 2;
	}
	else
	{
		state->MemoryBlocks = MEMORY_BLOCKS;
		state->MemoryBlockSize = MEMORY_BLOCKSIZE;
		state->MemoryTotalSize = MEMORY_SIZE;
		state->MemoryIterations = MEMORY_ACCESSLOOPS;
	}

	// this is a reset
	if (state->MemoryState.size() != 0 && state->MemoryTotalSize != 0)
	{

		std::memset(state->MemoryState.data(), 0, state->MemoryTotalSize);


	}
	else
	{
		state->MemoryState.resize(state->MemoryTotalSize, 0);
	}

	// fill the state with non-zero values
	Generate(state);

	return state;
}

size_t CJP::ShuffleLoop(std::unique_ptr<JitterState> &State, size_t LowBits, size_t MinShift)
{
	// update of the loop count used for the next round of an entropy collection
	const uint32_t SHFMSK = (1 << LowBits) - 1;
	uint64_t shuffle;
	uint64_t time;

	// store the timestamp
	time = GetTime();
	// mix the current state of the random number into the shuffle calculation to balance that shuffle a bit more
	time ^= State->RandomState;
	shuffle = 0;

	// fold the time value as much as possible to ensure that as many bits of the time stamp are included as possible
	for (size_t i = 0; (DATA_SIZE_BITS / LowBits) > i; ++i)
	{
		shuffle ^= time & SHFMSK;
		time = time >> LowBits;
	}

	// add a lower boundary value to ensure we have a minimum RNG loop count
	return (static_cast<size_t>(shuffle) + (static_cast<size_t>(1) << MinShift));
}

bool CJP::StuckCheck(std::unique_ptr<JitterState> &State, uint64_t CurrentDelta)
{
	const uint64_t DELTA2 = State->LastDelta - CurrentDelta;
	const uint64_t DELTA3 = DELTA2 - State->LastDelta2;
	bool ret;

	ret = false;
	State->LastDelta = CurrentDelta;
	State->LastDelta2 = DELTA2;

	if (CurrentDelta == 0 || DELTA2 == 0 || DELTA3 == 0)
	{
		ret = true;
	}

	return ret;
}

bool CJP::TimerCheck(std::unique_ptr<JitterState> &State)
{
	uint64_t delta;
	uint64_t olddelta;
	uint64_t sumdelta;
	uint64_t time;
	uint64_t time2;
	size_t backctr;
	size_t varctr;
	size_t modctr;
	bool result;

	sumdelta = 0;
	olddelta = 0;
	backctr = 0;
	varctr = 0;
	modctr = 0;
	result = false;

	for (size_t i = 0; (LOOP_TEST_COUNT + CLEARCACHE) > i; i++)
	{
		delta = 0;
		time = SystemTools::TimeStamp(OS_HAS_TSC);
		FoldTime(State, time);
		time2 = SystemTools::TimeStamp(OS_HAS_TSC);

		// test whether timer works
		if (time == 0 || time2 == 0)
		{
			break;
		}

		delta = time2 - time;
		// test whether timer is fine grained enough to provide delta even when called shortly after each other
		if (delta == 0)
		{
			break;
		}

		// up to here we did not modify any variable that will be evaluated later, but we already performed some work
		// thus we already have had an impact on the caches, branch prediction, etc. with the goal to clear it to get the worst case measurements
		if (i < CLEARCACHE)
		{
			continue;
		}

		// test whether we have an increasing timer
		if (time2 <= time)
		{
			backctr++;
		}
		if (delta % 100 == 0)
		{
			modctr++;
		}

		// ensure that we have a varying delta timer which is necessary for the calculation of entropy
		// perform this check only after the first loop is executed as we need to prime the oldDelta value
		if (delta != olddelta)
		{
			varctr++;
		}
		if (delta > olddelta)
		{
			sumdelta += (delta - olddelta);
		}
		else
		{
			sumdelta += (olddelta - delta);
		}

		olddelta = delta;
	}

	// we allow up to three times the time running backwards to account for ntp
	if (3 >= backctr && sumdelta > 1 && ((LOOP_TEST_COUNT / 10) * 9) >= modctr)
	{
		result = true;
	}

	return result;
}

NAMESPACE_PROVIDEREND
