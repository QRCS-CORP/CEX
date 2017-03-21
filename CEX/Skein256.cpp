#include "Skein256.h"
#include "ArrayUtils.h"
#include "IntUtils.h"
#include "ParallelUtils.h"

NAMESPACE_DIGEST

using Utility::IntUtils;
using Utility::ParallelUtils;

//~~~Constructor~~~//

Skein256::Skein256(bool Parallel)
	:
	m_dgtState(Parallel ? DEF_PRLDEGREE : 1),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_msgBuffer(Parallel ? MIN_PRLBLOCK : BLOCK_SIZE, 0),
	m_msgLength(0),
	m_parallelProfile(BLOCK_SIZE, false, STATE_PRECACHED, false, DEF_PRLDEGREE)
{
	if (m_parallelProfile.IsParallel())
		m_parallelProfile.IsParallel() = Parallel;

	if (Parallel)
		m_treeParams = { DIGEST_SIZE, static_cast<byte>(BLOCK_SIZE), DEF_PRLDEGREE };
	else
		m_treeParams = { DIGEST_SIZE };

	Initialize();
}

Skein256::Skein256(SkeinParams &Params)
	:
	m_treeParams(Params),
	m_dgtState(1),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_msgBuffer(BLOCK_SIZE),
	m_msgLength(0),
	m_parallelProfile(BLOCK_SIZE, false, STATE_PRECACHED, false, m_treeParams.FanOut())
{
	if (m_treeParams.FanOut() > 1)
	{
		m_dgtState.resize(m_treeParams.FanOut());
		m_msgBuffer.resize(m_treeParams.FanOut() * BLOCK_SIZE);
	}
	else if (m_parallelProfile.IsParallel())
	{
		m_parallelProfile.IsParallel() = false;
	}

	Initialize();
}

Skein256::~Skein256()
{
	Destroy();
}

//~~~Public Functions~~~//

void Skein256::Compute(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Output.resize(DIGEST_SIZE);
	Update(Input, 0, Input.size());
	Finalize(Output, 0);
}

void Skein256::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_isInitialized = false;
		m_msgLength = 0;
		m_parallelProfile.Reset();
		m_treeParams.Reset();

		for (size_t i = 0; i < m_dgtState.size(); ++i)
			m_dgtState[i].Reset();

		try
		{
			Utility::ArrayUtils::ClearVector(m_dgtState);
			Utility::ArrayUtils::ClearVector(m_msgBuffer);
		}
		catch (std::exception& ex)
		{
			throw CryptoDigestException("Skein256:Destroy", "Could not clear all variables!", std::string(ex.what()));
		}
	}
}

size_t Skein256::Finalize(std::vector<byte> &Output, const size_t OutOffset)
{
	CEXASSERT(Output.size() - OutOffset >= DIGEST_SIZE, "The Output buffer is too short!");

	if (m_parallelProfile.IsParallel())
	{
		// pad buffer with zeros
		if (m_msgLength < m_msgBuffer.size())
			memset(&m_msgBuffer[m_msgLength], (byte)0, m_msgBuffer.size() - m_msgLength);

		// process buffer
		if (m_msgLength != 0)
		{
			size_t blkCtr = 0;

			while (m_msgLength != 0)
			{
				const size_t MSGRMD = (m_msgLength >= BLOCK_SIZE) ? BLOCK_SIZE : m_msgLength;
				HashFinal(m_msgBuffer, blkCtr * BLOCK_SIZE, MSGRMD, m_dgtState, blkCtr);
				m_msgLength -= MSGRMD;
				++blkCtr;
			}
		}

		// initialize a linear-mode hash config
		std::vector<Skein256State> rootState(1);
		SkeinParams rootParams{ DIGEST_SIZE };
		std::vector<ulong> rootConfig = rootParams.GetConfig();
		// load the initial state
		LoadState(rootState[0], rootConfig);

		// add state blocks as contiguous message input
		for (size_t i = 0; i < m_dgtState.size(); ++i)
		{
			IntUtils::LeULL256ToBlock(m_dgtState[i].S, m_msgBuffer, i * BLOCK_SIZE);
			m_msgLength += BLOCK_SIZE;
		}

		// finalize and store
		HashFinal(m_msgBuffer, 0, m_msgLength, rootState, 0);
		IntUtils::LeULL256ToBlock(rootState[0].S, Output, OutOffset);
	}
	else
	{
		// pad buffer with zeros
		if (m_msgLength < m_msgBuffer.size())
			memset(&m_msgBuffer[m_msgLength], (byte)0, m_msgBuffer.size() - m_msgLength);

		// finalize and store
		HashFinal(m_msgBuffer, 0, m_msgLength, m_dgtState, 0);
		IntUtils::LeULL256ToBlock(m_dgtState[0].S, Output, OutOffset);
	}

	Reset();

	return DIGEST_SIZE;
}

void Skein256::Reset()
{
	for (size_t i = 0; i < m_dgtState.size(); ++i)
	{
		// copy the configuration value to the state
		m_dgtState[i].S = m_dgtState[i].V;
		SkeinUbiTweak::StartNewBlockType(m_dgtState[i].T, SkeinUbiType::Message);
	}

	m_isInitialized = false;
	// reset bytes filled
	m_msgLength = 0;
}

void Skein256::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0)
		throw CryptoDigestException("Skein256:ParallelMaxDegree", "Parallel degree can not be zero!");
	if (Degree > 254)
		throw CryptoDigestException("Skein256:ParallelMaxDegree", "Parallel degree can not exceed 254!");
	if (Degree % 2 != 0)
		throw CryptoDigestException("Skein256:ParallelMaxDegree", "Parallel degree must be an even number!");

	m_parallelProfile.SetMaxDegree(Degree);
	m_dgtState.clear();
	m_dgtState.resize(Degree);
	m_msgBuffer.clear();
	m_msgBuffer.resize(Degree * BLOCK_SIZE);
	m_treeParams = { DIGEST_SIZE, static_cast<byte>(BLOCK_SIZE), static_cast<byte>(Degree) };

	Initialize();
}

void Skein256::Update(byte Input)
{
	std::vector<byte> one(1, Input);
	Update(one, 0, 1);
}

void Skein256::Update(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	CEXASSERT(Input.size() - InOffset >= Length, "The Output buffer is too short!");

	if (Length == 0)
		return;

	if (m_parallelProfile.IsParallel())
	{
		if (m_msgLength != 0 && Length + m_msgLength >= m_msgBuffer.size())
		{
			// fill buffer
			const size_t BUFRMD = m_msgBuffer.size() - m_msgLength;
			if (BUFRMD != 0)
				memcpy(&m_msgBuffer[m_msgLength], &Input[InOffset], BUFRMD);

			// empty the message buffer
			ParallelUtils::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Input, InOffset](size_t i)
			{
				ProcessBlock(m_msgBuffer, i * BLOCK_SIZE, m_dgtState, i);
			});

			m_msgLength = 0;
			Length -= BUFRMD;
			InOffset += BUFRMD;
		}

		if (Length >= m_parallelProfile.ParallelBlockSize())
		{
			// calculate working set size
			const size_t PRCLEN = Length - (Length % m_parallelProfile.ParallelBlockSize());

			// process large blocks
			ParallelUtils::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Input, InOffset, PRCLEN](size_t i)
			{
				ProcessLeaf(Input, InOffset + (i * BLOCK_SIZE), m_dgtState, i, PRCLEN);
			});

			Length -= PRCLEN;
			InOffset += PRCLEN;
		}

		if (Length >= m_parallelProfile.ParallelMinimumSize())
		{
			const size_t PRMLEN = Length - (Length % m_parallelProfile.ParallelMinimumSize());

			Utility::ParallelUtils::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Input, InOffset, PRMLEN](size_t i)
			{
				ProcessLeaf(Input, InOffset + (i * BLOCK_SIZE), m_dgtState, i, PRMLEN);
			});

			Length -= PRMLEN;
			InOffset += PRMLEN;
		}

		if (Length >= BLOCK_SIZE)
		{
			// stagger blocks
			size_t blkCtr = 0;
			while (Length >= BLOCK_SIZE)
			{
				ProcessBlock(Input, InOffset, m_dgtState, blkCtr);
				InOffset += BLOCK_SIZE;
				Length -= BLOCK_SIZE;
				blkCtr = (blkCtr != m_dgtState.size() - 1) ? blkCtr + 1 : 0;
			}
		}
	}
	else
	{
		if (m_msgLength != 0 && (m_msgLength + Length >= BLOCK_SIZE))
		{
			size_t rmd = BLOCK_SIZE - m_msgLength;
			if (rmd != 0)
				memcpy(&m_msgBuffer[m_msgLength], &Input[InOffset], rmd);

			ProcessBlock(m_msgBuffer, 0, m_dgtState, 0);
			m_msgLength = 0;
			InOffset += rmd;
			Length -= rmd;
		}

		// sequential loop through blocks
		while (Length > BLOCK_SIZE)
		{
			ProcessBlock(Input, InOffset, m_dgtState, 0);
			InOffset += BLOCK_SIZE;
			Length -= BLOCK_SIZE;
		}
	}

	// store unaligned bytes
	if (Length != 0)
	{
		memcpy(&m_msgBuffer[m_msgLength], &Input[InOffset], Length);
		m_msgLength += Length;
	}
}

//~~~Private Functions~~~//

void Skein256::HashFinal(std::vector<byte> &Input, size_t InOffset, size_t Length, std::vector<Skein256State> &State, size_t StateOffset)
{
	// process message block
	SkeinUbiTweak::IsFinalBlock(State[StateOffset].T, true);
	while (Length != 0)
	{
		const size_t MSGRMD = (Length >= BLOCK_SIZE) ? BLOCK_SIZE : Length;
		ProcessBlock(Input, InOffset, State, StateOffset, MSGRMD);
		Length -= MSGRMD;
		InOffset += MSGRMD;
	}

	// finalize block
	SkeinUbiTweak::StartNewBlockType(State[StateOffset].T, SkeinUbiType::Out);
	SkeinUbiTweak::IsFinalBlock(State[StateOffset].T, true);
	std::vector<byte> tmp(BLOCK_SIZE);
	ProcessBlock(tmp, 0, State, StateOffset, 8);
}

void Skein256::ProcessBlock(const std::vector<byte> &Input, size_t InOffset, std::vector<Skein256State> &State, size_t StateOffset, size_t Length)
{
	// update length
	State[StateOffset].Increase(Length);
	// encrypt block
	std::vector<ulong> block(4, 0);
	IntUtils::BytesToLeULL256(Input, InOffset, block, 0);
	Threefish256::Transfrom32(block, 0, State[StateOffset]);

	// feed-forward input with state
	IntUtils::XORULL256(block, 0, State[StateOffset].S, 0, m_parallelProfile.SimdProfile());

	// clear first flag
	if (!m_isInitialized && StateOffset == 0)
	{
		SkeinUbiTweak::IsFirstBlock(m_dgtState[0].T, false);
		m_isInitialized = true;
	}
}

void Skein256::ProcessLeaf(const std::vector<byte> &Input, size_t InOffset, std::vector<Skein256State> &State, size_t StateOffset, ulong Length)
{
	do
	{
		// process message offset by lane size
		ProcessBlock(Input, InOffset, State, StateOffset);
		InOffset += m_parallelProfile.ParallelMinimumSize();
		Length -= m_parallelProfile.ParallelMinimumSize();
	} 
	while (Length > 0);
}

void Skein256::Initialize()
{
	std::vector<ulong> config = m_treeParams.GetConfig();

	LoadState(m_dgtState[0], config);

	if (m_parallelProfile.IsParallel())
	{
		for (size_t i = 1; i < m_dgtState.size(); ++i)
		{
			// create unique state for each node
			SkeinUbiTweak::StartNewBlockType(m_dgtState[i].T, SkeinUbiType::Config);
			SkeinUbiTweak::IsFinalBlock(m_dgtState[i].T, true);
			m_dgtState[i].Increase(32);
			// compress previous state
			Threefish256::Transfrom32(m_dgtState[i - 1].V, 0, m_dgtState[i]);
			// store the new state in V for reset
			memcpy(&m_dgtState[i].V[0], &m_dgtState[i].S[0], m_dgtState[i].V.size() * sizeof(ulong));
			// mix config with state
			IntUtils::XORULL256(config, 0, m_dgtState[i].V, 0, m_parallelProfile.SimdProfile());
		}
	}

	Reset();
}

void Skein256::LoadState(Skein256State &State, std::vector<ulong> &Config)
{
	// initialize the tweak value
	SkeinUbiTweak::StartNewBlockType(State.T, SkeinUbiType::Config);
	SkeinUbiTweak::IsFinalBlock(State.T, true);
	State.Increase(32);
	Threefish256::Transfrom32(Config, 0, State);
	// store the initial state for reset
	memcpy(&State.V[0], &State.S[0], State.V.size() * sizeof(ulong));
	// add the config string
	IntUtils::XORULL256(Config, 0, State.V, 0, m_parallelProfile.SimdProfile());
}

NAMESPACE_DIGESTEND
