#include "Skein1024.h"
#include "IntUtils.h"
#include "MemUtils.h"
#include "ParallelUtils.h"
#include "Skein.h"

NAMESPACE_DIGEST

using Utility::IntUtils;

const std::string Skein1024::CLASS_NAME("Skein1024");

//~~~Constructor~~~//

Skein1024::Skein1024(bool Parallel)
	:
	m_dgtState(Parallel ? DEF_PRLDEGREE : 1),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_msgBuffer(Parallel ? MIN_PRLBLOCK : BLOCK_SIZE, 0),
	m_msgLength(0),
	m_parallelProfile(BLOCK_SIZE, false, STATE_PRECACHED, false, DEF_PRLDEGREE),
	m_treeDestroy(true),
	m_treeParams(Parallel ? SkeinParams(DIGEST_SIZE, static_cast<byte>(BLOCK_SIZE), DEF_PRLDEGREE) : SkeinParams(DIGEST_SIZE, 0, 0))
{
	// TODO: implement parallel alternate for single core cpu
	if (Parallel && !m_parallelProfile.IsParallel())
	{
		throw CryptoDigestException("Skein1024::Ctor", "Cpu does not support parallel processing!");
	}

	if (m_parallelProfile.IsParallel())
	{
		m_parallelProfile.IsParallel() = Parallel;
	}

	Initialize();
}

Skein1024::Skein1024(SkeinParams &Params)
	:
	m_dgtState(1),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_msgBuffer(BLOCK_SIZE),
	m_msgLength(0),
	m_parallelProfile(BLOCK_SIZE, false, STATE_PRECACHED, false, m_treeParams.FanOut()),
	m_treeDestroy(false),
	m_treeParams(Params)
{
	if (m_treeParams.FanOut() > 1 && !m_parallelProfile.IsParallel())
	{
		throw CryptoDigestException("Skein1024::Ctor", "Cpu does not support parallel processing!");
	}

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

Skein1024::~Skein1024()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_isInitialized = false;
		m_msgLength = 0;

		if (m_treeDestroy)
		{
			m_treeParams.Reset();
			m_treeDestroy = false;
		}

		for (size_t i = 0; i < m_dgtState.size(); ++i)
		{
			m_dgtState[i].Reset();
		}

		IntUtils::ClearVector(m_dgtState);
		IntUtils::ClearVector(m_msgBuffer);
	}
}

//~~~Accessors~~~//

size_t Skein1024::BlockSize() 
{
	return BLOCK_SIZE; 
}

size_t Skein1024::DigestSize() 
{ 
	return DIGEST_SIZE; 
}

const Digests Skein1024::Enumeral() 
{ 
	return Digests::Skein1024; 
}

const bool Skein1024::IsParallel()
{ 
	return m_parallelProfile.IsParallel();
}

const std::string Skein1024::Name() 
{
	std::string txtName = "";

	if (m_parallelProfile.IsParallel())
	{
		txtName = CLASS_NAME + "-P" + IntUtils::ToString(m_parallelProfile.ParallelMaxDegree());
	}
	else
	{
		txtName = CLASS_NAME;
	}

	return txtName;
}

const size_t Skein1024::ParallelBlockSize() 
{ 
	return m_parallelProfile.ParallelBlockSize(); 
}

ParallelOptions &Skein1024::ParallelProfile()
{
	return m_parallelProfile;
}

//~~~Public Functions~~~//

void Skein1024::Compute(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Output.resize(DIGEST_SIZE);
	Update(Input, 0, Input.size());
	Finalize(Output, 0);
}

size_t Skein1024::Finalize(std::vector<byte> &Output, const size_t OutOffset)
{
	CexAssert(Output.size() - OutOffset >= DIGEST_SIZE, "The Output buffer is too short!");

	if (m_parallelProfile.IsParallel())
	{
		// pad buffer with zeros
		if (m_msgLength < m_msgBuffer.size())
		{
			Utility::MemUtils::Clear(m_msgBuffer, m_msgLength, m_msgBuffer.size() - m_msgLength);
		}

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
		std::vector<Skein1024State> rootState(1);
		SkeinParams rootParams{ DIGEST_SIZE };
		std::vector<ulong> rootConfig = rootParams.GetConfig();
		// load the initial state
		LoadState(rootState[0], rootConfig);

		// add state blocks as contiguous message input
		for (size_t i = 0; i < m_dgtState.size(); ++i)
		{
			IntUtils::LeULL1024ToBlock(m_dgtState[i].S, 0, m_msgBuffer, i * BLOCK_SIZE);
			m_msgLength += BLOCK_SIZE;
		}

		// finalize and store
		HashFinal(m_msgBuffer, 0, m_msgLength, rootState, 0);
		IntUtils::LeULL1024ToBlock(rootState[0].S, 0, Output, OutOffset);
	}
	else
	{
		// pad buffer with zeros
		if (m_msgLength < m_msgBuffer.size())
		{
			Utility::MemUtils::Clear(m_msgBuffer, m_msgLength, m_msgBuffer.size() - m_msgLength);
		}

		// finalize and store
		HashFinal(m_msgBuffer, 0, m_msgLength, m_dgtState, 0);
		IntUtils::LeULL1024ToBlock(m_dgtState[0].S, 0, Output, OutOffset);
	}

	Reset();

	return DIGEST_SIZE;
}

void Skein1024::Reset()
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

void Skein1024::ParallelMaxDegree(size_t Degree)
{
	CexAssert(Degree != 0, "parallel degree can not be zero");
	CexAssert(Degree % 2 == 0, "parallel degree must be an even number");
	CexAssert(Degree <= m_parallelProfile.ProcessorCount(), "parallel degree can not exceed processor count");

	m_parallelProfile.SetMaxDegree(Degree);
	m_dgtState.clear();
	m_dgtState.resize(Degree);
	m_msgBuffer.clear();
	m_msgBuffer.resize(Degree * BLOCK_SIZE);
	m_treeParams = { DIGEST_SIZE, static_cast<byte>(BLOCK_SIZE), static_cast<byte>(Degree) };

	Initialize();
}

void Skein1024::Update(byte Input)
{
	std::vector<byte> one(1, Input);
	Update(one, 0, 1);
}

void Skein1024::Update(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	CexAssert(Input.size() - InOffset >= Length, "The Output buffer is too short!");

	if (Length != 0)
	{
		if (m_parallelProfile.IsParallel())
		{
			if (m_msgLength != 0 && Length + m_msgLength >= m_msgBuffer.size())
			{
				// fill buffer
				const size_t RMDSZE = m_msgBuffer.size() - m_msgLength;
				if (RMDSZE != 0)
				{
					Utility::MemUtils::Copy(Input, InOffset, m_msgBuffer, m_msgLength, RMDSZE);
				}

				// empty the message buffer
				Utility::ParallelUtils::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Input, InOffset](size_t i)
				{
					ProcessBlock(m_msgBuffer, i * BLOCK_SIZE, m_dgtState, i);
				});

				m_msgLength = 0;
				Length -= RMDSZE;
				InOffset += RMDSZE;
			}

			if (Length >= m_parallelProfile.ParallelBlockSize())
			{
				// calculate working set size
				const size_t PRCLEN = Length - (Length % m_parallelProfile.ParallelBlockSize());

				// process large blocks
				Utility::ParallelUtils::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Input, InOffset, PRCLEN](size_t i)
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
		}
		else
		{
			if (m_msgLength != 0 && (m_msgLength + Length >= BLOCK_SIZE))
			{
				const size_t RMDSZE = BLOCK_SIZE - m_msgLength;
				if (RMDSZE != 0)
				{
					Utility::MemUtils::Copy(Input, InOffset, m_msgBuffer, m_msgLength, RMDSZE);
				}

				ProcessBlock(m_msgBuffer, 0, m_dgtState, 0);
				m_msgLength = 0;
				InOffset += RMDSZE;
				Length -= RMDSZE;
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
			Utility::MemUtils::Copy(Input, InOffset, m_msgBuffer, m_msgLength, Length);
			m_msgLength += Length;
		}
	}
}

//~~~Private Functions~~~//

void Skein1024::HashFinal(std::vector<byte> &Input, size_t InOffset, size_t Length, std::vector<Skein1024State> &State, size_t StateOffset)
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

void Skein1024::ProcessBlock(const std::vector<byte> &Input, size_t InOffset, std::vector<Skein1024State> &State, size_t StateOffset, size_t Length)
{
	// update length
	State[StateOffset].Increase(Length);
	// encrypt block
	std::array<ulong, 16> block;
	IntUtils::LeBytesToULL1024(Input, InOffset, block, 0);
	Skein::Compress1024(block, 0, State[StateOffset]);

	// feed-forward input with state
	Utility::MemUtils::XOR1024(block, 0, State[StateOffset].S, 0);

	// clear first flag
	if (!m_isInitialized && StateOffset == 0)
	{
		SkeinUbiTweak::IsFirstBlock(m_dgtState[0].T, false);
		m_isInitialized = true;
	}
}

void Skein1024::ProcessLeaf(const std::vector<byte> &Input, size_t InOffset, std::vector<Skein1024State> &State, size_t StateOffset, ulong Length)
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

void Skein1024::Initialize()
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
			Skein::Compress1024(m_dgtState[i - 1].V, 0, m_dgtState[i]);
			// store the new state in V for reset
			Utility::MemUtils::Copy(m_dgtState[i].S, 0, m_dgtState[i].V, 0, m_dgtState[i].V.size() * sizeof(ulong));
			// mix config with state
			Utility::MemUtils::XOR1024(config, 0, m_dgtState[i].V, 0);
		}
	}

	Reset();
}

void Skein1024::LoadState(Skein1024State &State, std::vector<ulong> &Config)
{
	// initialize the tweak value
	SkeinUbiTweak::StartNewBlockType(State.T, SkeinUbiType::Config);
	SkeinUbiTweak::IsFinalBlock(State.T, true);
	State.Increase(32);
	Skein::Compress1024(Config, 0, State);
	// store the initial state for reset
	Utility::MemUtils::Copy(m_dgtState[0].S, 0, m_dgtState[0].V, 0, m_dgtState[0].V.size() * sizeof(ulong));
	// add the config string
	Utility::MemUtils::XOR1024(Config, 0, State.V, 0);
}

NAMESPACE_DIGESTEND