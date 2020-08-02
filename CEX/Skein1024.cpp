#include "Skein1024.h"
#include "IntegerTools.h"
#include "MemoryTools.h"
#include "ParallelTools.h"
#include "Skein.h"

NAMESPACE_DIGEST

using Enumeration::DigestConvert;
using Tools::IntegerTools;
using Tools::MemoryTools;
using Tools::ParallelTools;

class Skein1024::Skein1024State
{
public:

	// state
	std::array<ulong, 16> S = { 0 };
	// config
	std::array<ulong, 16> V = { 0 };
	// tweak
	std::array<ulong, 2> T = { 0 };

	Skein1024State()
	{
	}

	~Skein1024State()
	{
		Reset();
	}

	void Increase(size_t Length)
	{
		T[0] += Length;
	}

	void Reset()
	{
		MemoryTools::Clear(S, 0, S.size() * sizeof(ulong));
		MemoryTools::Clear(T, 0, T.size() * sizeof(ulong));
		MemoryTools::Clear(V, 0, V.size() * sizeof(ulong));
	}
};

//~~~Constructor~~~//

Skein1024::Skein1024(bool Parallel)
	:
	m_dgtState(Parallel ? 
		DEF_PRLDEGREE : 
		1),
	m_msgBuffer(Parallel ?
		DEF_PRLDEGREE * Skein::SKEIN1024_RATE_SIZE : 
		Skein::SKEIN1024_RATE_SIZE),
	m_msgLength(0),
	m_parallelProfile(Skein::SKEIN1024_RATE_SIZE, Parallel, false, STATE_PRECACHED, false, DEF_PRLDEGREE),
	m_treeParams(Parallel ? 
		SkeinParams(Skein::SKEIN1024_DIGEST_SIZE, static_cast<byte>(Skein::SKEIN1024_RATE_SIZE), static_cast<byte>(DEF_PRLDEGREE)) :
		SkeinParams(Skein::SKEIN1024_DIGEST_SIZE, 0x00, 0x00))
{
	Initialize(m_dgtState, m_treeParams);
}

Skein1024::Skein1024(SkeinParams &Params)
	:
	m_dgtState(Params.FanOut() != 0 && Params.FanOut() <= MAX_PRLDEGREE ? 
		Params.FanOut() :
		throw CryptoDigestException(DigestConvert::ToName(Digests::Skein1024), std::string("Constructor"), std::string("The FanOut parameter can not be zero or exceed the maximum of 64!"), ErrorCodes::IllegalOperation)),
	m_msgBuffer(Skein::SKEIN1024_RATE_SIZE),
	m_msgLength(0),
	m_parallelProfile(Skein::SKEIN1024_RATE_SIZE, static_cast<bool>(Params.FanOut() > 1), false, STATE_PRECACHED, false, Params.FanOut()),
	m_treeParams(Params)
{
	Initialize(m_dgtState, m_treeParams);
}

Skein1024::~Skein1024()
{
	m_msgLength = 0;
	IntegerTools::Clear(m_dgtState);
	IntegerTools::Clear(m_msgBuffer);
}

//~~~Accessors~~~//

size_t Skein1024::BlockSize()
{
	return Skein::SKEIN1024_RATE_SIZE;
}

size_t Skein1024::DigestSize()
{
	return Skein::SKEIN1024_DIGEST_SIZE;
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
	std::string name;

	if (m_treeParams.FanOut() > 1)
	{
		name = DigestConvert::ToName(Digests::Skein1024) + std::string("-P") + IntegerTools::ToString(m_parallelProfile.ParallelMaxDegree());
	}
	else
	{
		name = DigestConvert::ToName(Digests::Skein1024);
	}

	return name;
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
	if (Output.size() < Skein::SKEIN1024_DIGEST_SIZE)
	{
		throw CryptoDigestException(Name(), std::string("Compute"), std::string("The output vector is too small!"), ErrorCodes::InvalidSize);
	}

	Update(Input, 0, Input.size());
	Finalize(Output, 0);
}

void Skein1024::Finalize(std::vector<byte> &Output, size_t OutOffset)
{
	if (Output.size() - OutOffset < Skein::SKEIN1024_DIGEST_SIZE)
	{
		throw CryptoDigestException(Name(), std::string("Finalize"), std::string("The output vector is too small!"), ErrorCodes::InvalidSize);
	}

	size_t bctr;
	size_t i;

	if (m_parallelProfile.IsParallel())
	{
		// pad buffer with zeros
		if (m_msgLength < m_msgBuffer.size())
		{
			MemoryTools::Clear(m_msgBuffer, m_msgLength, m_msgBuffer.size() - m_msgLength);
		}

		// process buffer
		if (m_msgLength != 0)
		{
			bctr = 0;

			while (m_msgLength != 0)
			{
				const size_t MSGRMD = (m_msgLength >= Skein::SKEIN1024_RATE_SIZE) ? Skein::SKEIN1024_RATE_SIZE : m_msgLength;
				HashFinal(m_msgBuffer, bctr * Skein::SKEIN1024_RATE_SIZE, MSGRMD, m_dgtState[bctr]);
				m_msgLength -= MSGRMD;
				++bctr;
			}
		}

		// initialize a linear-mode hash config
		Skein1024State proot;
		SkeinParams rparam{ Skein::SKEIN1024_DIGEST_SIZE };
		std::vector<ulong> tmp = rparam.GetConfig();
		std::array<ulong, 16> cfg{ tmp[0], tmp[1], tmp[2], tmp[3], tmp[4], tmp[5], tmp[6], tmp[7], tmp[8], tmp[9], tmp[10], tmp[11], tmp[12], tmp[13], tmp[14], tmp[15] };
		// load the initial state
		LoadState(proot, cfg);

		// add state blocks as contiguous message input
		for (i = 0; i < m_dgtState.size(); ++i)
		{
			IntegerTools::LeULL1024ToBlock(m_dgtState[i].S, 0, m_msgBuffer, i * Skein::SKEIN1024_RATE_SIZE);
			m_msgLength += Skein::SKEIN1024_RATE_SIZE;
		}

		// finalize and store
		HashFinal(m_msgBuffer, 0, m_msgLength, proot);
		IntegerTools::LeULL1024ToBlock(proot.S, 0, Output, OutOffset);
	}
	else
	{
		// pad buffer with zeros
		if (m_msgLength < m_msgBuffer.size())
		{
			MemoryTools::Clear(m_msgBuffer, m_msgLength, m_msgBuffer.size() - m_msgLength);
		}

		// finalize and store
		HashFinal(m_msgBuffer, 0, m_msgLength, m_dgtState[0]);
		IntegerTools::LeULL1024ToBlock(m_dgtState[0].S, 0, Output, OutOffset);
	}

	Reset();
}

void Skein1024::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0 || Degree % 2 != 0 || Degree > MAX_PRLDEGREE)
	{
		throw CryptoDigestException(Name(), std::string("ParallelMaxDegree"), std::string("Degree setting is invalid!"), ErrorCodes::NotSupported);
	}

	m_parallelProfile.SetMaxDegree(Degree);
	m_dgtState.clear();
	m_dgtState.resize(Degree);
	m_msgBuffer.clear();
	m_msgBuffer.resize(Degree * Skein::SKEIN1024_RATE_SIZE);
	m_treeParams = { Skein::SKEIN1024_DIGEST_SIZE, static_cast<byte>(Skein::SKEIN1024_RATE_SIZE), static_cast<byte>(Degree) };

	Initialize(m_dgtState, m_treeParams);
}

void Skein1024::Reset()
{
	size_t i;

	for (i = 0; i < m_dgtState.size(); ++i)
	{
		// copy the configuration value to the state
		m_dgtState[i].S = m_dgtState[i].V;
		SkeinUbiTweak::StartNewBlockType(m_dgtState[i].T, SkeinUbiType::Message);
	}

	// reset bytes filled
	MemoryTools::Clear(m_msgBuffer, 0, m_msgBuffer.size());
	m_msgLength = 0;
}

void Skein1024::Update(byte Input)
{
	std::vector<byte> one(1, Input);
	Update(one, 0, 1);
}

void Skein1024::Update(uint Input)
{
	std::vector<byte> tmp(sizeof(uint));
	IntegerTools::Le32ToBytes(Input, tmp, 0);
	Update(tmp, 0, tmp.size());
}

void Skein1024::Update(ulong Input)
{
	std::vector<byte> tmp(sizeof(ulong));
	IntegerTools::Le64ToBytes(Input, tmp, 0);
	Update(tmp, 0, tmp.size());
}

void Skein1024::Update(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	CEXASSERT(Input.size() - InOffset >= Length, "The input buffer is too short!");

	if (Length != 0)
	{
		if (m_parallelProfile.IsParallel())
		{
			if (m_msgLength != 0 && Length + m_msgLength >= m_msgBuffer.size())
			{
				// fill buffer
				const size_t RMDLEN = m_msgBuffer.size() - m_msgLength;
				if (RMDLEN != 0)
				{
					MemoryTools::Copy(Input, InOffset, m_msgBuffer, m_msgLength, RMDLEN);
				}

				// empty the message buffer
				ParallelTools::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Input, InOffset](size_t i)
				{
					ProcessBlock(m_msgBuffer, i * Skein::SKEIN1024_RATE_SIZE, m_dgtState[i], Skein::SKEIN1024_RATE_SIZE);
				});

				m_msgLength = 0;
				Length -= RMDLEN;
				InOffset += RMDLEN;
			}

			if (Length >= m_parallelProfile.ParallelBlockSize())
			{
				// calculate working set size
				const size_t PRCLEN = Length - (Length % m_parallelProfile.ParallelBlockSize());

				// process large blocks
				ParallelTools::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Input, InOffset, PRCLEN](size_t i)
				{
					ProcessLeaf(Input, InOffset + (i * Skein::SKEIN1024_RATE_SIZE), m_dgtState[i], PRCLEN);
				});

				Length -= PRCLEN;
				InOffset += PRCLEN;
			}

			if (Length >= m_parallelProfile.ParallelMinimumSize())
			{
				const size_t PRMLEN = Length - (Length % m_parallelProfile.ParallelMinimumSize());

				ParallelTools::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Input, InOffset, PRMLEN](size_t i)
				{
					ProcessLeaf(Input, InOffset + (i * Skein::SKEIN1024_RATE_SIZE), m_dgtState[i], PRMLEN);
				});

				Length -= PRMLEN;
				InOffset += PRMLEN;
			}
		}
		else
		{
			if (m_msgLength != 0 && (m_msgLength + Length > Skein::SKEIN1024_RATE_SIZE))
			{
				const size_t RMDLEN = Skein::SKEIN1024_RATE_SIZE - m_msgLength;
				if (RMDLEN != 0)
				{
					MemoryTools::Copy(Input, InOffset, m_msgBuffer, m_msgLength, RMDLEN);
				}

				ProcessBlock(m_msgBuffer, 0, m_dgtState[0], Skein::SKEIN1024_RATE_SIZE);
				m_msgLength = 0;
				InOffset += RMDLEN;
				Length -= RMDLEN;
			}

			// sequential loop through blocks
			while (Length > Skein::SKEIN1024_RATE_SIZE)
			{
				ProcessBlock(Input, InOffset, m_dgtState[0], Skein::SKEIN1024_RATE_SIZE);
				InOffset += Skein::SKEIN1024_RATE_SIZE;
				Length -= Skein::SKEIN1024_RATE_SIZE;
			}
		}

		// store unaligned bytes
		if (Length != 0)
		{
			MemoryTools::Copy(Input, InOffset, m_msgBuffer, m_msgLength, Length);
			m_msgLength += Length;
		}
	}
}

//~~~Private Functions~~~//

void Skein1024::HashFinal(std::vector<byte> &Input, size_t InOffset, size_t Length, Skein1024State &State)
{
	// process message block
	SkeinUbiTweak::IsFinalBlock(State.T, true);

	if (Length != 0)
	{
		while (Length != 0)
		{
			const size_t MSGRMD = (Length >= Skein::SKEIN1024_RATE_SIZE) ? Skein::SKEIN1024_RATE_SIZE : Length;
			ProcessBlock(Input, InOffset, State, MSGRMD);
			Length -= MSGRMD;
			InOffset += MSGRMD;
		}
	}
	else
	{
		ProcessBlock(Input, InOffset, State, 0);
	}

	// finalize block
	SkeinUbiTweak::StartNewBlockType(State.T, SkeinUbiType::Out);
	SkeinUbiTweak::IsFinalBlock(State.T, true);
	std::vector<byte> tmp(Skein::SKEIN1024_RATE_SIZE);
	ProcessBlock(tmp, 0, State, 8);
}

void Skein1024::Initialize(std::vector<Skein1024State> &State, SkeinParams &Params)
{
	std::vector<ulong> tmp = Params.GetConfig();
	std::array<ulong, 16> cfg{ tmp[0], tmp[1], tmp[2], tmp[3], tmp[4], tmp[5], tmp[6], tmp[7], tmp[8], tmp[9], tmp[10], tmp[11], tmp[12], tmp[13], tmp[14], tmp[15] };
	size_t i;

	LoadState(State[0], cfg);

	for (i = 1; i < State.size(); ++i)
	{
		// create unique state for each node
		SkeinUbiTweak::StartNewBlockType(State[i].T, SkeinUbiType::Config);
		SkeinUbiTweak::IsFinalBlock(State[i].T, true);
		State[i].Increase(32);
		// compress previous state
		Permute(State[i - 1].V, State[i]);
		// store the new state in V for reset
		MemoryTools::Copy(State[i].S, 0, State[i].V, 0, State[i].V.size() * sizeof(ulong));
		// mix config with state
		MemoryTools::XOR1024(cfg, 0, State[i].V, 0);
	}

	for (i = 0; i < State.size(); ++i)
	{
		// copy the configuration value to the state
		State[i].S = State[i].V;
		SkeinUbiTweak::StartNewBlockType(State[i].T, SkeinUbiType::Message);
	}
}

void Skein1024::LoadState(Skein1024State &State, std::array<ulong, 16> &Config)
{
	// initialize the tweak value
	SkeinUbiTweak::StartNewBlockType(State.T, SkeinUbiType::Config);
	SkeinUbiTweak::IsFinalBlock(State.T, true);
	State.Increase(32);
	Permute(Config, State);
	// store the initial state for reset
	MemoryTools::Copy(State.S, 0, State.V, 0, State.V.size() * sizeof(ulong));
	// add the config string
	MemoryTools::XOR1024(Config, 0, State.V, 0);
}

void Skein1024::Permute(std::array<ulong, 16> &Message, Skein1024State &State)
{
#if defined(CEX_DIGEST_COMPACT)
	Skein::PemuteP1024C(Message, State.T, State.S, 80);
#else
	Skein::PemuteR80P1024U(Message, State.T, State.S);
#endif
}

void Skein1024::ProcessBlock(const std::vector<byte> &Input, size_t InOffset, Skein1024State &State, size_t Length)
{
	// update length
	State.Increase(Length);
	// encrypt block
	std::array<ulong, 16> msg;
	IntegerTools::LeBytesToULL1024(Input, InOffset, msg, 0);
	Permute(msg, State);
	// feed-forward input with state
	MemoryTools::XOR1024(msg, 0, State.S, 0);

	// clear first flag
	if (SkeinUbiTweak::IsFirstBlock(State.T))
	{
		SkeinUbiTweak::IsFirstBlock(State.T, false);
	}
}

void Skein1024::ProcessLeaf(const std::vector<byte> &Input, size_t InOffset, Skein1024State &State, ulong Length)
{
	do
	{
		// process message offset by lane size
		ProcessBlock(Input, InOffset, State, Skein::SKEIN1024_RATE_SIZE);
		InOffset += m_parallelProfile.ParallelMinimumSize();
		Length -= m_parallelProfile.ParallelMinimumSize();
	} 
	while (Length > 0);
}

NAMESPACE_DIGESTEND
