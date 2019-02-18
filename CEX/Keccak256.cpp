#include "Keccak256.h"
#include "Keccak.h"
#include "IntegerTools.h"
#include "MemoryTools.h"
#include "ParallelTools.h"

NAMESPACE_DIGEST

using Utility::IntegerTools;
using Utility::MemoryTools;
using Utility::ParallelTools;

const std::string Keccak256::CLASS_NAME("Keccak512");

//~~~Constructor~~~//

Keccak256::Keccak256(bool Parallel)
	:
	m_dgtState(Parallel ? DEF_PRLDEGREE : 1),
	m_isDestroyed(false),
	m_msgBuffer(Parallel ? DEF_PRLDEGREE * Keccak::KECCAK_RATE256_SIZE : Keccak::KECCAK_RATE256_SIZE),
	m_msgLength(0),
	m_parallelProfile(Keccak::KECCAK_RATE256_SIZE, false, STATE_PRECACHED, false, DEF_PRLDEGREE),
	m_treeDestroy(true),
	m_treeParams(Parallel ? KeccakParams(DIGEST_SIZE, static_cast<byte>(Keccak::KECCAK_RATE256_SIZE), DEF_PRLDEGREE) : KeccakParams(DIGEST_SIZE, 0, 0))
{
	// TODO: implement parallel alternate for single core cpu
	m_parallelProfile.IsParallel() = (m_parallelProfile.IsParallel() == true) ? Parallel : false;

	Reset();
}

Keccak256::Keccak256(KeccakParams &Params)
	:
	m_dgtState(1),
	m_isDestroyed(false),
	m_msgBuffer(Keccak::KECCAK_RATE256_SIZE),
	m_msgLength(0),
	m_parallelProfile(Keccak::KECCAK_RATE256_SIZE, false, STATE_PRECACHED, false, m_treeParams.FanOut()),
	m_treeDestroy(false),
	m_treeParams(Params)
{
	if (m_treeParams.FanOut() > 1 && !m_parallelProfile.IsParallel())
	{
		throw CryptoDigestException(CLASS_NAME, std::string("Constructor"), std::string("Cpu does not support parallel processing!"), ErrorCodes::NotSupported);
	}
	if (m_parallelProfile.IsParallel() && m_treeParams.FanOut() > m_parallelProfile.ParallelMaxDegree())
	{
		throw CryptoDigestException(CLASS_NAME, std::string("Constructor"), std::string("The tree parameters are invalid!"), ErrorCodes::InvalidParam);
	}

	if (m_treeParams.FanOut() > 1 && m_parallelProfile.IsParallel())
	{
		m_dgtState.resize(m_treeParams.FanOut());
		m_msgBuffer.resize(m_treeParams.FanOut() * Keccak::KECCAK_RATE256_SIZE);
	}
	else if (m_parallelProfile.IsParallel())
	{
		m_parallelProfile.IsParallel() = false;
	}

	Reset();
}

Keccak256::~Keccak256()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
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

		IntegerTools::Clear(m_dgtState);
		IntegerTools::Clear(m_msgBuffer);
	}
}

//~~~Accessors~~~//

size_t Keccak256::BlockSize() 
{ 
	return Keccak::KECCAK_RATE256_SIZE; 
}

size_t Keccak256::DigestSize() 
{ 
	return DIGEST_SIZE; 
}

const Digests Keccak256::Enumeral() 
{ 
	return Digests::Keccak256; 
}

const bool Keccak256::IsParallel() 
{
	return m_parallelProfile.IsParallel(); 
}

const std::string Keccak256::Name()
{ 
	std::string name;

	if (m_parallelProfile.IsParallel())
	{
		name = CLASS_NAME + "-P" + IntegerTools::ToString(m_parallelProfile.ParallelMaxDegree());
	}
	else
	{
		name = CLASS_NAME;
	}

	return name;
}

const size_t Keccak256::ParallelBlockSize() 
{ 
	return m_parallelProfile.ParallelBlockSize(); 
}

ParallelOptions &Keccak256::ParallelProfile() 
{ 
	return m_parallelProfile;
}

//~~~Public Functions~~~//

void Keccak256::Compute(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Output.resize(DIGEST_SIZE);
	Update(Input, 0, Input.size());
	Finalize(Output, 0);
}

size_t Keccak256::Finalize(std::vector<byte> &Output, size_t OutOffset)
{
	CEXASSERT(Output.size() - OutOffset >= DIGEST_SIZE, "The Output buffer is too short!");

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
			size_t blkCtr = 0;

			while (m_msgLength != 0)
			{
				const size_t MSGRMD = (m_msgLength >= Keccak::KECCAK_RATE256_SIZE) ? Keccak::KECCAK_RATE256_SIZE : m_msgLength;
				HashFinal(m_msgBuffer, blkCtr * Keccak::KECCAK_RATE256_SIZE, MSGRMD, m_dgtState[blkCtr]);
				m_msgLength -= MSGRMD;
				++blkCtr;
			}
		}

		// initialize root state
		KeccakState rootState;

		// add state blocks as contiguous message input
		for (size_t i = 0; i < m_dgtState.size(); ++i)
		{
			IntegerTools::LeULL256ToBlock(m_dgtState[i].H, 0, m_msgBuffer, i * DIGEST_SIZE);
			m_msgLength += DIGEST_SIZE;
		}

		// compress full blocks
		size_t blkOff = 0;
		if (m_msgLength > Keccak::KECCAK_RATE256_SIZE)
		{
			const size_t BLKRMD = m_msgLength - (m_msgLength % Keccak::KECCAK_RATE256_SIZE);

			for (size_t i = 0; i < BLKRMD / Keccak::KECCAK_RATE256_SIZE; ++i)
			{
				Keccak::Absorb(m_msgBuffer, i * Keccak::KECCAK_RATE256_SIZE, Keccak::KECCAK_RATE256_SIZE, rootState.H);
				Permute(rootState.H);
			}

			m_msgLength -= BLKRMD;
			blkOff = BLKRMD;
		}

		// finalize and store
		HashFinal(m_msgBuffer, blkOff, m_msgLength, rootState);
		IntegerTools::LeULL256ToBlock(rootState.H, 0, Output, OutOffset);
	}
	else
	{
		if (m_msgLength != m_msgBuffer.size())
		{
			MemoryTools::Clear(m_msgBuffer, m_msgLength, m_msgBuffer.size() - m_msgLength);
		}

		HashFinal(m_msgBuffer, 0, m_msgLength, m_dgtState[0]);
		IntegerTools::LeULL256ToBlock(m_dgtState[0].H, 0, Output, OutOffset);
	}

	Reset();

	return DIGEST_SIZE;
}

void Keccak256::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0 || Degree % 2 != 0 || Degree > m_parallelProfile.ProcessorCount())
	{
		throw CryptoDigestException(Name(), std::string("ParallelMaxDegree"), std::string("Degree setting is invalid!"), ErrorCodes::NotSupported);
	}

	m_parallelProfile.SetMaxDegree(Degree);

	Reset();
}

void Keccak256::Reset()
{
	MemoryTools::Clear(m_msgBuffer, 0, m_msgBuffer.size());
	m_msgLength = 0;

	for (size_t i = 0; i < m_dgtState.size(); ++i)
	{
		m_dgtState[i].Reset();

		if (m_parallelProfile.IsParallel())
		{
			m_treeParams.NodeOffset() = static_cast<uint>(i);
			Keccak::Absorb(m_treeParams.ToBytes(), 0, Keccak::KECCAK_RATE256_SIZE, m_dgtState[i].H);
			Permute(m_dgtState[i].H);
		}
	}
}

void Keccak256::Update(byte Input)
{
	std::vector<byte> one(1, Input);
	Update(one, 0, 1);
}

void Keccak256::Update(const std::vector<byte> &Input, size_t InOffset, size_t Length)
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
					Keccak::Absorb(m_msgBuffer, i * Keccak::KECCAK_RATE256_SIZE, Keccak::KECCAK_RATE256_SIZE, m_dgtState[i].H);
					Permute(m_dgtState[i].H);
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
					ProcessLeaf(Input, InOffset + (i * Keccak::KECCAK_RATE256_SIZE), m_dgtState[i], PRCLEN);
				});

				Length -= PRCLEN;
				InOffset += PRCLEN;
			}

			if (Length >= m_parallelProfile.ParallelMinimumSize())
			{
				const size_t PRMLEN = Length - (Length % m_parallelProfile.ParallelMinimumSize());

				ParallelTools::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Input, InOffset, PRMLEN](size_t i)
				{
					ProcessLeaf(Input, InOffset + (i * Keccak::KECCAK_RATE256_SIZE), m_dgtState[i], PRMLEN);
				});

				Length -= PRMLEN;
				InOffset += PRMLEN;
			}
		}
		else
		{
			if (m_msgLength != 0 && (m_msgLength + Length >= Keccak::KECCAK_RATE256_SIZE))
			{
				const size_t RMDLEN = Keccak::KECCAK_RATE256_SIZE - m_msgLength;
				if (RMDLEN != 0)
				{
					MemoryTools::Copy(Input, InOffset, m_msgBuffer, m_msgLength, RMDLEN);
				}

				Keccak::Absorb(m_msgBuffer, 0, Keccak::KECCAK_RATE256_SIZE, m_dgtState[0].H);
				Permute(m_dgtState[0].H);
				m_msgLength = 0;
				InOffset += RMDLEN;
				Length -= RMDLEN;
			}

			// sequential loop through blocks
			while (Length >= Keccak::KECCAK_RATE256_SIZE)
			{
				Keccak::Absorb(Input, InOffset, Keccak::KECCAK_RATE256_SIZE, m_dgtState[0].H);
				Permute(m_dgtState[0].H);
				InOffset += Keccak::KECCAK_RATE256_SIZE;
				Length -= Keccak::KECCAK_RATE256_SIZE;
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

void Keccak256::Permute(std::array<ulong, 25> &Hash)
{
#if defined(CEX_DIGEST_COMPACT)
	Keccak::PermuteR24P1600C(Hash);
#else
	Keccak::PermuteR24P1600U(Hash);
#endif
}

void Keccak256::HashFinal(std::vector<byte> &Input, size_t InOffset, size_t Length, KeccakState &State)
{
	Input[InOffset + Length] = DOMAIN_CODE;
	Input[InOffset + Keccak::KECCAK_RATE256_SIZE - 1] |= 128;
	Keccak::Absorb(Input, InOffset, Keccak::KECCAK_RATE256_SIZE, State.H);
	Permute(State.H);
}

void Keccak256::ProcessLeaf(const std::vector<byte> &Input, size_t InOffset, KeccakState &State, ulong Length)
{
	do
	{
		Keccak::Absorb(Input, InOffset, Keccak::KECCAK_RATE256_SIZE, State.H);
		Permute(State.H);
		InOffset += m_parallelProfile.ParallelMinimumSize();
		Length -= m_parallelProfile.ParallelMinimumSize();
	} 
	while (Length > 0);
}

NAMESPACE_DIGESTEND
