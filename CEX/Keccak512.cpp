#include "Keccak512.h"
#include "Keccak.h"
#include "ParallelUtils.h"

NAMESPACE_DIGEST

using Utility::IntUtils;

const std::string Keccak512::CLASS_NAME("Keccak512");

//~~~Constructor~~~//

Keccak512::Keccak512(bool Parallel)
	:
	m_dgtState(Parallel ? DEF_PRLDEGREE : 1),
	m_isDestroyed(false),
	m_msgBuffer(Parallel ? DEF_PRLDEGREE * BLOCK_SIZE : BLOCK_SIZE),
	m_msgLength(0),
	m_parallelProfile(BLOCK_SIZE, false, STATE_PRECACHED, false, DEF_PRLDEGREE),
	m_treeDestroy(true),
	m_treeParams(Parallel ? KeccakParams(DIGEST_SIZE, static_cast<byte>(BLOCK_SIZE), DEF_PRLDEGREE) : KeccakParams(DIGEST_SIZE, 0, 0))
{
	// TODO: implement parallel alternate for single core cpu
	if (Parallel && !m_parallelProfile.IsParallel())
	{
		throw CryptoDigestException("Keccak512::Ctor", "Cpu does not support parallel processing!");
	}

	if (m_parallelProfile.IsParallel())
	{
		m_parallelProfile.IsParallel() = Parallel;
	}

	Reset();
}

Keccak512::Keccak512(KeccakParams &Params)
	:
	m_dgtState(1),
	m_isDestroyed(false),
	m_msgBuffer(BLOCK_SIZE),
	m_msgLength(0),
	m_parallelProfile(BLOCK_SIZE, false, STATE_PRECACHED, false, m_treeParams.FanOut()),
	m_treeDestroy(false),
	m_treeParams(Params)
{
	if (m_treeParams.FanOut() > 1 && !m_parallelProfile.IsParallel())
	{
		throw CryptoDigestException("Keccak512::Ctor", "Cpu does not support parallel processing!");
	}

	if (m_treeParams.FanOut() > 1 && m_parallelProfile.IsParallel())
	{
		m_dgtState.resize(m_treeParams.FanOut());
		m_msgBuffer.resize(m_treeParams.FanOut() * BLOCK_SIZE);
	}
	else if (m_parallelProfile.IsParallel())
	{
		m_parallelProfile.IsParallel() = false;
	}

	Reset();
}

Keccak512::~Keccak512()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_msgLength = 0;
		m_parallelProfile.Reset();

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

size_t Keccak512::BlockSize() 
{ 
	return BLOCK_SIZE; 
}

size_t Keccak512::DigestSize() 
{ 
	return DIGEST_SIZE; 
}

const Digests Keccak512::Enumeral() 
{
	return Digests::Keccak512;
}

const bool Keccak512::IsParallel() 
{
	return m_parallelProfile.IsParallel(); 
}

const std::string Keccak512::Name() 
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

const size_t Keccak512::ParallelBlockSize() 
{ 
	return m_parallelProfile.ParallelBlockSize(); 
}

ParallelOptions &Keccak512::ParallelProfile() 
{ 
	return m_parallelProfile; 
}

//~~~Public Functions~~~//

void Keccak512::Compute(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Output.resize(DIGEST_SIZE);
	Update(Input, 0, Input.size());
	Finalize(Output, 0);
}

size_t Keccak512::Finalize(std::vector<byte> &Output, const size_t OutOffset)
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
				HashFinal(m_msgBuffer, blkCtr * BLOCK_SIZE, MSGRMD, m_dgtState[blkCtr]);
				m_msgLength -= MSGRMD;
				++blkCtr;
			}
		}

		// initialize root state
		KeccakState rootState;

		// add state blocks as contiguous message input
		for (size_t i = 0; i < m_dgtState.size(); ++i)
		{
			IntUtils::LeULL512ToBlock(m_dgtState[i].H, 0, m_msgBuffer, i * DIGEST_SIZE);
			m_msgLength += DIGEST_SIZE;
		}

		// compress full blocks
		size_t blkOff = 0;
		if (m_msgLength > BLOCK_SIZE)
		{
			const size_t BLKRMD = m_msgLength - (m_msgLength % BLOCK_SIZE);

			for (size_t i = 0; i < BLKRMD / BLOCK_SIZE; ++i)
			{
				Absorb(m_msgBuffer, i * BLOCK_SIZE, BLOCK_SIZE, rootState);
				Keccak::PermuteR24P1600(rootState.H);
			}

			m_msgLength -= BLKRMD;
			blkOff = BLKRMD;
		}

		// finalize and store
		HashFinal(m_msgBuffer, blkOff, m_msgLength, rootState);
		IntUtils::LeULL512ToBlock(rootState.H, 0, Output, OutOffset);
	}
	else
	{

		if (m_msgLength != m_msgBuffer.size())
		{
			Utility::MemUtils::Clear(m_msgBuffer, m_msgLength, m_msgBuffer.size() - m_msgLength);
		}

		HashFinal(m_msgBuffer, 0, m_msgLength, m_dgtState[0]);
		IntUtils::LeULL512ToBlock(m_dgtState[0].H, 0, Output, OutOffset);
	}

	Reset();

	return DIGEST_SIZE;
}

void Keccak512::ParallelMaxDegree(size_t Degree)
{
	CexAssert(Degree != 0, "parallel degree can not be zero");
	CexAssert(Degree % 2 == 0, "parallel degree must be an even number");
	CexAssert(Degree <= m_parallelProfile.ProcessorCount(), "parallel degree can not exceed processor count");

	m_parallelProfile.SetMaxDegree(Degree);
	Reset();
}

void Keccak512::Reset()
{
	Utility::MemUtils::Clear(m_msgBuffer, 0, m_msgBuffer.size());
	m_msgLength = 0;

	for (size_t i = 0; i < m_dgtState.size(); ++i)
	{
		m_dgtState[i].Reset();

		if (m_parallelProfile.IsParallel())
		{
			m_treeParams.NodeOffset() = static_cast<uint>(i);
			Absorb(m_treeParams.ToBytes(), 0, BLOCK_SIZE, m_dgtState[i]);
			Keccak::PermuteR24P1600(m_dgtState[i].H);
		}
	}
}

void Keccak512::Update(byte Input)
{
	std::vector<byte> one(1, Input);
	Update(one, 0, 1);
}

void Keccak512::Update(const std::vector<byte> &Input, size_t InOffset, size_t Length)
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
					Absorb(m_msgBuffer, i * BLOCK_SIZE, BLOCK_SIZE, m_dgtState[i]);
					Keccak::PermuteR24P1600(m_dgtState[i].H);
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
					ProcessLeaf(Input, InOffset + (i * BLOCK_SIZE), m_dgtState[i], PRCLEN);
				});

				Length -= PRCLEN;
				InOffset += PRCLEN;
			}

			if (Length >= m_parallelProfile.ParallelMinimumSize())
			{
				const size_t PRMLEN = Length - (Length % m_parallelProfile.ParallelMinimumSize());

				Utility::ParallelUtils::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Input, InOffset, PRMLEN](size_t i)
				{
					ProcessLeaf(Input, InOffset + (i * BLOCK_SIZE), m_dgtState[i], PRMLEN);
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

				Absorb(m_msgBuffer, 0, BLOCK_SIZE, m_dgtState[0]);
				Keccak::PermuteR24P1600(m_dgtState[0].H);
				m_msgLength = 0;
				InOffset += RMDSZE;
				Length -= RMDSZE;
			}

			// sequential loop through blocks
			while (Length >= BLOCK_SIZE)
			{
				Absorb(Input, InOffset, BLOCK_SIZE, m_dgtState[0]);
				Keccak::PermuteR24P1600(m_dgtState[0].H);
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

void Keccak512::Absorb(const std::vector<byte> &Input, size_t InOffset, size_t Length, KeccakState &State)
{
	for (size_t i = 0; i < Length / sizeof(ulong); ++i)
	{
		State.H[i] ^= IntUtils::LeBytesTo64(Input, InOffset + (i * sizeof(ulong)));
	}
}

void Keccak512::HashFinal(std::vector<byte> &Input, size_t InOffset, size_t Length, KeccakState &State)
{
	Input[InOffset + Length] = DOMAIN_CODE;
	Input[InOffset + BLOCK_SIZE - 1] |= 128;
	Absorb(Input, InOffset, BLOCK_SIZE, State);
	Keccak::PermuteR24P1600(State.H);
}

void Keccak512::ProcessLeaf(const std::vector<byte> &Input, size_t InOffset, KeccakState &State, ulong Length)
{
	do
	{
		Absorb(Input, InOffset, BLOCK_SIZE, State);
		Keccak::PermuteR24P1600(State.H);
		InOffset += m_parallelProfile.ParallelMinimumSize();
		Length -= m_parallelProfile.ParallelMinimumSize();
	} 
	while (Length > 0);
}

NAMESPACE_DIGESTEND
