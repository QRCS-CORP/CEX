#include "Keccak1024.h"
#include "Keccak.h"
#include "IntUtils.h"
#include "MemUtils.h"
#include "ParallelUtils.h"

NAMESPACE_DIGEST

using Utility::IntUtils;
using Utility::MemUtils;
using Utility::ParallelUtils;

const std::string Keccak1024::CLASS_NAME("Keccak1024");

//~~~Constructor~~~//

Keccak1024::Keccak1024(bool Parallel)
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
		throw CryptoDigestException("Keccak1024::Ctor", "Cpu does not support parallel processing!");
	}

	if (m_parallelProfile.IsParallel())
	{
		m_parallelProfile.IsParallel() = Parallel;
	}

	Reset();
}

Keccak1024::Keccak1024(KeccakParams &Params)
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
		throw CryptoDigestException("Keccak1024::Ctor", "Cpu does not support parallel processing!");
	}
	if (m_parallelProfile.IsParallel() && m_treeParams.FanOut() > m_parallelProfile.ParallelMaxDegree())
	{
		throw CryptoDigestException("Keccak1024::Ctor", "The tree parameters are invalid!");
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

Keccak1024::~Keccak1024()
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

size_t Keccak1024::BlockSize()
{
	return BLOCK_SIZE;
}

size_t Keccak1024::DigestSize()
{
	return DIGEST_SIZE;
}

const Digests Keccak1024::Enumeral()
{
	return Digests::Keccak1024;
}

const bool Keccak1024::IsParallel()
{
	return m_parallelProfile.IsParallel();
}

const std::string Keccak1024::Name()
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

const size_t Keccak1024::ParallelBlockSize()
{
	return m_parallelProfile.ParallelBlockSize();
}

ParallelOptions &Keccak1024::ParallelProfile()
{
	return m_parallelProfile;
}

//~~~Public Functions~~~//

void Keccak1024::Compute(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Output.resize(DIGEST_SIZE);
	Update(Input, 0, Input.size());
	Finalize(Output, 0);
}

size_t Keccak1024::Finalize(std::vector<byte> &Output, const size_t OutOffset)
{
	const size_t OUTLEN = Output.size() - OutOffset;

	if (m_parallelProfile.IsParallel())
	{
		// pad buffer with zeros
		if (m_msgLength < m_msgBuffer.size())
		{
			MemUtils::Clear(m_msgBuffer, m_msgLength, m_msgBuffer.size() - m_msgLength);
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
		m_msgBuffer.resize(m_dgtState.size() * DIGEST_SIZE, 0);

		// add state blocks as contiguous message input
		for (size_t i = 0; i < m_dgtState.size(); ++i)
		{
			IntUtils::LeULL1024ToBlock(m_dgtState[i].H, 0, m_msgBuffer, i * DIGEST_SIZE);
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
				Permute(rootState.H);
			}

			m_msgLength -= BLKRMD;
			blkOff = BLKRMD;
		}

		// finalize and store
		std::vector<byte> tmpH(BLOCK_SIZE, 0);
		MemUtils::Copy(m_msgBuffer, blkOff, tmpH, 0, m_msgLength);
		HashFinal(tmpH, 0, m_msgLength, rootState);

		if (OUTLEN >= DIGEST_SIZE)
		{
			IntUtils::LeULL1024ToBlock(rootState.H, 0, Output, OutOffset);
		}
		else
		{
			for (size_t i = 0; i < OUTLEN / sizeof(ulong); ++i)
			{
				IntUtils::Le64ToBytes(rootState.H[i], Output, OutOffset + i * sizeof(ulong));
			}
		}
	}
	else
	{
		if (m_msgLength != m_msgBuffer.size())
		{
			MemUtils::Clear(m_msgBuffer, m_msgLength, m_msgBuffer.size() - m_msgLength);
		}

		HashFinal(m_msgBuffer, 0, m_msgLength, m_dgtState[0]);

		if (OUTLEN >= DIGEST_SIZE)
		{
			IntUtils::LeULL1024ToBlock(m_dgtState[0].H, 0, Output, OutOffset);
		}
		else
		{
			for (size_t i = 0; i < OUTLEN / sizeof(ulong); ++i)
			{
				IntUtils::Le64ToBytes(m_dgtState[0].H[i], Output, OutOffset + (i * sizeof(ulong)));
			}
		}
	}

	Reset();

	return (OUTLEN >= DIGEST_SIZE) ? DIGEST_SIZE : OUTLEN;
}

void Keccak1024::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0 || Degree % 2 != 0 || Degree > m_parallelProfile.ProcessorCount())
	{
		throw CryptoDigestException("Keccak1024::ParallelMaxDegree", "Degree setting is invalid!");
	}

	m_parallelProfile.SetMaxDegree(Degree);

	Reset();
}

void Keccak1024::Reset()
{
	MemUtils::Clear(m_msgBuffer, 0, m_msgBuffer.size());
	m_msgLength = 0;

	for (size_t i = 0; i < m_dgtState.size(); ++i)
	{
		m_dgtState[i].Reset();

		if (m_parallelProfile.IsParallel())
		{
			m_treeParams.NodeOffset() = static_cast<uint>(i);
			Absorb(m_treeParams.ToBytes(), 0, BLOCK_SIZE, m_dgtState[i]);
			Permute(m_dgtState[i].H);
		}
	}
}

void Keccak1024::Update(byte Input)
{
	std::vector<byte> one(1, Input);
	Update(one, 0, 1);
}

void Keccak1024::Update(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	CexAssert(Input.size() - InOffset >= Length, "The Output buffer is too short!");

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
					MemUtils::Copy(Input, InOffset, m_msgBuffer, m_msgLength, RMDLEN);
				}

				// empty the message buffer
				ParallelUtils::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Input, InOffset](size_t i)
				{
					Absorb(m_msgBuffer, i * BLOCK_SIZE, BLOCK_SIZE, m_dgtState[i]);
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
				ParallelUtils::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Input, InOffset, PRCLEN](size_t i)
				{
					ProcessLeaf(Input, InOffset + (i * BLOCK_SIZE), m_dgtState[i], PRCLEN);
				});

				Length -= PRCLEN;
				InOffset += PRCLEN;
			}

			if (Length >= m_parallelProfile.ParallelMinimumSize())
			{
				const size_t PRMLEN = Length - (Length % m_parallelProfile.ParallelMinimumSize());

				ParallelUtils::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Input, InOffset, PRMLEN](size_t i)
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
				const size_t RMDLEN = BLOCK_SIZE - m_msgLength;
				if (RMDLEN != 0)
				{
					MemUtils::Copy(Input, InOffset, m_msgBuffer, m_msgLength, RMDLEN);
				}


				Absorb(m_msgBuffer, 0, BLOCK_SIZE, m_dgtState[0]);
				Permute(m_dgtState[0].H);
				m_msgLength = 0;
				InOffset += RMDLEN;
				Length -= RMDLEN;
			}

			// sequential loop through blocks
			while (Length >= BLOCK_SIZE)
			{
				Absorb(Input, InOffset, BLOCK_SIZE, m_dgtState[0]);
				Permute(m_dgtState[0].H);
				InOffset += BLOCK_SIZE;
				Length -= BLOCK_SIZE;
			}
		}

		// store unaligned bytes
		if (Length != 0)
		{
			MemUtils::Copy(Input, InOffset, m_msgBuffer, m_msgLength, Length);
			m_msgLength += Length;
		}
	}
}

//~~~Private Functions~~~//

void Keccak1024::Absorb(const std::vector<byte> &Input, size_t InOffset, size_t Length, KeccakState &State)
{
	for (size_t i = 0; i < Length / sizeof(ulong); ++i)
	{
		State.H[i] ^= IntUtils::LeBytesTo64(Input, InOffset + (i * sizeof(ulong)));
	}
}

void Keccak1024::Permute(std::array<ulong, 25> &Hash)
{
#if defined(CEX_DIGEST_COMPACT)
	Keccak::PermuteR48P1600C(Hash);
#else
	Keccak::PermuteR48P1600U(Hash);
#endif
}

void Keccak1024::HashFinal(std::vector<byte> &Input, size_t InOffset, size_t Length, KeccakState &State)
{
	Input[InOffset + Length] = DOMAIN_CODE;
	Input[InOffset + BLOCK_SIZE - 1] |= 128;
	Absorb(Input, InOffset, BLOCK_SIZE, State);
	Permute(State.H);
}

void Keccak1024::ProcessLeaf(const std::vector<byte> &Input, size_t InOffset, KeccakState &State, ulong Length)
{
	do
	{
		Absorb(Input, InOffset, BLOCK_SIZE, State);
		Permute(State.H);
		InOffset += m_parallelProfile.ParallelMinimumSize();
		Length -= m_parallelProfile.ParallelMinimumSize();
	} 
	while (Length > 0);
}

NAMESPACE_DIGESTEND
