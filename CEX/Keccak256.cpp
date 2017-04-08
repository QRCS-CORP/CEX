#include "Keccak256.h"
#include "Keccak.h"
#include "ArrayUtils.h"
#include "IntUtils.h"
#include "ParallelUtils.h"

NAMESPACE_DIGEST

using Utility::IntUtils;
using Utility::ParallelUtils;

//~~~Constructor~~~//

Keccak256::Keccak256(bool Parallel)
	:
	m_treeParams(DIGEST_SIZE, static_cast<uint>(BLOCK_SIZE), DEF_PRLDEGREE),
	m_isDestroyed(false),
	m_msgBuffer(Parallel ? DEF_PRLDEGREE * BLOCK_SIZE : BLOCK_SIZE),
	m_msgLength(0),
	m_parallelProfile(BLOCK_SIZE, false, STATE_PRECACHED, false, DEF_PRLDEGREE),
	m_dgtState(Parallel ? DEF_PRLDEGREE : 1)
{
	if (m_parallelProfile.IsParallel())
		m_parallelProfile.IsParallel() = Parallel;

	Reset();
}

Keccak256::Keccak256(KeccakParams &Params)
	:
	m_treeParams(Params),
	m_dgtState(1),
	m_isDestroyed(false),
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

	Reset();
}

Keccak256::~Keccak256()
{
	Destroy();
}

//~~~Public Functions~~~//

void Keccak256::Compute(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Output.resize(DIGEST_SIZE);
	Update(Input, 0, Input.size());
	Finalize(Output, 0);
}

void Keccak256::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_msgLength = 0;

		try
		{
			for (size_t i = 0; i < m_dgtState.size(); ++i)
				m_dgtState[i].Reset();

			Utility::ArrayUtils::ClearVector(m_dgtState);
			Utility::ArrayUtils::ClearVector(m_msgBuffer);
		}
		catch (std::exception& ex)
		{
			throw CryptoDigestException("Keccak256:Destroy", "Could not clear all variables!", std::string(ex.what()));
		}
	}
}

size_t Keccak256::Finalize(std::vector<byte> &Output, size_t OutOffset)
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
				HashFinal(m_msgBuffer, blkCtr * BLOCK_SIZE, MSGRMD, m_dgtState[blkCtr]);
				m_msgLength -= MSGRMD;
				++blkCtr;
			}
		}

		// initialize root state
		Keccak256State rootState;

		// add state blocks as contiguous message input
		for (size_t i = 0; i < m_dgtState.size(); ++i)
		{
			IntUtils::LeULL256ToBlock(m_dgtState[i].H, m_msgBuffer, i * BLOCK_SIZE);
			m_msgLength += DIGEST_SIZE;
		}

		// compress full blocks
		size_t blkOff = 0;
		if (m_msgLength > BLOCK_SIZE)
		{
			const size_t BLKRMD = m_msgLength - (m_msgLength % BLOCK_SIZE);

			for (size_t i = 0; i < BLKRMD / BLOCK_SIZE; ++i)
				Compress(m_msgBuffer, i * BLOCK_SIZE, rootState);

			m_msgLength -= BLKRMD;
			blkOff = BLKRMD;
		}

		// finalize and store
		HashFinal(m_msgBuffer, blkOff, m_msgLength, rootState);
		IntUtils::LeULL256ToBlock(rootState.H, Output, OutOffset);
	}
	else
	{
		if (m_msgLength != m_msgBuffer.size())
			memset(&m_msgBuffer[m_msgLength], (byte)0, m_msgBuffer.size() - m_msgLength);

		HashFinal(m_msgBuffer, 0, m_msgLength, m_dgtState[0]);
		IntUtils::LeULL256ToBlock(m_dgtState[0].H, Output, OutOffset);
	}

	Reset();

	return DIGEST_SIZE;
}

void Keccak256::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0)
		throw CryptoDigestException("Skein256:ParallelMaxDegree", "Parallel degree can not be zero!");
	if (Degree > 254)
		throw CryptoDigestException("Skein256:ParallelMaxDegree", "Parallel degree can not exceed 254!");
	if (Degree % 2 != 0)
		throw CryptoDigestException("Skein256:ParallelMaxDegree", "Parallel degree must be an even number!");

	m_parallelProfile.SetMaxDegree(Degree);
	//m_dgtState.clear();
	//m_dgtState.resize(Degree);
	//m_msgBuffer.clear();
	//m_msgBuffer.resize(Degree * BLOCK_SIZE);
	//m_treeParams = { DIGEST_SIZE, static_cast<byte>(BLOCK_SIZE), static_cast<byte>(Degree) };

	Reset();
}

void Keccak256::Reset()
{
	memset(&m_msgBuffer[0], (byte)0, m_msgBuffer.size());
	m_msgLength = 0;

	for (size_t i = 0; i < m_dgtState.size(); ++i)
	{
		m_dgtState[i].Reset();

		if (m_parallelProfile.IsParallel())
		{
			m_treeParams.NodeOffset() = static_cast<uint>(i);
			Compress(m_treeParams.ToBytes(), 0, m_dgtState[i]);
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
				Compress(m_msgBuffer, i * BLOCK_SIZE, m_dgtState[i]);
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
			const size_t RMDLEN = BLOCK_SIZE - m_msgLength;
			if (RMDLEN != 0)
				memcpy(&m_msgBuffer[m_msgLength], &Input[InOffset], RMDLEN);

			Compress(m_msgBuffer, 0, m_dgtState[0]);
			m_msgLength = 0;
			InOffset += RMDLEN;
			Length -= RMDLEN;
		}

		// sequential loop through blocks
		while (Length >= BLOCK_SIZE)
		{
			Compress(Input, InOffset, m_dgtState[0]);
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

void Keccak256::Compress(const std::vector<byte> &Input, size_t InOffset, Keccak256State &State)
{
	Keccak::Compress(Input, InOffset, BLOCK_SIZE, State.H);
}

void Keccak256::HashFinal(std::vector<byte> &Input, size_t InOffset, size_t Length, Keccak256State &State)
{
	Input[InOffset + Length] = 1;
	Input[InOffset + BLOCK_SIZE - 1] |= 128;
	Compress(Input, InOffset, State);

	State.H[1] = ~State.H[1];
	State.H[2] = ~State.H[2];
	State.H[8] = ~State.H[8];
	State.H[12] = ~State.H[12];
	State.H[17] = ~State.H[17];
}

void Keccak256::ProcessLeaf(const std::vector<byte> &Input, size_t InOffset, Keccak256State &State, ulong Length)
{
	do
	{
		Compress(Input, InOffset, State);
		InOffset += m_parallelProfile.ParallelMinimumSize();
		Length -= m_parallelProfile.ParallelMinimumSize();
	} 
	while (Length > 0);
}

NAMESPACE_DIGESTEND