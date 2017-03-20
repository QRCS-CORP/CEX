#include "SHA512.h"
#include "ArrayUtils.h"
#include "IntUtils.h"
#include "ParallelUtils.h"
#include "SHA512Compress.h"

NAMESPACE_DIGEST

using Utility::IntUtils;
using Utility::ParallelUtils;

//~~~Constructor~~~//

SHA512::SHA512(bool Parallel)
	:
	m_dstCode(0),
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

SHA512::~SHA512()
{
	Destroy();
}

//~~~Public Functions~~~//

void SHA512::Compute(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Output.resize(DIGEST_SIZE);
	Update(Input, 0, Input.size());
	Finalize(Output, 0);
}

void SHA512::Destroy()
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
			throw CryptoDigestException("SHA512:Destroy", "Could not clear all variables!", std::string(ex.what()));
		}
	}
}

size_t SHA512::Finalize(std::vector<byte> &Output, const size_t OutOffset)
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
		SHA512State rootState;
		LoadState(rootState);

		// add state blocks as contiguous message input
		for (size_t i = 0; i < m_dgtState.size(); ++i)
		{
			IntUtils::BeULL512ToBlock(m_dgtState[i].H, m_msgBuffer, i * BLOCK_SIZE);
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
		IntUtils::BeULL512ToBlock(rootState.H, Output, OutOffset);
	}
	else
	{
		// finalize and store
		HashFinal(m_msgBuffer, 0, m_msgLength, m_dgtState[0]);
		IntUtils::BeULL512ToBlock(m_dgtState[0].H, Output, OutOffset);
	}

	Reset();

	return DIGEST_SIZE;
}

void SHA512::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0)
		throw CryptoDigestException("SHA512:ParallelMaxDegree", "Parallel degree can not be zero!");
	if (Degree > 254)
		throw CryptoDigestException("SHA512:ParallelMaxDegree", "Parallel degree can not exceed 254!");
	if (Degree % 2 != 0)
		throw CryptoDigestException("SHA512:ParallelMaxDegree", "Parallel degree must be an even number!");

	m_parallelProfile.SetMaxDegree(Degree);
	m_dgtState.clear();
	m_dgtState.resize(Degree);
	m_msgBuffer.clear();
	m_msgBuffer.resize(Degree * BLOCK_SIZE);

	Reset();
}

void SHA512::Reset()
{
	m_msgLength = 0;
	memset(&m_msgBuffer[0], 0, m_msgBuffer.size());

	for (size_t i = 0; i < m_dgtState.size(); ++i)
		LoadState(m_dgtState[i]);

	if (m_dstCode.size() != 0)
		Compress(m_dstCode, 0, m_dgtState[0]);
}

void SHA512::Update(byte Input)
{
	std::vector<byte> inp(1, Input);
	Update(inp, 0, 1);
}

void SHA512::Update(const std::vector<byte> &Input, size_t InOffset, size_t Length)
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
			size_t rmd = BLOCK_SIZE - m_msgLength;
			if (rmd != 0)
				memcpy(&m_msgBuffer[m_msgLength], &Input[InOffset], rmd);

			Compress(m_msgBuffer, 0, m_dgtState[0]);
			m_msgLength = 0;
			InOffset += rmd;
			Length -= rmd;
		}

		// sequential loop through blocks
		while (Length > BLOCK_SIZE)
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

void SHA512::Compress(const std::vector<byte> &Input, size_t InOffset, SHA512State &State)
{
	SHA512Compress::Compress128(Input, InOffset, State);
}

void SHA512::HashFinal(std::vector<byte> &Input, size_t InOffset, size_t Length, SHA512State &State)
{
	State.Increase(Length);
	ulong bitLen = (State.T[0] << 3);

	if (Length == BLOCK_SIZE)
	{
		SHA512Compress::Compress128(Input, InOffset, State);
		Length = 0;
	}

	Input[InOffset + Length] = (byte)128;
	++Length;

	// padding
	if (Length < BLOCK_SIZE)
		memset(&Input[InOffset + Length], 0, BLOCK_SIZE - Length);

	if (Length > 112)
	{
		SHA512Compress::Compress128(Input, InOffset, State);
		memset(&Input[InOffset], 0, BLOCK_SIZE);
	}

	// finalize state with counter and last compression
	IntUtils::Be64ToBytes(State.T[1], Input, InOffset + 112);
	IntUtils::Be64ToBytes(bitLen, Input, InOffset + 120);
	SHA512Compress::Compress128(Input, InOffset, State);
}

void SHA512::LoadState(SHA512State &State)
{
	State.T[0] = 0;
	State.T[1] = 0;
	State.H[0] = 0x6a09e667f3bcc908;
	State.H[1] = 0xbb67ae8584caa73b;
	State.H[2] = 0x3c6ef372fe94f82b;
	State.H[3] = 0xa54ff53a5f1d36f1;
	State.H[4] = 0x510e527fade682d1;
	State.H[5] = 0x9b05688c2b3e6c1f;
	State.H[6] = 0x1f83d9abfb41bd6b;
	State.H[7] = 0x5be0cd19137e2179;
}

void SHA512::ProcessLeaf(const std::vector<byte> &Input, size_t InOffset, SHA512State &State, ulong Length)
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