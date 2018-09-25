#include "SHA512.h"
#include "SHA2.h"
#include "IntUtils.h"
#include "MemUtils.h"
#include "ParallelUtils.h"

NAMESPACE_DIGEST

using Utility::IntUtils;
using Utility::MemUtils;
using Utility::ParallelUtils;

const std::string SHA512::CLASS_NAME("SHA512");

//~~~Constructor~~~//

SHA512::SHA512(bool Parallel)
	:
	m_dgtState(Parallel ? DEF_PRLDEGREE : 1),
	m_isDestroyed(false),
	m_msgBuffer(Parallel ? DEF_PRLDEGREE * BLOCK_SIZE : BLOCK_SIZE),
	m_msgLength(0),
	m_parallelProfile(BLOCK_SIZE, false, STATE_PRECACHED, false, DEF_PRLDEGREE),
	m_treeDestroy(true),
	m_treeParams(Parallel ? SHA2Params(DIGEST_SIZE, static_cast<byte>(BLOCK_SIZE), DEF_PRLDEGREE) : SHA2Params(DIGEST_SIZE, 0, 0))
{
	// TODO: implement parallel alternate for single core cpu
	if (Parallel && !m_parallelProfile.IsParallel())
	{
		throw CryptoDigestException("SHA512::Ctor", "Cpu does not support parallel processing!");
	}

	if (m_parallelProfile.IsParallel())
	{
		m_parallelProfile.IsParallel() = Parallel;
	}

	Reset();
}

SHA512::SHA512(SHA2Params &Params)
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
		throw CryptoDigestException("SHA512::Ctor", "Cpu does not support parallel processing!");
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

SHA512::~SHA512()
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

size_t SHA512::BlockSize() 
{ 
	return BLOCK_SIZE; 
}

size_t SHA512::DigestSize() 
{ 
	return DIGEST_SIZE; 
}

const Digests SHA512::Enumeral()
{ 
	return Digests::SHA512; 
}

const bool SHA512::IsParallel() 
{ 
	return m_parallelProfile.IsParallel(); 
}

const std::string SHA512::Name() 
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

const size_t SHA512::ParallelBlockSize() 
{ 
	return m_parallelProfile.ParallelBlockSize(); 
}

ParallelOptions &SHA512::ParallelProfile()
{
	return m_parallelProfile; 
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

		for (size_t i = 0; i < m_dgtState.size(); ++i)
		{
			m_dgtState[i].Reset();
		}

		IntUtils::ClearVector(m_dgtState);
		IntUtils::ClearVector(m_msgBuffer);
	}
}

size_t SHA512::Finalize(std::vector<byte> &Output, const size_t OutOffset)
{
	CexAssert(Output.size() - OutOffset >= DIGEST_SIZE, "The Output buffer is too short!");

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
		SHA512State rootState;
		rootState.Reset();

		// add state blocks as contiguous message input
		for (size_t i = 0; i < m_dgtState.size(); ++i)
		{
			IntUtils::BeULL512ToBlock(m_dgtState[i].H, 0, m_msgBuffer, i * BLOCK_SIZE);
			m_msgLength += DIGEST_SIZE;
		}

		// compress full blocks
		size_t blkOff = 0;
		if (m_msgLength > BLOCK_SIZE)
		{
			const size_t BLKRMD = m_msgLength - (m_msgLength % BLOCK_SIZE);

			for (size_t i = 0; i < BLKRMD / BLOCK_SIZE; ++i)
			{
				Permute(m_msgBuffer, i * BLOCK_SIZE, rootState);
			}

			m_msgLength -= BLKRMD;
			blkOff = BLKRMD;
		}

		// finalize and store
		HashFinal(m_msgBuffer, blkOff, m_msgLength, rootState);
		IntUtils::BeULL512ToBlock(rootState.H, 0, Output, OutOffset);
	}
	else
	{
		// finalize and store
		HashFinal(m_msgBuffer, 0, m_msgLength, m_dgtState[0]);
		IntUtils::BeULL512ToBlock(m_dgtState[0].H, 0, Output, OutOffset);
	}

	Reset();

	return DIGEST_SIZE;
}

void SHA512::ParallelMaxDegree(size_t Degree)
{
	CexAssert(Degree != 0, "parallel degree can not be zero");
	CexAssert(Degree % 2 == 0, "parallel degree must be an even number");
	CexAssert(Degree <= m_parallelProfile.ProcessorCount(), "parallel degree can not exceed processor count");

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
	MemUtils::Clear(m_msgBuffer, 0, m_msgBuffer.size());

	for (size_t i = 0; i < m_dgtState.size(); ++i)
	{
		m_dgtState[i].Reset();

		if (m_parallelProfile.IsParallel())
		{
			m_treeParams.NodeOffset() = static_cast<uint>(i);
			Permute(m_treeParams.ToBytes(), 0, m_dgtState[i]);
		}
	}
}

void SHA512::Update(byte Input)
{
	std::vector<byte> inp(1, Input);
	Update(inp, 0, 1);
}

void SHA512::Update(const std::vector<byte> &Input, size_t InOffset, size_t Length)
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
					Permute(m_msgBuffer, i * BLOCK_SIZE, m_dgtState[i]);
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

				Permute(m_msgBuffer, 0, m_dgtState[0]);
				m_msgLength = 0;
				InOffset += RMDLEN;
				Length -= RMDLEN;
			}

			// sequential loop through blocks
			while (Length > BLOCK_SIZE)
			{
				Permute(Input, InOffset, m_dgtState[0]);
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

void SHA512::HashFinal(std::vector<byte> &Input, size_t InOffset, size_t Length, SHA512State &State)
{
	State.Increase(Length);
	ulong bitLen = (State.T[0] << 3);

	if (Length == BLOCK_SIZE)
	{
		Permute(Input, InOffset, State);
		Length = 0;
	}

	Input[InOffset + Length] = 128;
	++Length;

	// padding
	if (Length < BLOCK_SIZE)
	{
		MemUtils::Clear(Input, InOffset + Length, BLOCK_SIZE - Length);
	}

	if (Length > 112)
	{
		Permute(Input, InOffset, State);
		MemUtils::Clear(Input, InOffset, BLOCK_SIZE);
	}

	// finalize state with counter and last compression
	IntUtils::Be64ToBytes(State.T[1], Input, InOffset + 112);
	IntUtils::Be64ToBytes(bitLen, Input, InOffset + 120);
	Permute(Input, InOffset, State);
}

void SHA512::Permute(const std::vector<byte> &Input, size_t InOffset, SHA512State &State)
{
#if defined(CEX_DIGEST_COMPACT)
	SHA2::PermuteR80P1024C(Input, InOffset, State.H);
#else
	SHA2::PermuteR80P1024U(Input, InOffset, State.H);
#endif

	State.Increase(BLOCK_SIZE);
}

void SHA512::ProcessLeaf(const std::vector<byte> &Input, size_t InOffset, SHA512State &State, ulong Length)
{
	do
	{
		Permute(Input, InOffset, State);
		InOffset += m_parallelProfile.ParallelMinimumSize();
		Length -= m_parallelProfile.ParallelMinimumSize();
	} 
	while (Length > 0);
}

NAMESPACE_DIGESTEND
