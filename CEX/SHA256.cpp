#include "SHA256.h"
#include "SHA2.h"
#include "IntegerTools.h"
#include "MemoryTools.h"
#include "ParallelTools.h"
#if defined(__AVX__)
#	include "Intrinsics.h"
#endif

NAMESPACE_DIGEST

using Utility::IntegerTools;
using Utility::MemoryTools;
using Utility::ParallelTools;

const std::string SHA256::CLASS_NAME("SHA256");

//~~~Constructor~~~//

SHA256::SHA256(bool Parallel)
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
	m_parallelProfile.IsParallel() = (m_parallelProfile.IsParallel() == true) ? Parallel : false;

	Reset();
}

SHA256::SHA256(SHA2Params &Params)
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
		throw CryptoDigestException(CLASS_NAME, std::string("Constructor"), std::string("Cpu does not support parallel processing!"), ErrorCodes::NotSupported);
	}
	if (m_parallelProfile.IsParallel() && m_treeParams.FanOut() > m_parallelProfile.ParallelMaxDegree())
	{
		throw CryptoDigestException(CLASS_NAME, std::string("Constructor"), std::string("The tree parameters are invalid!"), ErrorCodes::InvalidParam);
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

SHA256::~SHA256()
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

		IntegerTools::Clear(m_msgBuffer);
		IntegerTools::Clear(m_dgtState);
	}
}

//~~~Accessors~~~//

size_t SHA256::BlockSize() 
{ 
	return BLOCK_SIZE; 
}

size_t SHA256::DigestSize() 
{ 
	return DIGEST_SIZE;
}

const Digests SHA256::Enumeral() 
{
	return Digests::SHA256; 
}

const bool SHA256::IsParallel()
{ 
	return m_parallelProfile.IsParallel(); 
}

const std::string SHA256::Name()
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

const size_t SHA256::ParallelBlockSize()
{ 
	return m_parallelProfile.ParallelBlockSize(); 
}

ParallelOptions &SHA256::ParallelProfile() 
{ 
	return m_parallelProfile; 
}

//~~~Public Functions~~~//

void SHA256::Compute(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Output.resize(DIGEST_SIZE);
	Update(Input, 0, Input.size());
	Finalize(Output, 0);
}

size_t SHA256::Finalize(std::vector<byte> &Output, const size_t OutOffset)
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
				const size_t MSGRMD = (m_msgLength >= BLOCK_SIZE) ? BLOCK_SIZE : m_msgLength;
				HashFinal(m_msgBuffer, blkCtr * BLOCK_SIZE, MSGRMD, m_dgtState[blkCtr]);
				m_msgLength -= MSGRMD;
				++blkCtr;
			}
		}

		// initialize root state
		SHA256State rootState;
		rootState.Reset();

		// add state blocks as contiguous message input
		for (size_t i = 0; i < m_dgtState.size(); ++i)
		{
			IntegerTools::BeUL256ToBlock(m_dgtState[i].H, 0, m_msgBuffer, i * BLOCK_SIZE);
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
		IntegerTools::BeUL256ToBlock(rootState.H, 0, Output, OutOffset);
	}
	else
	{
		// finalize and store
		HashFinal(m_msgBuffer, 0, m_msgLength, m_dgtState[0]);
		IntegerTools::BeUL256ToBlock(m_dgtState[0].H, 0, Output, OutOffset);
	}

	Reset();

	return DIGEST_SIZE;
}

void SHA256::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0 || Degree % 2 != 0 || Degree > m_parallelProfile.ProcessorCount())
	{
		throw CryptoDigestException(Name(), std::string("ParallelMaxDegree"), std::string("Degree setting is invalid!"), ErrorCodes::NotSupported);
	}

	m_parallelProfile.SetMaxDegree(Degree);

	Reset();
}

void SHA256::Reset()
{
	std::vector<byte> params(BLOCK_SIZE);

	m_dgtState.clear();
	m_dgtState.resize(m_parallelProfile.IsParallel() ? m_parallelProfile.ParallelMaxDegree() : 1);
	m_msgBuffer.clear();
	m_msgBuffer.resize(m_parallelProfile.IsParallel() ? m_parallelProfile.ParallelMaxDegree() * BLOCK_SIZE : BLOCK_SIZE);
	m_msgLength = 0;

	for (size_t i = 0; i < m_dgtState.size(); ++i)
	{
		m_dgtState[i].Reset();

		if (m_parallelProfile.IsParallel())
		{
			m_treeParams.NodeOffset() = static_cast<uint>(i);
			MemoryTools::Copy(m_treeParams.ToBytes(), 0, params, 0, params.size());
			Permute(params, 0, m_dgtState[i]);
		}
	}
}

void SHA256::Update(byte Input)
{
	std::vector<byte> inp(1, Input);
	Update(inp, 0, 1);
}

void SHA256::Update(const std::vector<byte> &Input, size_t InOffset, size_t Length)
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
				ParallelTools::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Input, InOffset, PRCLEN](size_t i)
				{
					ProcessLeaf(Input, InOffset + (i * BLOCK_SIZE), m_dgtState[i], PRCLEN);
				});

				Length -= PRCLEN;
				InOffset += PRCLEN;
			}

			if (Length >= m_parallelProfile.ParallelMinimumSize())
			{
				const size_t PRMLEN = Length - (Length % m_parallelProfile.ParallelMinimumSize());

				ParallelTools::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Input, InOffset, PRMLEN](size_t i)
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
					MemoryTools::Copy(Input, InOffset, m_msgBuffer, m_msgLength, RMDLEN);
				}

				Permute(m_msgBuffer, 0, m_dgtState[0]);
				m_msgLength = 0;
				InOffset += RMDLEN;
				Length -= RMDLEN;
			}

			// sequential loop through blocks
			while (Length >= BLOCK_SIZE)
			{
				Permute(Input, InOffset, m_dgtState[0]);
				InOffset += BLOCK_SIZE;
				Length -= BLOCK_SIZE;
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

void SHA256::HashFinal(std::vector<byte> &Input, size_t InOffset, size_t Length, SHA256State &State)
{
	State.T += Length;
	ulong bitLen = (State.T << 3);

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
		MemoryTools::Clear(Input, InOffset + Length, BLOCK_SIZE - Length);
	}

	if (Length > 56)
	{
		Permute(Input, InOffset, State);
		MemoryTools::Clear(Input, 0, BLOCK_SIZE);
	}

	// finalize state with counter and last compression
	IntegerTools::Be32ToBytes(static_cast<uint>(static_cast<ulong>(bitLen) >> 32), Input, InOffset + 56);
	IntegerTools::Be32ToBytes(static_cast<uint>(static_cast<ulong>(bitLen)), Input, InOffset + 60);
	Permute(Input, InOffset, State);
}

void SHA256::Permute(const std::vector<byte> &Input, size_t InOffset, SHA256State &State)
{
	if (m_parallelProfile.HasSHA2())
	{
		SHA2::PermuteR64P512V(Input, InOffset, State.H);
	}
	else
	{
#if defined(CEX_DIGEST_COMPACT)
		SHA2::PermuteR64P512C(Input, InOffset, State.H);
#else
		SHA2::PermuteR64P512U(Input, InOffset, State.H);
#endif
	}

	State.Increase(BLOCK_SIZE);
}

void SHA256::ProcessLeaf(const std::vector<byte> &Input, size_t InOffset, SHA256State &State, ulong Length)
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
