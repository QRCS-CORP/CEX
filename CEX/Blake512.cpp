#include "Blake512.h"
#include "Blake2.h"
#include "CpuDetect.h"
#include "ParallelUtils.h"

NAMESPACE_DIGEST

using Utility::IntUtils;

struct Blake512::Blake2bState
{
	std::array<ulong, 2> F;
	std::array<ulong, 8> H;
	std::array<ulong, 2> T;

	Blake2bState()
	{
	}

	void Reset()
	{
		Utility::MemUtils::Clear(F, 0, F.size() * sizeof(ulong));
		Utility::MemUtils::Clear(H, 0, H.size() * sizeof(ulong));
		Utility::MemUtils::Clear(T, 0, T.size() * sizeof(ulong));
	}
};

const std::string Blake512::CLASS_NAME("Blake512");

//~~~Constructor~~~//

Blake512::Blake512(bool Parallel)
	:
	m_dgtState(Parallel ? DEF_PRLDEGREE : 1),
	m_isDestroyed(false),
	m_leafSize(Parallel ? DEF_LEAFSIZE : BLOCK_SIZE),
	m_msgBuffer(Parallel ? 2 * DEF_PRLDEGREE * BLOCK_SIZE : BLOCK_SIZE),
	m_msgLength(0),
	m_parallelProfile(BLOCK_SIZE, false, STATE_PRECACHED, false, DEF_PRLDEGREE),
	m_treeConfig(8),
	m_treeDestroy(true),
	m_treeParams(Parallel ? BlakeParams(static_cast<byte>(DIGEST_SIZE), 2, DEF_PRLDEGREE, 0, static_cast<byte>(DIGEST_SIZE)) : BlakeParams(static_cast<byte>(DIGEST_SIZE), 1, 1, 0, 0))
{
	// TODO: implement parallel alternate for single core cpu
	if (Parallel && !m_parallelProfile.IsParallel())
	{
		throw CryptoDigestException("Blake512::Ctor", "Cpu does not support parallel processing!");
	}

	if (m_parallelProfile.IsParallel())
	{
		m_parallelProfile.IsParallel() = Parallel;
	}

	if (m_parallelProfile.IsParallel())
	{
		m_parallelProfile.IsParallel() = Parallel;
		// initialize the leaf nodes
		Reset();
	}
	else
	{
		LoadState(m_dgtState[0]);
	}
}

Blake512::Blake512(BlakeParams &Params)
	:
	m_dgtState(Params.FanOut() > 0 ? Params.FanOut() : 1),
	m_isDestroyed(false),
	m_leafSize(BLOCK_SIZE),
	m_msgBuffer(Params.FanOut() > 0 ? 2 * Params.FanOut() * BLOCK_SIZE : BLOCK_SIZE),
	m_msgLength(0),
	m_parallelProfile(BLOCK_SIZE, false, STATE_PRECACHED, false, Params.FanOut()),
	m_treeConfig(CHAIN_SIZE),
	m_treeDestroy(false),
	m_treeParams(Params)
{
	if (m_treeParams.FanOut() > 1 && !m_parallelProfile.IsParallel())
	{
		throw CryptoDigestException("Blake512::Ctor", "Cpu does not support parallel processing!");
	}

	if (m_parallelProfile.IsParallel())
	{
		m_parallelProfile.IsParallel() = m_treeParams.FanOut() > 1;
	}

	if (m_parallelProfile.IsParallel())
	{
		if (Params.LeafLength() != 0 && (Params.LeafLength() < BLOCK_SIZE || Params.LeafLength() % BLOCK_SIZE != 0))
		{
			throw CryptoDigestException("BlakeBP512:Ctor", "The LeafLength parameter is invalid! Must be evenly divisible by digest block size.");
		}
		if (Params.FanOut() < 2 || Params.FanOut() % 2 != 0)
		{
			throw CryptoDigestException("BlakeBP512:Ctor", "The FanOut parameter is invalid! Must be an even number greater than 1.");
		}

		m_leafSize = Params.LeafLength() == 0 ? DEF_LEAFSIZE : Params.LeafLength();
		// initialize leafs
		Reset();
	}
	else
	{
		// fixed at defaults for sequential; depth 1, fanout 1, leaf length unlimited
		m_treeParams = BlakeParams(static_cast<byte>(DIGEST_SIZE));
		LoadState(m_dgtState[0]);
	}
}

Blake512::~Blake512()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_leafSize = 0;
		m_msgLength = 0;

		IntUtils::ClearVector(m_msgBuffer);
		IntUtils::ClearVector(m_treeConfig);
		m_parallelProfile.Reset();

		for (size_t i = 0; i < m_dgtState.size(); ++i)
		{
			m_dgtState[i].Reset();
		}

		if (m_treeDestroy)
		{
			m_treeParams.Reset();
			m_treeDestroy = false;
		}
	}
}

//~~~Accessors~~~//

size_t Blake512::BlockSize() 
{ 
	return BLOCK_SIZE; 
}

size_t Blake512::DigestSize()
{
	return DIGEST_SIZE; 
}

const Digests Blake512::Enumeral()
{
	return Digests::Blake512;
}

const bool Blake512::IsParallel() 
{ 
	return m_parallelProfile.IsParallel(); 
}

const std::string Blake512::Name()
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

const size_t Blake512::ParallelBlockSize() 
{ 
	return m_parallelProfile.ParallelBlockSize();
}

ParallelOptions &Blake512::ParallelProfile()
{ 
	return m_parallelProfile; 
}

//~~~Public Functions~~~//

void Blake512::Compute(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Update(Input, 0, Input.size());
	Finalize(Output, 0);
}

size_t Blake512::Finalize(std::vector<byte> &Output, const size_t OutOffset)
{
	if (m_parallelProfile.IsParallel())
	{
		std::vector<byte> hashCodes(m_treeParams.FanOut() * DIGEST_SIZE);

		// padding
		if (m_msgLength < m_msgBuffer.size())
		{
			Utility::MemUtils::Clear(m_msgBuffer, m_msgLength, m_msgBuffer.size() - m_msgLength);
		}

		std::vector<byte> padLen(m_treeParams.FanOut(), BLOCK_SIZE);
		ulong prtBlk = 0xFFFFFFFFFFFFFFFFULL;

		// process unaligned blocks
		if (m_msgLength > m_parallelProfile.ParallelMinimumSize())
		{
			size_t blkCount = (m_msgLength - m_parallelProfile.ParallelMinimumSize()) / BLOCK_SIZE;
			if (m_msgLength % BLOCK_SIZE != 0)
			{
				++blkCount;
			}

			for (size_t i = 0; i < blkCount; ++i)
			{
				// process partial block set
				Permute(m_msgBuffer, (i * BLOCK_SIZE), m_dgtState[i], BLOCK_SIZE);
				Utility::MemUtils::Copy(m_msgBuffer, m_parallelProfile.ParallelMinimumSize() + (i * BLOCK_SIZE), m_msgBuffer, i * BLOCK_SIZE, BLOCK_SIZE);
				m_msgLength -= BLOCK_SIZE;
			}

			if (m_msgLength % BLOCK_SIZE != 0)
			{
				prtBlk = blkCount - 1;
			}
		}

		// process last 4 blocks
		for (size_t i = 0; i < m_treeParams.FanOut(); ++i)
		{
			// apply f0 bit reversal constant to final blocks
			m_dgtState[i].F[0] = 0xFFFFFFFFFFFFFFFFULL;
			size_t blkLen = BLOCK_SIZE;

			// f1 constant on last block
			if (i == m_treeParams.FanOut() - 1)
			{
				m_dgtState[i].F[1] = 0xFFFFFFFFFFFFFFFFULL;
			}

			if (i == prtBlk)
			{
				blkLen = m_msgLength % BLOCK_SIZE;
				m_msgLength += BLOCK_SIZE - blkLen;
				Utility::MemUtils::Clear(m_msgBuffer, (i * BLOCK_SIZE) + blkLen, BLOCK_SIZE - blkLen);
			}
			else if ((int32_t)m_msgLength < 1)
			{
				blkLen = 0;
				Utility::MemUtils::Clear(m_msgBuffer, i * BLOCK_SIZE, BLOCK_SIZE);
			}
			else if ((int32_t)m_msgLength < BLOCK_SIZE)
			{
				blkLen = m_msgLength;
				Utility::MemUtils::Clear(m_msgBuffer, (i * BLOCK_SIZE) + blkLen, BLOCK_SIZE - blkLen);
			}

			Permute(m_msgBuffer, i * BLOCK_SIZE, m_dgtState[i], blkLen);
			m_msgLength -= BLOCK_SIZE;

			IntUtils::LeULL512ToBlock(m_dgtState[i].H, 0, hashCodes, i * DIGEST_SIZE);
		}

		// set up the root node
		m_msgLength = 0;
		m_treeParams.NodeDepth() = 1;
		m_treeParams.NodeOffset() = 0;
		m_treeParams.MaxDepth() = 2;
		LoadState(m_dgtState[0]);

		// load blocks
		for (size_t i = 0; i < m_treeParams.FanOut(); ++i)
		{
			Update(hashCodes, i * DIGEST_SIZE, DIGEST_SIZE);
		}

		// compress all but last block
		for (size_t i = 0; i < hashCodes.size() - BLOCK_SIZE; i += BLOCK_SIZE)
		{
			Permute(m_msgBuffer, i, m_dgtState[0], BLOCK_SIZE);
		}

		// apply f0 and f1 flags
		m_dgtState[0].F[0] = 0xFFFFFFFFFFFFFFFFULL;
		m_dgtState[0].F[1] = 0xFFFFFFFFFFFFFFFFULL;
		// last compression
		Permute(m_msgBuffer, m_msgLength - BLOCK_SIZE, m_dgtState[0], BLOCK_SIZE);
		// output the code
		IntUtils::LeULL512ToBlock(m_dgtState[0].H, 0, Output, 0);
	}
	else
	{
		size_t padLen = m_msgBuffer.size() - m_msgLength;
		if (padLen > 0)
		{
			Utility::MemUtils::Clear(m_msgBuffer, m_msgLength, padLen);
		}

		m_dgtState[0].F[0] = 0xFFFFFFFFFFFFFFFFULL;
		Permute(m_msgBuffer, 0, m_dgtState[0], m_msgLength);
		IntUtils::LeULL512ToBlock(m_dgtState[0].H, 0, Output, OutOffset);
	}

	Reset();

	return DIGEST_SIZE;
}

void Blake512::Initialize(Key::Symmetric::ISymmetricKey &MacKey)
{
	if (MacKey.Key().size() < 32 || MacKey.Key().size() > 64)
	{
		throw Exception::CryptoDigestException("Blake512::Initialize", "Mac Key has invalid length!");
	}

	if (MacKey.Nonce().size() != 0)
	{
		if (MacKey.Nonce().size() != 16)
		{
			throw Exception::CryptoDigestException("Blake512::Initialize", "Salt has invalid length!");
		}

		m_treeConfig[4] = IntUtils::LeBytesTo64(MacKey.Nonce(), 0);
		m_treeConfig[5] = IntUtils::LeBytesTo64(MacKey.Nonce(), 8);
	}

	if (MacKey.Info().size() != 0)
	{
		if (MacKey.Info().size() != 16)
		{
			throw Exception::CryptoDigestException("Blake512::Initialize", "Info has invalid length!");
		}

		m_treeConfig[6] = IntUtils::LeBytesTo64(MacKey.Info(), 0);
		m_treeConfig[7] = IntUtils::LeBytesTo64(MacKey.Info(), 8);
	}

	std::vector<byte> mkey(BLOCK_SIZE, 0);
	Utility::MemUtils::Copy(MacKey.Key(), 0, mkey, 0, IntUtils::Min(MacKey.Key().size(), mkey.size()));
	m_treeParams.KeyLength() = static_cast<byte>(MacKey.Key().size());

	if (m_parallelProfile.IsParallel())
	{
		// initialize the leaf nodes and add the key 
		for (size_t i = 0; i < m_treeParams.FanOut(); ++i)
		{
			Utility::MemUtils::Copy(mkey, 0, m_msgBuffer, i * BLOCK_SIZE, mkey.size());
			m_treeParams.NodeOffset() = static_cast<byte>(i);
			LoadState(m_dgtState[i]);
		}
		m_msgLength = m_parallelProfile.ParallelMinimumSize();
		m_treeParams.NodeOffset() = 0;
	}
	else
	{
		Utility::MemUtils::Copy(mkey, 0, m_msgBuffer, 0, mkey.size());
		m_msgLength = BLOCK_SIZE;
		LoadState(m_dgtState[0]);
	}
}

void Blake512::ParallelMaxDegree(size_t Degree)
{
	CexAssert(Degree != 0, "parallel degree can not be zero");
	CexAssert(Degree % 2 == 0, "parallel degree must be an even number");
	CexAssert(Degree <= m_parallelProfile.ProcessorCount(), "parallel degree can not exceed processor count");

	if (Degree > 1 && m_parallelProfile.ProcessorCount() > 1)
	{
		m_treeParams.FanOut() = static_cast<byte>(Degree);
		m_treeParams.MaxDepth() = 2;
		m_treeParams.InnerLength() = static_cast<byte>(DIGEST_SIZE);
		m_parallelProfile.IsParallel() = true;
	}
	else
	{
		m_treeParams = BlakeParams(static_cast<byte>(DIGEST_SIZE));
		m_parallelProfile.IsParallel() = false;
	}

	Reset();
}

void Blake512::Reset()
{
	m_msgLength = 0;
	Utility::MemUtils::Clear(m_msgBuffer, 0, m_msgBuffer.size());

	if (m_parallelProfile.IsParallel())
	{
		for (size_t i = 0; i < m_treeParams.FanOut(); ++i)
		{
			m_treeParams.NodeOffset() = static_cast<byte>(i);
			LoadState(m_dgtState[i]);
		}
		m_treeParams.NodeOffset() = 0;
	}
	else
	{
		LoadState(m_dgtState[0]);
	}
}

void Blake512::Update(byte Input)
{
	std::vector<byte> inp(1, Input);
	Update(inp, 0, 1);
}

void Blake512::Update(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	if (Length != 0)
	{
		if (m_parallelProfile.IsParallel())
		{
			size_t ttlLen = Length + m_msgLength;
			const size_t PRLMIN = m_msgBuffer.size() + (m_parallelProfile.ParallelMinimumSize() - BLOCK_SIZE);

			// input larger than min parallel; process buffer and loop-in remainder
			if (ttlLen > PRLMIN)
			{
				// fill buffer
				const size_t RMDLEN = m_msgBuffer.size() - m_msgLength;
				if (RMDLEN != 0)
				{
					Utility::MemUtils::Copy(Input, InOffset, m_msgBuffer, m_msgLength, RMDLEN);
				}

				m_msgLength = 0;
				Length -= RMDLEN;
				InOffset += RMDLEN;
				ttlLen -= m_msgBuffer.size();

				// empty the message buffer
				Utility::ParallelUtils::ParallelFor(0, m_treeParams.FanOut(), [this, &Input, InOffset](size_t i)
				{
					Permute(m_msgBuffer, i * BLOCK_SIZE, m_dgtState[i], BLOCK_SIZE);
					Permute(m_msgBuffer, (i * BLOCK_SIZE) + (m_treeParams.FanOut() * BLOCK_SIZE), m_dgtState[i], BLOCK_SIZE);
				});

				// loop in the remainder (no buffering)
				if (Length > PRLMIN)
				{
					// calculate working set size
					size_t prcLen = Length - m_parallelProfile.ParallelMinimumSize();
					if (prcLen % m_parallelProfile.ParallelMinimumSize() != 0)
					{
						prcLen -= (prcLen % m_parallelProfile.ParallelMinimumSize());
					}

					// process large blocks
					Utility::ParallelUtils::ParallelFor(0, m_treeParams.FanOut(), [this, &Input, InOffset, prcLen](size_t i)
					{
						ProcessLeaf(Input, InOffset + (i * BLOCK_SIZE), m_dgtState[i], prcLen);
					});

					Length -= prcLen;
					InOffset += prcLen;
					ttlLen -= prcLen;
				}
			}

			// remainder exceeds buffer size; process first 4 blocks and shift buffer left
			if (ttlLen > m_msgBuffer.size())
			{
				// fill buffer
				size_t RMDLEN = m_msgBuffer.size() - m_msgLength;
				if (RMDLEN != 0)
				{
					Utility::MemUtils::Copy(Input, InOffset, m_msgBuffer, m_msgLength, RMDLEN);
				}

				Length -= RMDLEN;
				InOffset += RMDLEN;
				m_msgLength = m_msgBuffer.size();

				// process first half of buffer
				Utility::ParallelUtils::ParallelFor(0, m_treeParams.FanOut(), [this, &Input, InOffset](size_t i)
				{
					Permute(m_msgBuffer, i * BLOCK_SIZE, m_dgtState[i], BLOCK_SIZE);
				});

				// left rotate the buffer
				m_msgLength -= m_parallelProfile.ParallelMinimumSize();
				const size_t FNLLEN = m_msgBuffer.size() / 2;
				Utility::MemUtils::Copy(m_msgBuffer, FNLLEN, m_msgBuffer, 0, FNLLEN);
			}
		}
		else
		{
			if (m_msgLength + Length > BLOCK_SIZE)
			{
				const size_t RMDLEN = BLOCK_SIZE - m_msgLength;
				if (RMDLEN != 0)
				{
					Utility::MemUtils::Copy(Input, InOffset, m_msgBuffer, m_msgLength, RMDLEN);
				}

				Permute(m_msgBuffer, 0, m_dgtState[0], BLOCK_SIZE);
				m_msgLength = 0;
				InOffset += RMDLEN;
				Length -= RMDLEN;
			}

			// loop until last block
			while (Length > BLOCK_SIZE)
			{
				Permute(Input, InOffset, m_dgtState[0], BLOCK_SIZE);
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

void Blake512::LoadState(Blake2bState &State)
{
	Utility::MemUtils::Clear(State.T, 0, COUNTER_SIZE * sizeof(ulong));
	Utility::MemUtils::Clear(State.F, 0, FLAG_SIZE * sizeof(ulong));
	Utility::MemUtils::Copy(Blake2::IV512, 0, State.H, 0, CHAIN_SIZE * sizeof(ulong));

	m_treeParams.GetConfig<ulong>(m_treeConfig);
	Utility::MemUtils::XOR512(m_treeConfig, 0, State.H, 0);
}

void Blake512::Permute(const std::vector<byte> &Input, size_t InOffset, Blake2bState &State, size_t Length)
{
	IntUtils::LeIncreaseW(State.T, State.T, Length);

	std::array<ulong, 8> iv{
		Blake2::IV512[0],
		Blake2::IV512[1],
		Blake2::IV512[2],
		Blake2::IV512[3],
		Blake2::IV512[4] ^ State.T[0],
		Blake2::IV512[5] ^ State.T[1],
		Blake2::IV512[6] ^ State.F[0],
		Blake2::IV512[7] ^ State.F[1] };

#if defined(__AVX__)
	Blake2::PermuteR12P1024V(Input, InOffset, State.H, iv);
#else
#	if defined(CEX_DIGEST_COMPACT)
		Blake2::PermuteR12P1024C(Input, InOffset, State.H, iv);
#	else
		Blake2::PermuteR12P1024U(Input, InOffset, State.H, iv);
#	endif
#endif
}

void Blake512::ProcessLeaf(const std::vector<byte> &Input, size_t InOffset, Blake2bState &State, ulong Length)
{
	do
	{
		Permute(Input, InOffset, State, BLOCK_SIZE);
		InOffset += m_parallelProfile.ParallelMinimumSize();
		Length -= m_parallelProfile.ParallelMinimumSize();
	}
	while (Length > 0);
}

NAMESPACE_DIGESTEND
