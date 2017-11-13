#include "Blake256.h"
#include "Blake2.h"
#include "CpuDetect.h"
#include "IntUtils.h"
#include "MemUtils.h"
#include "ParallelUtils.h"

NAMESPACE_DIGEST

using Utility::IntUtils;

const std::vector<uint> SCIV = 
{ 
	0x6A09E667UL, 
	0xBB67AE85UL,
	0x3C6EF372UL, 
	0xA54FF53AUL, 
	0x510E527FUL, 
	0x9B05688CUL,
	0x1F83D9ABUL,
	0x5BE0CD19UL 
};

const std::string Blake256::CLASS_NAME("Blake256");

//~~~Constructor~~~//

Blake256::Blake256(bool Parallel)
	:
	m_cIV(SCIV),
	m_dgtState(Parallel ? 8 : 1),
	m_isDestroyed(false),
	m_leafSize(Parallel ? DEF_LEAFSIZE : BLOCK_SIZE),
	m_msgBuffer(Parallel ? 2 * DEF_PRLDEGREE * BLOCK_SIZE : BLOCK_SIZE),
	m_msgLength(0),
	m_parallelProfile(BLOCK_SIZE, false, STATE_PRECACHED, false, DEF_PRLDEGREE),
	m_treeConfig(CHAIN_SIZE),
	m_treeDestroy(true),
	m_treeParams(Parallel ? BlakeParams(static_cast<byte>(DIGEST_SIZE), 2, DEF_PRLDEGREE, 0, static_cast<byte>(DIGEST_SIZE)) : BlakeParams(static_cast<byte>(DIGEST_SIZE), 1, 1, 0, 0))
{
	// TODO: implement parallel alternate for single core cpu
	if (Parallel && !m_parallelProfile.IsParallel())
	{
		throw CryptoDigestException("Blake256::Ctor", "Cpu does not support parallel processing!");
	}

	if (m_parallelProfile.IsParallel())
	{
		m_parallelProfile.IsParallel() = Parallel;
	}

	if (m_parallelProfile.IsParallel())
	{
		// initialize the leaf nodes 
		Reset();
	}
	else
	{
		LoadState(m_dgtState[0]);
	}
}

Blake256::Blake256(BlakeParams &Params)
	:
	m_cIV(SCIV),
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
		throw CryptoDigestException("Blake256::Ctor", "Cpu does not support parallel processing!");
	}

	if (m_parallelProfile.IsParallel())
	{
		m_parallelProfile.IsParallel() = m_treeParams.FanOut() > 1;
	}

	if (m_parallelProfile.IsParallel())
	{
		if (Params.LeafLength() != 0 && (Params.LeafLength() < BLOCK_SIZE || Params.LeafLength() % BLOCK_SIZE != 0))
		{
			throw CryptoDigestException("BlakeSP256:Ctor", "The LeafLength parameter is invalid! Must be evenly divisible by digest block size.");
		}
		if (Params.FanOut() < 2 || Params.FanOut() % 2 != 0)
		{
			throw CryptoDigestException("BlakeSP256:Ctor", "The FanOut parameter is invalid! Must be an even number greater than 1.");
		}

		m_leafSize = (Params.LeafLength() == 0) ? DEF_LEAFSIZE : Params.LeafLength();
		Reset();
	}
	else
	{
		// fixed at defaults for sequential; depth 1, fanout 1, leaf length unlimited
		m_treeParams = BlakeParams(static_cast<byte>(DIGEST_SIZE), 0, 1, 1, 0, 0, 0, 0, Params.DistributionCode());
		LoadState(m_dgtState[0]);
	}
}

Blake256::~Blake256()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		IntUtils::ClearVector(m_cIV);
		IntUtils::ClearVector(m_msgBuffer);
		IntUtils::ClearVector(m_treeConfig);
		m_leafSize = 0;
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
	}
}

//~~~Accessors~~~//

size_t Blake256::BlockSize() 
{ 
	return BLOCK_SIZE; 
}

size_t Blake256::DigestSize() 
{ 
	return DIGEST_SIZE; 
}

const Digests Blake256::Enumeral()
{
	return Digests::Blake256;
}

const bool Blake256::IsParallel() 
{
	return m_parallelProfile.IsParallel(); 
}

const std::string Blake256::Name()
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

const size_t Blake256::ParallelBlockSize()
{ 
	return m_parallelProfile.ParallelBlockSize(); 
}

ParallelOptions &Blake256::ParallelProfile()
{ 
	return m_parallelProfile; 
}

//~~~Public Functions~~~//

void Blake256::Compute(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Update(Input, 0, Input.size());
	Finalize(Output, 0);
	Reset();
}

size_t Blake256::Finalize(std::vector<byte> &Output, const size_t OutOffset)
{
	if (m_parallelProfile.IsParallel())
	{
		std::vector<byte> hashCodes(m_treeParams.FanOut() * DIGEST_SIZE);

		// padding
		if (m_msgLength < m_msgBuffer.size())
		{
			Utility::MemUtils::Clear(m_msgBuffer, m_msgLength, m_msgBuffer.size() - m_msgLength);
		}

		uint prtBlk = UL_MAX;

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
				Compress(m_msgBuffer, (i * BLOCK_SIZE), m_dgtState[i], BLOCK_SIZE);
				Utility::MemUtils::Copy(m_msgBuffer, m_parallelProfile.ParallelMinimumSize() + (i * BLOCK_SIZE), m_msgBuffer, i * BLOCK_SIZE, BLOCK_SIZE);
				m_msgLength -= BLOCK_SIZE;
			}

			if (m_msgLength % BLOCK_SIZE != 0)
			{
				prtBlk = static_cast<uint>(blkCount - 1);
			}
		}

		// process last 8 blocks
		for (size_t i = 0; i < m_treeParams.FanOut(); ++i)
		{
			// apply f0 bit reversal constant to final blocks
			m_dgtState[i].F[0] = UL_MAX;
			size_t blkLen = BLOCK_SIZE;

			// f1 constant on last block
			if (i == m_treeParams.FanOut() - 1)
			{
				m_dgtState[i].F[1] = UL_MAX;
			}

			if (i == prtBlk)
			{
				blkLen = m_msgLength % BLOCK_SIZE;
				m_msgLength += BLOCK_SIZE - blkLen;
				Utility::MemUtils::Clear(m_msgBuffer, (i * BLOCK_SIZE) + blkLen, BLOCK_SIZE - blkLen);
			}
			else if (static_cast<int>(m_msgLength) < 1)
			{
				blkLen = 0;
				Utility::MemUtils::Clear(m_msgBuffer, i * BLOCK_SIZE, BLOCK_SIZE);
			}
			else if ((int32_t)m_msgLength < BLOCK_SIZE)
			{
				blkLen = m_msgLength;
				Utility::MemUtils::Clear(m_msgBuffer, (i * BLOCK_SIZE) + blkLen, BLOCK_SIZE - blkLen);
			}

			Compress(m_msgBuffer, i * BLOCK_SIZE, m_dgtState[i], blkLen);
			m_msgLength -= BLOCK_SIZE;

			IntUtils::LeUL256ToBlock(m_dgtState[i].H, 0, hashCodes, i * DIGEST_SIZE);
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
			Compress(m_msgBuffer, i, m_dgtState[0], BLOCK_SIZE);
		}

		// apply f0 and f1 flags
		m_dgtState[0].F[0] = UL_MAX;
		m_dgtState[0].F[1] = UL_MAX;
		// last compression
		Compress(m_msgBuffer, m_msgLength - BLOCK_SIZE, m_dgtState[0], BLOCK_SIZE);
		// output the code
		IntUtils::LeUL256ToBlock(m_dgtState[0].H, 0, Output, OutOffset);
	}
	else
	{
		size_t padLen = m_msgBuffer.size() - m_msgLength;
		if (padLen > 0)
		{
			Utility::MemUtils::Clear(m_msgBuffer, m_msgLength, padLen);
		}

		m_dgtState[0].F[0] = UL_MAX;
		Compress(m_msgBuffer, 0, m_dgtState[0], m_msgLength);
		IntUtils::LeUL256ToBlock(m_dgtState[0].H, 0, Output, OutOffset);
	}

	Reset();

	return DIGEST_SIZE;
}

void Blake256::Initialize(Key::Symmetric::ISymmetricKey &MacKey)
{
	if (MacKey.Key().size() < 16 || MacKey.Key().size() > 32)
	{
		throw CryptoDigestException("Blake256::Initialize", "Mac Key has invalid length!");
	}

	if (MacKey.Nonce().size() != 0)
	{
		if (MacKey.Nonce().size() != 8)
		{
			throw CryptoDigestException("Blake256::Initialize", "Salt has invalid length!");
		}

		m_treeConfig[4] = IntUtils::LeBytesTo32(MacKey.Nonce(), 0);
		m_treeConfig[5] = IntUtils::LeBytesTo32(MacKey.Nonce(), 4);
	}

	if (MacKey.Info().size() != 0)
	{
		if (MacKey.Info().size() != 8)
		{
			throw CryptoDigestException("Blake256::Initialize", "Info has invalid length!");
		}

		m_treeConfig[6] = IntUtils::LeBytesTo32(MacKey.Info(), 0);
		m_treeConfig[7] = IntUtils::LeBytesTo32(MacKey.Info(), 4);
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

void Blake256::ParallelMaxDegree(size_t Degree)
{
	CexAssert(Degree != 0, "parallel degree can not be zero");
	CexAssert(Degree % 2 == 0, "parallel degree must be an even number");
	CexAssert(Degree <= m_parallelProfile.ProcessorCount(), "parallel degree can not exceed processor count");

	m_parallelProfile.SetMaxDegree(Degree);
	m_dgtState.clear();
	m_dgtState.resize(Degree);
	m_msgBuffer.clear();
	m_msgBuffer.resize(Degree * BLOCK_SIZE);

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

void Blake256::Reset()
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

void Blake256::Update(byte Input)
{
	std::vector<byte> inp(1, Input);
	Update(inp, 0, 1);
}

void Blake256::Update(const std::vector<byte> &Input, size_t InOffset, size_t Length)
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
				const size_t RMDSZE = m_msgBuffer.size() - m_msgLength;
				if (RMDSZE != 0)
				{
					Utility::MemUtils::Copy(Input, InOffset, m_msgBuffer, m_msgLength, RMDSZE);
				}

				m_msgLength = 0;
				Length -= RMDSZE;
				InOffset += RMDSZE;
				ttlLen -= m_msgBuffer.size();

				// empty the entire message buffer
				Utility::ParallelUtils::ParallelFor(0, m_treeParams.FanOut(), [this, &Input, InOffset](size_t i)
				{
					Compress(m_msgBuffer, i * BLOCK_SIZE, m_dgtState[i], BLOCK_SIZE);
					Compress(m_msgBuffer, (i * BLOCK_SIZE) + (m_treeParams.FanOut() * BLOCK_SIZE), m_dgtState[i], BLOCK_SIZE);
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
				size_t RMDSZE = m_msgBuffer.size() - m_msgLength;
				if (RMDSZE != 0)
				{
					Utility::MemUtils::Copy(Input, InOffset, m_msgBuffer, m_msgLength, RMDSZE);
				}

				Length -= RMDSZE;
				InOffset += RMDSZE;
				m_msgLength = m_msgBuffer.size();

				// process first half of buffer
				Utility::ParallelUtils::ParallelFor(0, m_treeParams.FanOut(), [this, &Input, InOffset](size_t i)
				{
					Compress(m_msgBuffer, i * BLOCK_SIZE, m_dgtState[i], BLOCK_SIZE);
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
				const size_t RMDSZE = BLOCK_SIZE - m_msgLength;
				if (RMDSZE != 0)
				{
					Utility::MemUtils::Copy(Input, InOffset, m_msgBuffer, m_msgLength, RMDSZE);
				}

				Compress(m_msgBuffer, 0, m_dgtState[0], BLOCK_SIZE);
				m_msgLength = 0;
				InOffset += RMDSZE;
				Length -= RMDSZE;
			}

			// loop until last block
			while (Length > BLOCK_SIZE)
			{
				Compress(Input, InOffset, m_dgtState[0], BLOCK_SIZE);
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

void Blake256::Compress(const std::vector<byte> &Input, size_t InOffset, Blake2sState &State, size_t Length)
{
	IntUtils::LeIncreaseW(State.T, State.T, Length);
	Blake2::Compress512(Input, InOffset, State, m_cIV);
}

void Blake256::LoadState(Blake2sState &State)
{
	Utility::MemUtils::Clear(State.T, 0, COUNTER_SIZE * sizeof(uint));
	Utility::MemUtils::Clear(State.F, 0, FLAG_SIZE * sizeof(uint));
	Utility::MemUtils::Clear(State.F, 0, FLAG_SIZE * sizeof(uint));
	Utility::MemUtils::Copy(m_cIV, 0, State.H, 0, CHAIN_SIZE * sizeof(uint));

	m_treeParams.GetConfig<uint>(m_treeConfig);
	Utility::MemUtils::XOR256(m_treeConfig, 0, State.H, 0);
}

void Blake256::ProcessLeaf(const std::vector<byte> &Input, size_t InOffset, Blake2sState &State, ulong Length)
{
	do
	{
		Compress(Input, InOffset, State, BLOCK_SIZE);
		InOffset += m_parallelProfile.ParallelMinimumSize();
		Length -= m_parallelProfile.ParallelMinimumSize();
	} 
	while (Length > 0);
}

NAMESPACE_DIGESTEND