#include "Blake512.h"
#include "Blake512Compress.h"
#include "ArrayUtils.h"
#include "CpuDetect.h"
#include "IntUtils.h"
#include "ParallelUtils.h"

NAMESPACE_DIGEST

using Utility::ArrayUtils;
using Utility::IntUtils;


static const std::vector<ulong> BCIV = { 0x6A09E667F3BCC908UL, 0xBB67AE8584CAA73BUL, 0x3C6EF372FE94F82BUL, 0xA54FF53A5F1D36F1UL, 
	0x510E527FADE682D1UL, 0x9B05688C2B3E6C1FUL, 0x1F83D9ABFB41BD6BUL, 0x5BE0CD19137E2179UL };


//~~~Constructor~~~//

Blake512::Blake512(bool Parallel)
	:
	m_cIV(BCIV),
	m_dgtState(Parallel ? DEF_PRLDEGREE : 1),
	m_isDestroyed(false),
	m_leafSize(Parallel ? DEF_LEAFSIZE : BLOCK_SIZE),
	m_msgBuffer(Parallel ? 2 * DEF_PRLDEGREE * BLOCK_SIZE : BLOCK_SIZE),
	m_msgLength(0),
	m_parallelProfile(BLOCK_SIZE, false, STATE_PRECACHED, false, DEF_PRLDEGREE),
	m_treeConfig(8),
	m_treeDestroy(true)
{
	if (m_parallelProfile.IsParallel())
		m_parallelProfile.IsParallel() = Parallel;

	if (m_parallelProfile.IsParallel())
	{
		// sets defaults of depth 2, fanout 4, 4 threads
		m_treeParams = BlakeParams(static_cast<byte>(DIGEST_SIZE), 2, DEF_PRLDEGREE, 0, static_cast<byte>(DIGEST_SIZE));
		// initialize the leaf nodes
		Reset();
	}
	else
	{
		// default depth 1, fanout 1, leaf length unlimited
		m_treeParams = BlakeParams(static_cast<byte>(DIGEST_SIZE));
		LoadState(m_dgtState[0]);
	}
}

Blake512::Blake512(BlakeParams &Params)
	:
	m_cIV(BCIV),
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
	if (m_parallelProfile.IsParallel())
		m_parallelProfile.IsParallel() = m_treeParams.FanOut() > 1;

	if (m_parallelProfile.IsParallel())
	{
		if (Params.LeafLength() != 0 && (Params.LeafLength() < BLOCK_SIZE || Params.LeafLength() % BLOCK_SIZE != 0))
			throw CryptoDigestException("BlakeBP512:Ctor", "The LeafLength parameter is invalid! Must be evenly divisible by digest block size.");
		if (Params.FanOut() < 2 || Params.FanOut() % 2 != 0)
			throw CryptoDigestException("BlakeBP512:Ctor", "The FanOut parameter is invalid! Must be an even number greater than 1.");

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
	Destroy();
}

//~~~Public Functions~~~//

void Blake512::Compute(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Update(Input, 0, Input.size());
	Finalize(Output, 0);
}

void Blake512::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_leafSize = 0;
		m_msgLength = 0;

		try
		{
			ArrayUtils::ClearVector(m_cIV);
			ArrayUtils::ClearVector(m_msgBuffer);
			ArrayUtils::ClearVector(m_treeConfig);

			for (size_t i = 0; i < m_dgtState.size(); ++i)
				m_dgtState[i].Reset();

			if (m_treeDestroy)
				m_treeParams.Reset();
		}
		catch (std::exception& ex)
		{
			throw CryptoDigestException("Blake512:Destroy", "Could not clear all variables!", std::string(ex.what()));
		}
	}
}

size_t Blake512::Finalize(std::vector<byte> &Output, const size_t OutOffset)
{
	if (m_parallelProfile.IsParallel())
	{
		std::vector<byte> hashCodes(m_treeParams.FanOut() * DIGEST_SIZE);

		// padding
		if (m_msgLength < m_msgBuffer.size())
			memset(&m_msgBuffer[m_msgLength], 0, m_msgBuffer.size() - m_msgLength);

		std::vector<byte> padLen(m_treeParams.FanOut(), BLOCK_SIZE);
		ulong prtBlk = ULL_MAX;

		// process unaligned blocks
		if (m_msgLength > m_parallelProfile.ParallelMinimumSize())
		{
			size_t blkCount = (m_msgLength - m_parallelProfile.ParallelMinimumSize()) / BLOCK_SIZE;
			if (m_msgLength % BLOCK_SIZE != 0)
				++blkCount;

			for (size_t i = 0; i < blkCount; ++i)
			{
				// process partial block set
				Compress(m_msgBuffer, (i * BLOCK_SIZE), m_dgtState[i], BLOCK_SIZE);
				memcpy(&m_msgBuffer[i * BLOCK_SIZE], &m_msgBuffer[m_parallelProfile.ParallelMinimumSize() + (i * BLOCK_SIZE)], BLOCK_SIZE);
				m_msgLength -= BLOCK_SIZE;
			}

			if (m_msgLength % BLOCK_SIZE != 0)
				prtBlk = blkCount - 1;
		}

		// process last 4 blocks
		for (size_t i = 0; i < m_treeParams.FanOut(); ++i)
		{
			// apply f0 bit reversal constant to final blocks
			m_dgtState[i].F[0] = ULL_MAX;
			size_t blkLen = BLOCK_SIZE;

			// f1 constant on last block
			if (i == m_treeParams.FanOut() - 1)
				m_dgtState[i].F[1] = ULL_MAX;

			if (i == prtBlk)
			{
				blkLen = m_msgLength % BLOCK_SIZE;
				m_msgLength += BLOCK_SIZE - blkLen;
				memset(&m_msgBuffer[(i * BLOCK_SIZE) + blkLen], 0, BLOCK_SIZE - blkLen);
			}
			else if ((int32_t)m_msgLength < 1)
			{
				blkLen = 0;
				memset(&m_msgBuffer[i * BLOCK_SIZE], 0, BLOCK_SIZE);
			}
			else if ((int32_t)m_msgLength < BLOCK_SIZE)
			{
				blkLen = m_msgLength;
				memset(&m_msgBuffer[(i * BLOCK_SIZE) + blkLen], 0, BLOCK_SIZE - blkLen);
			}

			Compress(m_msgBuffer, i * BLOCK_SIZE, m_dgtState[i], blkLen);
			m_msgLength -= BLOCK_SIZE;

			IntUtils::LeULL512ToBlock(m_dgtState[i].H, hashCodes, i * DIGEST_SIZE);
		}

		// set up the root node
		m_msgLength = 0;
		m_treeParams.NodeDepth() = 1;
		m_treeParams.NodeOffset() = 0;
		m_treeParams.MaxDepth() = 2;
		LoadState(m_dgtState[0]);

		// load blocks
		for (size_t i = 0; i < m_treeParams.FanOut(); ++i)
			Update(hashCodes, i * DIGEST_SIZE, DIGEST_SIZE);

		// compress all but last block
		for (size_t i = 0; i < hashCodes.size() - BLOCK_SIZE; i += BLOCK_SIZE)
			Compress(m_msgBuffer, i, m_dgtState[0], BLOCK_SIZE);

		// apply f0 and f1 flags
		m_dgtState[0].F[0] = ULL_MAX;
		m_dgtState[0].F[1] = ULL_MAX;
		// last compression
		Compress(m_msgBuffer, m_msgLength - BLOCK_SIZE, m_dgtState[0], BLOCK_SIZE);
		// output the code
		IntUtils::LeULL512ToBlock(m_dgtState[0].H, Output, 0);
	}
	else
	{
		size_t padLen = m_msgBuffer.size() - m_msgLength;
		if (padLen > 0)
			memset(&m_msgBuffer[m_msgLength], 0, padLen);

		m_dgtState[0].F[0] = ULL_MAX;
		Compress(m_msgBuffer, 0, m_dgtState[0], m_msgLength);
		IntUtils::LeULL512ToBlock(m_dgtState[0].H, Output, OutOffset);
	}

	Reset();

	return DIGEST_SIZE;
}

void Blake512::Initialize(Key::Symmetric::ISymmetricKey &MacKey)
{
	if (MacKey.Key().size() < 32 || MacKey.Key().size() > 64)
		throw Exception::CryptoDigestException("Blake512", "Mac Key has invalid length!");

	if (MacKey.Nonce().size() != 0)
	{
		if (MacKey.Nonce().size() != 16)
			throw Exception::CryptoDigestException("Blake512", "Salt has invalid length!");

		m_treeConfig[4] = IntUtils::BytesToLe64(MacKey.Nonce(), 0);
		m_treeConfig[5] = IntUtils::BytesToLe64(MacKey.Nonce(), 8);
	}

	if (MacKey.Info().size() != 0)
	{
		if (MacKey.Info().size() != 16)
			throw Exception::CryptoDigestException("Blake512", "Info has invalid length!");

		m_treeConfig[6] = IntUtils::BytesToLe64(MacKey.Info(), 0);
		m_treeConfig[7] = IntUtils::BytesToLe64(MacKey.Info(), 8);
	}

	std::vector<byte> mkey(BLOCK_SIZE, 0);
	memcpy(&mkey[0], &MacKey.Key()[0], MacKey.Key().size());
	m_treeParams.KeyLength() = (byte)MacKey.Key().size();

	if (m_parallelProfile.IsParallel())
	{
		// initialize the leaf nodes and add the key 
		for (size_t i = 0; i < m_treeParams.FanOut(); ++i)
		{
			memcpy(&m_msgBuffer[i * BLOCK_SIZE], &mkey[0], mkey.size());
			m_treeParams.NodeOffset() = static_cast<byte>(i);
			LoadState(m_dgtState[i]);
		}
		m_msgLength = m_parallelProfile.ParallelMinimumSize();
		m_treeParams.NodeOffset() = 0;
	}
	else
	{
		memcpy(&m_msgBuffer[0], &mkey[0], mkey.size());
		m_msgLength = BLOCK_SIZE;
		LoadState(m_dgtState[0]);
	}
}

void Blake512::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0)
		throw CryptoDigestException("Blake512:ParallelMaxDegree", "Parallel degree can not be zero!");
	if (Degree > 254)
		throw CryptoDigestException("Blake512:ParallelMaxDegree", "Parallel degree can not exceed 254!");
	if (Degree % 2 != 0)
		throw CryptoDigestException("Blake512:ParallelMaxDegree", "Parallel degree must be an even number!");

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
	memset(&m_msgBuffer[0], 0, m_msgBuffer.size());

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
	if (Length == 0)
		return;

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
				memcpy(&m_msgBuffer[m_msgLength], &Input[InOffset], RMDLEN);

			m_msgLength = 0;
			Length -= RMDLEN;
			InOffset += RMDLEN;
			ttlLen -= m_msgBuffer.size();

			// empty the message buffer
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
					prcLen -= (prcLen % m_parallelProfile.ParallelMinimumSize());

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
				memcpy(&m_msgBuffer[m_msgLength], &Input[InOffset], RMDLEN);

			Length -= RMDLEN;
			InOffset += RMDLEN;
			m_msgLength = m_msgBuffer.size();

			// process first half of buffer
			Utility::ParallelUtils::ParallelFor(0, m_treeParams.FanOut(), [this, &Input, InOffset](size_t i)
			{
				Compress(m_msgBuffer, i * BLOCK_SIZE, m_dgtState[i], BLOCK_SIZE);
			});

			// left rotate the buffer
			m_msgLength -= m_parallelProfile.ParallelMinimumSize();
			const size_t FNLLEN = m_msgBuffer.size() / 2;
			memcpy(&m_msgBuffer[0], &m_msgBuffer[FNLLEN], FNLLEN);
		}
	}
	else
	{
		if (m_msgLength + Length > BLOCK_SIZE)
		{
			const size_t RMDLEN = BLOCK_SIZE - m_msgLength;
			if (RMDLEN != 0)
				memcpy(&m_msgBuffer[m_msgLength], &Input[InOffset], RMDLEN);

			Compress(m_msgBuffer, 0, m_dgtState[0], BLOCK_SIZE);
			m_msgLength = 0;
			InOffset += RMDLEN;
			Length -= RMDLEN;
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
		memcpy(&m_msgBuffer[m_msgLength], &Input[InOffset], Length);
		m_msgLength += Length;
	}
}

//~~~Private Functions~~~//

void Blake512::Compress(const std::vector<byte> &Input, size_t InOffset, Blake2bState &State, size_t Length)
{
	ArrayUtils::IncreaseLE64(State.T, State.T, Length);
	Blake512Compress::Compress128(Input, InOffset, State, m_cIV);
}

void Blake512::LoadState(Blake2bState &State)
{
	memset(&State.T[0], 0, COUNTER_SIZE * sizeof(ulong));
	memset(&State.F[0], 0, FLAG_SIZE * sizeof(ulong));
	memcpy(&State.H[0], &m_cIV[0], CHAIN_SIZE * sizeof(ulong));

	m_treeParams.GetConfig<ulong>(m_treeConfig);
	IntUtils::XORULL512(m_treeConfig, 0, State.H, 0);
}

void Blake512::ProcessLeaf(const std::vector<byte> &Input, size_t InOffset, Blake2bState &State, ulong Length)
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