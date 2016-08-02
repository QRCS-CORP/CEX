#include "Blake2Sp256.h"
#include "Blake2SCompress.h"
#include "CpuDetect.h"
#include "IntUtils.h"
#include "ParallelUtils.h"

NAMESPACE_DIGEST

// *** Public Methods *** //

void Blake2Sp256::BlockUpdate(const std::vector<uint8_t> &Input, size_t InOffset, size_t Length)
{
	if (Length == 0)
		return;

	if (m_isParallel)
	{
		size_t ttlLen = Length + m_msgLength;
		const size_t minPrl = m_msgBuffer.size() + (m_minParallel - BLOCK_SIZE);

		// input larger than min parallel; process buffer and loop-in remainder
		if (ttlLen > minPrl)
		{
			// fill buffer
			size_t rmd = m_msgBuffer.size() - m_msgLength;
			if (rmd != 0)
				memcpy(&m_msgBuffer[m_msgLength], &Input[InOffset], rmd);

			m_msgLength = 0;
			Length -= rmd;
			InOffset += rmd;
			ttlLen -= m_msgBuffer.size();

			// empty the message buffer
			CEX::Utility::ParallelUtils::ParallelFor(0, m_treeParams.ParallelDegree(), [this, &Input, InOffset](size_t i)
			{
				ProcessBlock(m_msgBuffer, i * BLOCK_SIZE, m_State[i], BLOCK_SIZE);
				ProcessBlock(m_msgBuffer, (i * BLOCK_SIZE) + (m_treeParams.ParallelDegree() * BLOCK_SIZE), m_State[i], BLOCK_SIZE);
			});

			// loop in the remainder (no buffering)
			if (Length > minPrl)
			{
				// calculate working set size
				size_t prcLen = Length - m_minParallel;
				if (prcLen % m_minParallel != 0)
					prcLen -= (prcLen % m_minParallel);

				// process large blocks
				CEX::Utility::ParallelUtils::ParallelFor(0, m_treeParams.ParallelDegree(), [this, &Input, InOffset, prcLen](size_t i)
				{
					ProcessLeaf(Input, InOffset + (i * BLOCK_SIZE), m_State[i], prcLen);
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
			size_t rmd = m_msgBuffer.size() - m_msgLength;
			if (rmd != 0)
				memcpy(&m_msgBuffer[m_msgLength], &Input[InOffset], rmd);

			Length -= rmd;
			InOffset += rmd;
			m_msgLength = m_msgBuffer.size();

			// process first half of buffer
			CEX::Utility::ParallelUtils::ParallelFor(0, m_treeParams.ParallelDegree(), [this, &Input, InOffset](size_t i)
			{
				ProcessBlock(m_msgBuffer, i * BLOCK_SIZE, m_State[i], BLOCK_SIZE);
			});

			// left rotate the buffer
			m_msgLength -= m_minParallel;
			rmd = m_msgBuffer.size() / 2;
			memcpy(&m_msgBuffer[0], &m_msgBuffer[rmd], rmd);
		}
	}
	else
	{
		if (m_msgLength + Length > BLOCK_SIZE)
		{
			size_t rmd = BLOCK_SIZE - m_msgLength;
			if (rmd != 0)
				memcpy(&m_msgBuffer[m_msgLength], &Input[InOffset], rmd);

			ProcessBlock(m_msgBuffer, 0, m_State[0], BLOCK_SIZE);
			m_msgLength = 0;
			InOffset += rmd;
			Length -= rmd;
		}

		// loop until last block
		while (Length > BLOCK_SIZE)
		{
			ProcessBlock(Input, InOffset, m_State[0], BLOCK_SIZE);
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

void Blake2Sp256::ComputeHash(const std::vector<uint8_t> &Input, std::vector<uint8_t> &Output)
{
	BlockUpdate(Input, 0, Input.size());
	DoFinal(Output, 0);
	Reset();
}

void Blake2Sp256::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		CEX::Utility::IntUtils::ClearVector(m_cIV);
		CEX::Utility::IntUtils::ClearVector(m_msgBuffer);
		CEX::Utility::IntUtils::ClearVector(m_treeConfig);

		for (size_t i = 0; i < m_State.size(); ++i)
			m_State[i].Reset();

		if (m_treeDestroy)
			m_treeParams.Reset();

		m_isParallel = false;
		m_leafSize = 0;
		m_minParallel = 0;
		m_msgLength = 0;
		m_parallelBlockSize = 0;
	}
}

size_t Blake2Sp256::DoFinal(std::vector<uint8_t> &Output, const size_t OutOffset)
{
	if (m_isParallel)
	{
		std::vector<uint8_t> hashCodes(m_treeParams.ParallelDegree() * DIGEST_SIZE);

		// padding
		if (m_msgLength < m_msgBuffer.size())
			memset(&m_msgBuffer[m_msgLength], 0, m_msgBuffer.size() - m_msgLength);

		std::vector<uint8_t> padLen(m_treeParams.ParallelDegree(), BLOCK_SIZE);
		uint32_t prtBlk = UL_MAX;

		// process unaligned blocks
		if (m_msgLength > m_minParallel)
		{
			size_t blkCount = (m_msgLength - m_minParallel) / BLOCK_SIZE;
			if (m_msgLength % BLOCK_SIZE != 0)
				++blkCount;

			for (size_t i = 0; i < blkCount; ++i)
			{
				// process partial block set
				ProcessBlock(m_msgBuffer, (i * BLOCK_SIZE), m_State[i], BLOCK_SIZE);
				memcpy(&m_msgBuffer[i * BLOCK_SIZE], &m_msgBuffer[m_minParallel + (i * BLOCK_SIZE)], BLOCK_SIZE);
				m_msgLength -= BLOCK_SIZE;
			}
			if (m_msgLength % BLOCK_SIZE != 0)
				prtBlk = (uint32_t)blkCount - 1;
		}

		// process last 4 blocks
		for (size_t i = 0; i < m_treeParams.ParallelDegree(); ++i)
		{
			// apply f0 bit reversal constant to final blocks
			m_State[i].F[0] = UL_MAX;
			size_t blkSze = BLOCK_SIZE;

			// f1 constant on last block
			if (i == m_treeParams.ParallelDegree() - 1)
				m_State[i].F[1] = UL_MAX;

			if (i == prtBlk)
			{
				blkSze = m_msgLength % BLOCK_SIZE;
				m_msgLength += BLOCK_SIZE - blkSze;
				memset(&m_msgBuffer[(i * BLOCK_SIZE) + blkSze], 0, BLOCK_SIZE - blkSze);
			}
			else if ((int32_t)m_msgLength < 1)
			{
				blkSze = 0;
				memset(&m_msgBuffer[i * BLOCK_SIZE], 0, BLOCK_SIZE);
			}
			else if ((int32_t)m_msgLength < BLOCK_SIZE)
			{
				blkSze = m_msgLength;
				memset(&m_msgBuffer[(i * BLOCK_SIZE) + blkSze], 0, BLOCK_SIZE - blkSze);
			}

			ProcessBlock(m_msgBuffer, i * BLOCK_SIZE, m_State[i], blkSze);
			m_msgLength -= BLOCK_SIZE;

			CEX::Utility::IntUtils::Le256ToBlock(m_State[i].H, hashCodes, i * DIGEST_SIZE);
		}

		// set up the root node
		m_msgLength = 0;
		m_treeParams.NodeDepth() = 1;
		m_treeParams.NodeOffset() = 0;
		m_treeParams.MaxDepth() = 2;
		Initialize(m_treeParams, m_State[0]);

		// load blocks
		for (size_t i = 0; i < m_treeParams.ParallelDegree(); ++i)
			BlockUpdate(hashCodes, i * DIGEST_SIZE, DIGEST_SIZE);

		// compress all but last block
		for (size_t i = 0; i < hashCodes.size() - BLOCK_SIZE; i += BLOCK_SIZE)
			ProcessBlock(m_msgBuffer, i, m_State[0], BLOCK_SIZE);

		// apply f0 and f1 flags
		m_State[0].F[0] = UL_MAX;
		m_State[0].F[1] = UL_MAX;
		// last compression
		ProcessBlock(m_msgBuffer, m_msgLength - BLOCK_SIZE, m_State[0], BLOCK_SIZE);
		// output the code
		CEX::Utility::IntUtils::Le256ToBlock(m_State[0].H, Output, 0);
	}
	else
	{
		size_t padLen = m_msgBuffer.size() - m_msgLength;
		if (padLen > 0)
			memset(&m_msgBuffer[m_msgLength], 0, padLen);

		m_State[0].F[0] = UL_MAX;
		ProcessBlock(m_msgBuffer, 0, m_State[0], m_msgLength);
		CEX::Utility::IntUtils::Le256ToBlock(m_State[0].H, Output, 0);
	}

	Reset();

	return DIGEST_SIZE;
}

size_t Blake2Sp256::Generate(CEX::Common::MacParams &MacKey, std::vector<uint8_t> &Output)
{
#if defined(_DEBUG)
	assert(Output.size() != 0);
	assert(MacKey.Key().size() >= DIGEST_SIZE);
	assert((MacKey.Key().size() + MacKey.Salt().size() + MacKey.Info().size()) <= BLOCK_SIZE);
#endif
#if defined(CPPEXCEPTIONS_ENABLED)
	if (Output.size() == 0)
		throw CEX::Exception::CryptoDigestException("Blake2Bp512:Generate", "Buffer size must be at least 1 byte!");
	if (MacKey.Key().size() < DIGEST_SIZE)
		throw CEX::Exception::CryptoDigestException("Blake2Sp256:Generate", "The key must be at least 32 bytes long!");
#endif

	size_t bufSize = DIGEST_SIZE;
	std::vector<uint8_t> inpCtr(BLOCK_SIZE);

	// add the key to state
	LoadMacKey(MacKey);
	// process the key
	ProcessBlock(m_msgBuffer, 0, m_State[0], BLOCK_SIZE);
	// copy hash to upper half of input
	memcpy(&inpCtr[DIGEST_SIZE], &m_State[0].H[0], DIGEST_SIZE);
	// add padding to empty bytes
	memset(&inpCtr[sizeof(uint32_t)], 0x0, DIGEST_SIZE - sizeof(uint32_t));
	// increment the input counter
	Increment(inpCtr);
	// process the block
	ProcessBlock(inpCtr, 0, m_State[0], BLOCK_SIZE);

	if (bufSize < Output.size())
	{
		memcpy(&Output[0], &m_State[0].H[0], bufSize);
		int32_t rmd = (int32_t)(Output.size() - bufSize);

		while (rmd > 0)
		{
			memcpy(&inpCtr[DIGEST_SIZE], &m_State[0].H[0], DIGEST_SIZE);
			Increment(inpCtr);
			ProcessBlock(inpCtr, 0, m_State[0], BLOCK_SIZE);

			if (rmd > (int32_t)DIGEST_SIZE)
			{
				memcpy(&Output[bufSize], &m_State[0].H[0], DIGEST_SIZE);
				bufSize += DIGEST_SIZE;
				rmd -= (int32_t)DIGEST_SIZE;
			}
			else
			{
				rmd = (int32_t)(Output.size() - bufSize);
				memcpy(&Output[bufSize], &m_State[0].H[0], rmd);
				rmd = 0;
			}
		}
	}
	else
	{
		memcpy(&Output[0], &m_State[0].H[0], Output.size());
	}

	return Output.size();
}

void Blake2Sp256::LoadMacKey(CEX::Common::MacParams &MacKey)
{
#if defined(_DEBUG)
	assert(MacKey.Key().size() >= 16 || MacKey.Key().size() <= 32);
#endif
#if defined(CPPEXCEPTIONS_ENABLED)
	if (MacKey.Key().size() < 16 || MacKey.Key().size() > 32)
		throw CEX::Exception::CryptoDigestException("Blake2Sp256", "Mac Key has invalid length!");
#endif

	if (MacKey.Salt().size() != 0)
	{
#if defined(_DEBUG)
		assert(MacKey.Salt().size() == 8);
#endif
#if defined(CPPEXCEPTIONS_ENABLED)
		if (MacKey.Salt().size() != 8)
			throw CEX::Exception::CryptoDigestException("Blake2Sp256", "Salt has invalid length!");
#endif

		m_treeConfig[4] = CEX::Utility::IntUtils::BytesToLe32(MacKey.Salt(), 0);
		m_treeConfig[5] = CEX::Utility::IntUtils::BytesToLe32(MacKey.Salt(), 4);
	}

	if (MacKey.Info().size() != 0)
	{
#if defined(_DEBUG)
		assert(MacKey.Info().size() == 8);
#endif
#if defined(CPPEXCEPTIONS_ENABLED)
		if (MacKey.Info().size() != 8)
			throw CEX::Exception::CryptoDigestException("Blake2Sp256", "Info has invalid length!");
#endif

		m_treeConfig[6] = CEX::Utility::IntUtils::BytesToLe32(MacKey.Info(), 0);
		m_treeConfig[7] = CEX::Utility::IntUtils::BytesToLe32(MacKey.Info(), 4);
	}

	std::vector<uint8_t> mkey(BLOCK_SIZE, 0);
	memcpy(&mkey[0], &MacKey.Key()[0], MacKey.Key().size());
	m_treeParams.KeyLength() = (uint8_t)MacKey.Key().size();

	if (m_isParallel)
	{
		// initialize the leaf nodes and add the key 
		for (size_t i = 0; i < m_treeParams.ParallelDegree(); ++i)
		{
			memcpy(&m_msgBuffer[i * BLOCK_SIZE], &mkey[0], mkey.size());
			m_treeParams.NodeOffset() = i;
			Initialize(m_treeParams, m_State[i]);
		}
		m_msgLength = m_minParallel;
		m_treeParams.NodeOffset() = 0;
	}
	else
	{
		memcpy(&m_msgBuffer[0], &mkey[0], mkey.size());
		m_msgLength = BLOCK_SIZE;
		Initialize(m_treeParams, m_State[0]);
	}
}

void Blake2Sp256::Reset()
{
	m_msgLength = 0;
	memset(&m_msgBuffer[0], 0, m_msgBuffer.size());

	if (m_isParallel)
	{
		for (size_t i = 0; i < m_treeParams.ParallelDegree(); ++i)
		{
			m_treeParams.NodeOffset() = i;
			Initialize(m_treeParams, m_State[i]);
		}
		m_treeParams.NodeOffset() = 0;
	}
	else
	{
		Initialize(m_treeParams, m_State[0]);
	}
}

void Blake2Sp256::Update(uint8_t Input)
{
	std::vector<uint8_t> inp(1, Input);
	BlockUpdate(inp, 0, 1);
}

// *** Private Methods *** //

void Blake2Sp256::DetectCpu()
{
	CEX::Common::CpuDetect detect;
	m_hasIntrinsics = detect.HasMinIntrinsics();
}

void Blake2Sp256::Increase(Blake2sState &State, uint32_t Length)
{
	State.T[0] += Length;
	if (State.T[0] < Length)
		++State.T[1];
}

void Blake2Sp256::Increment(std::vector<uint8_t> &Counter)
{
	// increment the message counter
	CEX::Utility::IntUtils::Le32ToBytes(CEX::Utility::IntUtils::BytesToLe32(Counter, 0) + 1, Counter, 0);
}

void Blake2Sp256::Initialize(Blake2Params &Params, Blake2sState &State)
{
	memset(&State.T[0], 0, COUNTER_SIZE * sizeof(uint32_t));
	memset(&State.F[0], 0, FLAG_SIZE * sizeof(uint32_t));
	memcpy(&State.H[0], &m_cIV[0], CHAIN_SIZE * sizeof(uint32_t));

	m_treeConfig[0] = Params.DigestLength();
	m_treeConfig[0] |= Params.KeyLength() << 8;
	m_treeConfig[0] |= Params.FanOut() << 16;
	m_treeConfig[0] |= Params.MaxDepth() << 24;
	m_treeConfig[1] = Params.LeafLength();
	m_treeConfig[2] = (uint32_t)Params.NodeOffset();
	m_treeConfig[3] |= Params.NodeDepth() << 16;
	m_treeConfig[3] |= Params.InnerLength() << 24;

	State.H[0] ^= m_treeConfig[0];
	State.H[1] ^= m_treeConfig[1];
	State.H[2] ^= m_treeConfig[2];
	State.H[3] ^= m_treeConfig[3];
	State.H[4] ^= m_treeConfig[4];
	State.H[5] ^= m_treeConfig[5];
	State.H[6] ^= m_treeConfig[6];
	State.H[7] ^= m_treeConfig[7];
}

void Blake2Sp256::ProcessBlock(const std::vector<uint8_t> &Input, size_t InOffset, Blake2sState &State, size_t Length)
{
	Increase(State, (uint32_t)Length);
	if (m_hasIntrinsics)
		Blake2SCompress::SCompress(Input, InOffset, State, m_cIV);
	else
		Blake2SCompress::UCompress(Input, InOffset, State, m_cIV);
}

void Blake2Sp256::ProcessLeaf(const std::vector<uint8_t> &Input, size_t InOffset, Blake2sState &State, uint64_t Length)
{
	do
	{
		ProcessBlock(Input, InOffset, State, BLOCK_SIZE);
		InOffset += m_minParallel;
		Length -= m_minParallel;
	} 
	while (Length > 0);
}

NAMESPACE_DIGESTEND