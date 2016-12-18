#include "BlakeB512.h"
#include "Blake2B.h"
#include "ArrayUtils.h"
#include "CpuDetect.h"
#include "IntUtils.h"
#include "ParallelUtils.h"

NAMESPACE_DIGEST

using Utility::IntUtils;

//~~~Public Methods~~~//

void BlakeB512::BlockUpdate(const std::vector<uint8_t> &Input, size_t InOffset, size_t Length)
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
			Utility::ParallelUtils::ParallelFor(0, m_treeParams.ParallelDegree(), [this, &Input, InOffset](size_t i)
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
				Utility::ParallelUtils::ParallelFor(0, m_treeParams.ParallelDegree(), [this, &Input, InOffset, prcLen](size_t i)
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
			Utility::ParallelUtils::ParallelFor(0, m_treeParams.ParallelDegree(), [this, &Input, InOffset](size_t i)
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

void BlakeB512::ComputeHash(const std::vector<uint8_t> &Input, std::vector<uint8_t> &Output)
{
	BlockUpdate(Input, 0, Input.size());
	DoFinal(Output, 0);
	Reset();
}

void BlakeB512::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_isParallel = false;
		m_leafSize = 0;
		m_minParallel = 0;
		m_msgLength = 0;
		m_parallelBlockSize = 0;

		try
		{
			Utility::ArrayUtils::ClearVector(m_cIV);
			Utility::ArrayUtils::ClearVector(m_msgBuffer);
			Utility::ArrayUtils::ClearVector(m_treeConfig);

			for (size_t i = 0; i < m_State.size(); ++i)
				m_State[i].Reset();

			if (m_treeDestroy)
				m_treeParams.Reset();
		}
		catch (std::exception& ex)
		{
			throw CryptoDigestException("BlakeB512:Destroy", "Could not clear all variables!", std::string(ex.what()));
		}
	}
}

size_t BlakeB512::DoFinal(std::vector<uint8_t> &Output, const size_t OutOffset)
{
	if (m_isParallel)
	{
		std::vector<uint8_t> hashCodes(m_treeParams.ParallelDegree() * DIGEST_SIZE);

		// padding
		if (m_msgLength < m_msgBuffer.size())
			memset(&m_msgBuffer[m_msgLength], 0, m_msgBuffer.size() - m_msgLength);

		std::vector<uint8_t> padLen(m_treeParams.ParallelDegree(), BLOCK_SIZE);
		uint64_t prtBlk = ULL_MAX;

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
				prtBlk = blkCount - 1;
		}

		// process last 4 blocks
		for (size_t i = 0; i < m_treeParams.ParallelDegree(); ++i)
		{
			// apply f0 bit reversal constant to final blocks
			m_State[i].F[0] = ULL_MAX;
			size_t blkLen = BLOCK_SIZE;

			// f1 constant on last block
			if (i == m_treeParams.ParallelDegree() - 1)
				m_State[i].F[1] = ULL_MAX;

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

			ProcessBlock(m_msgBuffer, i * BLOCK_SIZE, m_State[i], blkLen);
			m_msgLength -= BLOCK_SIZE;

			IntUtils::Le512ToBlock(m_State[i].H, hashCodes, i * DIGEST_SIZE);
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
		m_State[0].F[0] = ULL_MAX;
		m_State[0].F[1] = ULL_MAX;
		// last compression
		ProcessBlock(m_msgBuffer, m_msgLength - BLOCK_SIZE, m_State[0], BLOCK_SIZE);
		// output the code
		IntUtils::Le512ToBlock(m_State[0].H, Output, 0);
	}
	else
	{
		size_t padLen = m_msgBuffer.size() - m_msgLength;
		if (padLen > 0)
			memset(&m_msgBuffer[m_msgLength], 0, padLen);

		m_State[0].F[0] = ULL_MAX;
		ProcessBlock(m_msgBuffer, 0, m_State[0], m_msgLength);
		IntUtils::Le512ToBlock(m_State[0].H, Output, OutOffset);
	}

	Reset();

	return DIGEST_SIZE;
}

size_t BlakeB512::Generate(Key::Symmetric::ISymmetricKey &MacKey, std::vector<uint8_t> &Output)
{
	if (Output.size() == 0)
		throw Exception::CryptoDigestException("BlakeB512:Generate", "Buffer size must be at least 1 byte!");
	if (MacKey.Key().size() < DIGEST_SIZE)
		throw Exception::CryptoDigestException("BlakeB512:Generate", "The key must be at least 64 bytes long!");

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

void BlakeB512::LoadMacKey(Key::Symmetric::ISymmetricKey &MacKey)
{
	if (MacKey.Key().size() < 32 || MacKey.Key().size() > 64)
		throw Exception::CryptoDigestException("BlakeB512", "Mac Key has invalid length!");

	if (MacKey.Nonce().size() != 0)
	{
		if (MacKey.Nonce().size() != 16)
			throw Exception::CryptoDigestException("BlakeB512", "Salt has invalid length!");

		m_treeConfig[4] = IntUtils::BytesToLe64(MacKey.Nonce(), 0);
		m_treeConfig[5] = IntUtils::BytesToLe64(MacKey.Nonce(), 8);
	}

	if (MacKey.Info().size() != 0)
	{
		if (MacKey.Info().size() != 16)
			throw Exception::CryptoDigestException("BlakeB512", "Info has invalid length!");

		m_treeConfig[6] = IntUtils::BytesToLe64(MacKey.Info(), 0);
		m_treeConfig[7] = IntUtils::BytesToLe64(MacKey.Info(), 8);
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

void BlakeB512::Reset()
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

void BlakeB512::Update(uint8_t Input)
{
	std::vector<uint8_t> inp(1, Input);
	BlockUpdate(inp, 0, 1);
}

//~~~Private Methods~~~//

void BlakeB512::Detect()
{
	Common::CpuDetect detect;
	m_hasSSE = detect.SSE();
}

void BlakeB512::Increase(Blake2bState &State, uint64_t Length)
{
	State.T[0] += Length;
	if (State.T[0] < Length)
		++State.T[1];
}

void BlakeB512::Increment(std::vector<uint8_t> &Counter)
{
	IntUtils::Le64ToBytes(IntUtils::BytesToLe64(Counter, 0) + 1, Counter, 0);
}

void BlakeB512::Initialize(Blake2Params &Params, Blake2bState &State)
{
	memset(&State.T[0], 0, COUNTER_SIZE * sizeof(uint64_t));
	memset(&State.F[0], 0, FLAG_SIZE * sizeof(uint64_t));
	memcpy(&State.H[0], &m_cIV[0], CHAIN_SIZE * sizeof(uint64_t));

	m_treeConfig[0] = Params.DigestLength();
	m_treeConfig[0] |= Params.KeyLength() << 8;
	m_treeConfig[0] |= Params.FanOut() << 16;
	m_treeConfig[0] |= Params.MaxDepth() << 24;
	m_treeConfig[0] |= (uint64_t)Params.LeafLength() << 32;
	m_treeConfig[1] = Params.NodeOffset();
	m_treeConfig[2] = Params.NodeDepth();
	m_treeConfig[2] |= Params.InnerLength() << 8;

	State.H[0] ^= m_treeConfig[0];
	State.H[1] ^= m_treeConfig[1];
	State.H[2] ^= m_treeConfig[2];
	State.H[3] ^= m_treeConfig[3];
	State.H[4] ^= m_treeConfig[4];
	State.H[5] ^= m_treeConfig[5];
	State.H[6] ^= m_treeConfig[6];
	State.H[7] ^= m_treeConfig[7];
}

void BlakeB512::ProcessBlock(const std::vector<uint8_t> &Input, size_t InOffset, Blake2bState &State, size_t Length)
{
	Increase(State, Length);

	if (m_hasSSE)
		Blake2B::CompressW(Input, InOffset, State, m_cIV);
	else
		Blake2B::Compress(Input, InOffset, State, m_cIV);
}

void BlakeB512::ProcessLeaf(const std::vector<uint8_t> &Input, size_t InOffset, Blake2bState &State, uint64_t Length)
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