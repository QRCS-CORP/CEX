#include "Blake512.h"
#include "Blake2.h"
#include "CpuDetect.h"
#include "IntegerTools.h"
#include "MemoryTools.h"
#include "ParallelTools.h"

NAMESPACE_DIGEST

using Utility::IntegerTools;
using Utility::MemoryTools;
using Utility::ParallelTools;

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
		MemoryTools::Clear(F, 0, F.size() * sizeof(ulong));
		MemoryTools::Clear(H, 0, H.size() * sizeof(ulong));
		MemoryTools::Clear(T, 0, T.size() * sizeof(ulong));
	}
};

const std::string Blake512::CLASS_NAME("Blake512");

//~~~Constructor~~~//

Blake512::Blake512(bool Parallel)
	:
	m_dgtState(Parallel ? DEF_PRLDEGREE : 1),
	m_isDestroyed(false),
	m_msgBuffer(Parallel ? 2 * DEF_PRLDEGREE * BLOCK_SIZE : BLOCK_SIZE),
	m_msgLength(0),
	m_parallelProfile(BLOCK_SIZE, false, STATE_PRECACHED, false, DEF_PRLDEGREE),
	m_treeDestroy(true),
	m_treeParams(Parallel ? BlakeParams(static_cast<byte>(DIGEST_SIZE), 2, DEF_PRLDEGREE, 0, static_cast<byte>(DIGEST_SIZE)) : BlakeParams(static_cast<byte>(DIGEST_SIZE), 1, 1, 0, 0))
{
	// TODO: implement parallel alternate for single core cpu
	if (Parallel && !m_parallelProfile.IsParallel())
	{
		throw CryptoDigestException(CLASS_NAME, std::string("Constructor"), std::string("Cpu does not support parallel processing!"), ErrorCodes::InvalidParam);
	}

	m_parallelProfile.IsParallel() = m_parallelProfile.IsParallel() ? Parallel : false;

	if (m_parallelProfile.IsParallel())
	{
		m_dgtState.resize(m_parallelProfile.ParallelMaxDegree());
		m_msgBuffer.resize(2 * (m_parallelProfile.ParallelMaxDegree() * BLOCK_SIZE));
	}

	Reset();
}

Blake512::Blake512(BlakeParams &Params)
	:
	m_dgtState(Params.FanOut() > 0 ? Params.FanOut() : 1),
	m_isDestroyed(false),
	m_msgBuffer(Params.FanOut() > 0 ? 2 * Params.FanOut() * BLOCK_SIZE : BLOCK_SIZE),
	m_msgLength(0),
	m_parallelProfile(BLOCK_SIZE, false, STATE_PRECACHED, false, Params.FanOut()),
	m_treeDestroy(false),
	m_treeParams(Params)
{
	if (m_treeParams.FanOut() > 1 && !m_parallelProfile.IsParallel())
	{
		throw CryptoDigestException(CLASS_NAME, std::string("Constructor"), std::string("Cpu does not support parallel processing!"), ErrorCodes::InvalidParam);
	}

	m_parallelProfile.IsParallel() = m_parallelProfile.IsParallel() ? m_treeParams.FanOut() > 1 : false;

	if (m_parallelProfile.IsParallel())
	{
		if (Params.LeafLength() != 0 && (Params.LeafLength() < BLOCK_SIZE || Params.LeafLength() % BLOCK_SIZE != 0))
		{
			throw CryptoDigestException(CLASS_NAME, std::string("Constructor"), std::string("The LeafLength parameter is invalid! Must be evenly divisible by digest block size!"), ErrorCodes::InvalidParam);
		}
		if (Params.FanOut() < 2 || Params.FanOut() % 2 != 0)
		{
			throw CryptoDigestException(CLASS_NAME, std::string("Constructor"), std::string("The FanOut parameter is invalid! Must be an even number greater than 1!"), ErrorCodes::InvalidParam);
		}
	}
	else
	{
		// fixed at defaults for sequential; depth 1, fanout 1, leaf length unlimited
		m_treeParams = BlakeParams(static_cast<byte>(DIGEST_SIZE));
	}

	Reset();
}

Blake512::~Blake512()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_msgLength = 0;

		IntegerTools::Clear(m_msgBuffer);
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
			MemoryTools::Clear(m_msgBuffer, m_msgLength, m_msgBuffer.size() - m_msgLength);
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
				MemoryTools::Copy(m_msgBuffer, m_parallelProfile.ParallelMinimumSize() + (i * BLOCK_SIZE), m_msgBuffer, i * BLOCK_SIZE, BLOCK_SIZE);
				m_msgLength -= BLOCK_SIZE;
			}

			if (m_msgLength % BLOCK_SIZE != 0)
			{
				prtBlk = blkCount - 1;
			}
		}

		// process last blocks
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
				MemoryTools::Clear(m_msgBuffer, (i * BLOCK_SIZE) + blkLen, BLOCK_SIZE - blkLen);
			}
			else if (m_msgLength < BLOCK_SIZE)
			{
				blkLen = m_msgLength;
				MemoryTools::Clear(m_msgBuffer, (i * BLOCK_SIZE) + blkLen, BLOCK_SIZE - blkLen);
			}

			Permute(m_msgBuffer, i * BLOCK_SIZE, m_dgtState[i], blkLen);
			m_msgLength -= BLOCK_SIZE;

			IntegerTools::LeULL512ToBlock(m_dgtState[i].H, 0, hashCodes, i * DIGEST_SIZE);
		}

		// set up the root node
		m_msgLength = 0;
		BlakeParams rootP = m_treeParams;
		rootP.NodeDepth() = 1;
		rootP.NodeOffset() = 0;
		rootP.MaxDepth() = 2;
		std::vector<ulong> config(CHAIN_SIZE);
		LoadState(m_dgtState[0], rootP, config);

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
		IntegerTools::LeULL512ToBlock(m_dgtState[0].H, 0, Output, 0);
	}
	else
	{
		size_t padLen = m_msgBuffer.size() - m_msgLength;
		if (padLen > 0)
		{
			MemoryTools::Clear(m_msgBuffer, m_msgLength, padLen);
		}

		m_dgtState[0].F[0] = 0xFFFFFFFFFFFFFFFFULL;
		Permute(m_msgBuffer, 0, m_dgtState[0], m_msgLength);
		IntegerTools::LeULL512ToBlock(m_dgtState[0].H, 0, Output, OutOffset);
	}

	Reset();

	return DIGEST_SIZE;
}

void Blake512::Initialize(Cipher::ISymmetricKey &MacKey)
{
	if (MacKey.Key().size() < 32 || MacKey.Key().size() > 64)
	{
		throw CryptoDigestException(Name(), std::string("Initialize"), std::string("Mac Key has invalid length!"), ErrorCodes::InvalidKey);
	}

	std::vector<ulong> config(CHAIN_SIZE);

	if (MacKey.Nonce().size() != 0)
	{
		if (MacKey.Nonce().size() != 16)
		{
			throw CryptoDigestException(Name(), std::string("Initialize"), std::string("Salt has invalid length!"), ErrorCodes::InvalidSize);
		}

		config[4] = IntegerTools::LeBytesTo64(MacKey.Nonce(), 0);
		config[5] = IntegerTools::LeBytesTo64(MacKey.Nonce(), 8);
	}

	if (MacKey.Info().size() != 0)
	{
		if (MacKey.Info().size() != 16)
		{
			throw CryptoDigestException(Name(), std::string("Initialize"), std::string("Info has invalid length"), ErrorCodes::InvalidSize);
		}

		config[6] = IntegerTools::LeBytesTo64(MacKey.Info(), 0);
		config[7] = IntegerTools::LeBytesTo64(MacKey.Info(), 8);
	}

	std::vector<byte> mkey(BLOCK_SIZE, 0);
	MemoryTools::Copy(MacKey.Key(), 0, mkey, 0, IntegerTools::Min(MacKey.Key().size(), mkey.size()));
	m_treeParams.KeyLength() = static_cast<byte>(MacKey.Key().size());

	if (m_parallelProfile.IsParallel())
	{
		// initialize the leaf nodes and add the key 
		for (size_t i = 0; i < m_treeParams.FanOut(); ++i)
		{
			MemoryTools::Copy(mkey, 0, m_msgBuffer, i * BLOCK_SIZE, mkey.size());
			m_treeParams.NodeOffset() = static_cast<byte>(i);
			LoadState(m_dgtState[i], m_treeParams, config);
		}
		m_msgLength = m_parallelProfile.ParallelMinimumSize();
		m_treeParams.NodeOffset() = 0;
	}
	else
	{
		MemoryTools::Copy(mkey, 0, m_msgBuffer, 0, mkey.size());
		m_msgLength = BLOCK_SIZE;
		LoadState(m_dgtState[0], m_treeParams, config);
	}
}

void Blake512::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0 || Degree % 2 != 0 || Degree > m_parallelProfile.ProcessorCount())
	{
		throw CryptoDigestException(Name(), std::string("ParallelMaxDegree"), std::string("Degree setting is invalid!"), ErrorCodes::IllegalOperation);
	}

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

void Blake512::Reset()
{
	std::vector<ulong> config(CHAIN_SIZE);

	if (m_parallelProfile.IsParallel())
	{
		for (size_t i = 0; i < m_treeParams.FanOut(); ++i)
		{
			m_treeParams.NodeOffset() = static_cast<byte>(i);
			LoadState(m_dgtState[i], m_treeParams, config);
		}
		m_treeParams.NodeOffset() = 0;
	}
	else
	{
		m_treeParams.NodeOffset() = 0;
		LoadState(m_dgtState[0], m_treeParams, config);
	}

	MemoryTools::Clear(m_msgBuffer, 0, m_msgBuffer.size());
	m_msgLength = 0;
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
					MemoryTools::Copy(Input, InOffset, m_msgBuffer, m_msgLength, RMDLEN);
				}

				m_msgLength = 0;
				Length -= RMDLEN;
				InOffset += RMDLEN;
				ttlLen -= m_msgBuffer.size();

				// empty the message buffer
				ParallelTools::ParallelFor(0, m_treeParams.FanOut(), [this, &Input, InOffset](size_t i)
				{
					Permute(m_msgBuffer, i * BLOCK_SIZE, m_dgtState[i], BLOCK_SIZE);
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
					ParallelTools::ParallelFor(0, m_treeParams.FanOut(), [this, &Input, InOffset, prcLen](size_t i)
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
					MemoryTools::Copy(Input, InOffset, m_msgBuffer, m_msgLength, RMDLEN);
				}

				Length -= RMDLEN;
				InOffset += RMDLEN;
				m_msgLength = m_msgBuffer.size();

				// process first half of buffer
				ParallelTools::ParallelFor(0, m_treeParams.FanOut(), [this, &Input, InOffset](size_t i)
				{
					Permute(m_msgBuffer, i * BLOCK_SIZE, m_dgtState[i], BLOCK_SIZE);
				});

				// left rotate the buffer
				m_msgLength -= m_parallelProfile.ParallelMinimumSize();
				const size_t FNLLEN = m_msgBuffer.size() / 2;
				MemoryTools::Copy(m_msgBuffer, FNLLEN, m_msgBuffer, 0, FNLLEN);
			}
		}
		else
		{
			if (m_msgLength + Length > BLOCK_SIZE)
			{
				const size_t RMDLEN = BLOCK_SIZE - m_msgLength;
				if (RMDLEN != 0)
				{
					MemoryTools::Copy(Input, InOffset, m_msgBuffer, m_msgLength, RMDLEN);
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
			MemoryTools::Copy(Input, InOffset, m_msgBuffer, m_msgLength, Length);
			m_msgLength += Length;
		}
	}
}

//~~~Private Functions~~~//

void Blake512::LoadState(Blake2bState &State, BlakeParams &Params, std::vector<ulong> &Config)
{
	MemoryTools::Clear(State.T, 0, COUNTER_SIZE * sizeof(ulong));
	MemoryTools::Clear(State.F, 0, FLAG_SIZE * sizeof(ulong));
	MemoryTools::Copy(Blake2::IV512, 0, State.H, 0, CHAIN_SIZE * sizeof(ulong));

	Params.GetConfig<ulong>(Config);
	MemoryTools::XOR512(Config, 0, State.H, 0);
}

void Blake512::Permute(const std::vector<byte> &Input, size_t InOffset, Blake2bState &State, size_t Length)
{
	IntegerTools::LeIncreaseW(State.T, State.T, Length);

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
