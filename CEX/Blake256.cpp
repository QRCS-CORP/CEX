#include "Blake256.h"
#include "Blake.h"
#include "CpuDetect.h"
#include "IntegerTools.h"
#include "MemoryTools.h"
#include "ParallelTools.h"

NAMESPACE_DIGEST

using Enumeration::DigestConvert;
using Utility::IntegerTools;
using Utility::MemoryTools;
using Utility::ParallelTools;

class Blake256::Blake2sState
{
public:

	std::array<uint, 2> F;
	std::array<uint, 8> H;
	std::array<uint, 2> T;

	Blake2sState()
	{
	}

	~Blake2sState()
	{
		Reset();
	}

	void Reset()
	{
		MemoryTools::Clear(F, 0, F.size() * sizeof(uint));
		MemoryTools::Clear(H, 0, H.size() * sizeof(uint));
		MemoryTools::Clear(T, 0, T.size() * sizeof(uint));
	}
};

//~~~Constructor~~~//

Blake256::Blake256(bool Parallel)
	:
	m_dgtState(Parallel ? DEF_PRLDEGREE : 1),
	m_msgBuffer(Parallel ? 2 * DEF_PRLDEGREE * Blake::BLAKE256_RATE_SIZE : Blake::BLAKE256_RATE_SIZE),
	m_msgLength(0),
	m_parallelProfile(Blake::BLAKE256_RATE_SIZE, false, STATE_PRECACHED, false, DEF_PRLDEGREE),
	m_treeParams(Parallel ? BlakeParams(static_cast<byte>(Blake::BLAKE256_DIGEST_SIZE), 0x02, static_cast<byte>(DEF_PRLDEGREE), 0x00, static_cast<byte>(Blake::BLAKE256_DIGEST_SIZE)) : 
		BlakeParams(static_cast<byte>(Blake::BLAKE256_DIGEST_SIZE), 0x01, 0x01, 0x00, 0x00))
{
	if (Parallel && !m_parallelProfile.IsParallel())
	{
		throw CryptoDigestException(DigestConvert::ToName(Digests::Blake256), std::string("Constructor"), std::string("This cpu does not support parallel processing!"), ErrorCodes::InvalidParam);
	}

	Reset();
}

Blake256::Blake256(BlakeParams &Params)
	:
	m_dgtState(Params.FanOut() != 0 && Params.FanOut() <= MAX_PRLDEGREE ? Params.FanOut() :
		throw CryptoDigestException(DigestConvert::ToName(Digests::Blake256), std::string("Constructor"), std::string("The FanOut parameter can not be zero or exceed the maximum of 64!"), ErrorCodes::IllegalOperation)),
	m_msgBuffer(Params.FanOut() > 0 ? 2 * Params.FanOut() * Blake::BLAKE256_RATE_SIZE : 
		Blake::BLAKE256_RATE_SIZE),
	m_msgLength(0),
	m_parallelProfile(Blake::BLAKE256_RATE_SIZE, false, STATE_PRECACHED, false, Params.FanOut()),
	m_treeParams(Params)
{
	if (m_parallelProfile.IsParallel())
	{
		if (Params.LeafLength() != 0 && (Params.LeafLength() < Blake::BLAKE256_RATE_SIZE || Params.LeafLength() % Blake::BLAKE256_RATE_SIZE != 0))
		{
			throw CryptoDigestException(DigestConvert::ToName(Digests::Blake256), std::string("Constructor"), std::string("The LeafLength parameter is invalid! Must be evenly divisible by digest block size!"), ErrorCodes::InvalidSize);
		}
		if (Params.FanOut() < 2 || Params.FanOut() % 2 != 0)
		{
			throw CryptoDigestException(DigestConvert::ToName(Digests::Blake256), std::string("Constructor"), std::string("The FanOut parameter is invalid! Must be an even number greater than 1!"), ErrorCodes::InvalidParam);
		}
	}
	else
	{
		// fixed at defaults for sequential; depth 1, fanout 1, leaf length unlimited
		m_treeParams = BlakeParams(static_cast<byte>(Blake::BLAKE256_DIGEST_SIZE), 0, 1, 1, 0, 0, 0, 0, Params.DistributionCode());
	}

	Reset();
}

Blake256::~Blake256()
{
	IntegerTools::Clear(m_msgBuffer);
	m_msgLength = 0;
	m_dgtState.clear();
}

//~~~Accessors~~~//

size_t Blake256::BlockSize() 
{ 
	return Blake::BLAKE256_RATE_SIZE; 
}

size_t Blake256::DigestSize() 
{ 
	return Blake::BLAKE256_DIGEST_SIZE; 
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
	std::string name;

	if (m_treeParams.FanOut() > 1)
	{
		name = DigestConvert::ToName(Enumeral()) + std::string("-P") + IntegerTools::ToString(m_parallelProfile.ParallelMaxDegree());
	}
	else
	{
		name = DigestConvert::ToName(Enumeral());
	}

	return name;
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
	if (Output.size() < Blake::BLAKE256_DIGEST_SIZE)
	{
		throw CryptoDigestException(Name(), std::string("Compute"), std::string("The output vector is too small!"), ErrorCodes::InvalidSize);
	}

	Update(Input, 0, Input.size());
	Finalize(Output, 0);
}

void Blake256::Finalize(std::vector<byte> &Output, size_t OutOffset)
{
	if (Output.size() - OutOffset < Blake::BLAKE256_DIGEST_SIZE)
	{
		throw CryptoDigestException(Name(), std::string("Finalize"), std::string("The output vector is too small!"), ErrorCodes::InvalidSize);
	}

	size_t bcnt;
	size_t blen;
	size_t i;
	uint pblock;

	if (m_treeParams.FanOut() > 1)
	{
		std::vector<byte> codes(m_treeParams.FanOut() * Blake::BLAKE256_DIGEST_SIZE);

		// clear the unused buffer
		MemoryTools::Clear(m_msgBuffer, m_msgLength, m_msgBuffer.size() - m_msgLength);

		const size_t MINPRL = m_treeParams.FanOut() * Blake::BLAKE256_RATE_SIZE;
		pblock = 0xFFFFFFFFUL;

		// process unaligned blocks
		if (m_msgLength > MINPRL)
		{
			bcnt = (m_msgLength % Blake::BLAKE256_RATE_SIZE != 0) ? ((m_msgLength - MINPRL) / Blake::BLAKE256_RATE_SIZE) + 1 :
				((m_msgLength - MINPRL) / Blake::BLAKE256_RATE_SIZE);

			for (i = 0; i < bcnt; ++i)
			{
				// process partial block set
				IntegerTools::LeIncreaseW(m_dgtState[i].T, m_dgtState[i].T, Blake::BLAKE256_RATE_SIZE);
				Permute(m_msgBuffer, (i * Blake::BLAKE256_RATE_SIZE), m_dgtState[i]);
				MemoryTools::Copy(m_msgBuffer, MINPRL + (i * Blake::BLAKE256_RATE_SIZE), m_msgBuffer, (i * Blake::BLAKE256_RATE_SIZE), Blake::BLAKE256_RATE_SIZE);
				m_msgLength -= Blake::BLAKE256_RATE_SIZE;
			}

			if (m_msgLength % Blake::BLAKE256_RATE_SIZE != 0)
			{
				pblock = static_cast<uint>(bcnt - 1);
			}
		}

		// process last blocks
		for (i = 0; i < m_treeParams.FanOut(); ++i)
		{
			// apply f0 bit reversal constant to final blocks
			m_dgtState[i].F[0] = 0xFFFFFFFFUL;
			blen = Blake::BLAKE256_RATE_SIZE;

			// f1 constant on last block
			if (i == m_treeParams.FanOut() - 1)
			{
				m_dgtState[i].F[1] = 0xFFFFFFFFUL;
			}

			if (i == pblock)
			{
				blen = m_msgLength % Blake::BLAKE256_RATE_SIZE;
				m_msgLength += Blake::BLAKE256_RATE_SIZE - blen;
				MemoryTools::Clear(m_msgBuffer, (i * Blake::BLAKE256_RATE_SIZE) + blen, Blake::BLAKE256_RATE_SIZE - blen);
			}
			else if (m_msgLength < Blake::BLAKE256_RATE_SIZE)
			{
				blen = m_msgLength;
				MemoryTools::Clear(m_msgBuffer, (i * Blake::BLAKE256_RATE_SIZE) + blen, Blake::BLAKE256_RATE_SIZE - blen);
			}

			IntegerTools::LeIncreaseW(m_dgtState[i].T, m_dgtState[i].T, blen);
			Permute(m_msgBuffer, i * Blake::BLAKE256_RATE_SIZE, m_dgtState[i]);
			m_msgLength -= Blake::BLAKE256_RATE_SIZE;

			IntegerTools::LeUL256ToBlock(m_dgtState[i].H, 0, codes, i * Blake::BLAKE256_DIGEST_SIZE);
		}

		// set up the root node
		m_msgLength = 0;
		BlakeParams rootp = m_treeParams;
		rootp.NodeDepth() = 1;
		rootp.NodeOffset() = 0;
		rootp.MaxDepth() = 2;
		std::vector<uint> config(CONFIG_SIZE);
		LoadState(rootp, config, m_dgtState[0]);

		// load blocks
		for (i = 0; i < m_treeParams.FanOut(); ++i)
		{
			Update(codes, i * Blake::BLAKE256_DIGEST_SIZE, Blake::BLAKE256_DIGEST_SIZE);
		}

		// compress all but last block
		for (i = 0; i < codes.size() - Blake::BLAKE256_RATE_SIZE; i += Blake::BLAKE256_RATE_SIZE)
		{
			IntegerTools::LeIncreaseW(m_dgtState[0].T, m_dgtState[0].T, Blake::BLAKE256_RATE_SIZE);
			Permute(m_msgBuffer, i, m_dgtState[0]);
		}

		// apply f0 and f1 flags
		m_dgtState[0].F[0] = 0xFFFFFFFFUL;
		m_dgtState[0].F[1] = 0xFFFFFFFFUL;
		// last compression
		IntegerTools::LeIncreaseW(m_dgtState[0].T, m_dgtState[0].T, Blake::BLAKE256_RATE_SIZE);
		Permute(m_msgBuffer, m_msgLength - Blake::BLAKE256_RATE_SIZE, m_dgtState[0]);
		// output the code
		IntegerTools::LeUL256ToBlock(m_dgtState[0].H, 0, Output, OutOffset);
	}
	else
	{
		const size_t PADLEN = m_msgBuffer.size() - m_msgLength;

		if (PADLEN > 0)
		{
			MemoryTools::Clear(m_msgBuffer, m_msgLength, PADLEN);
		}

		m_dgtState[0].F[0] = 0xFFFFFFFFUL;
		IntegerTools::LeIncreaseW(m_dgtState[0].T, m_dgtState[0].T, m_msgLength);
		Permute(m_msgBuffer, 0, m_dgtState[0]);
		IntegerTools::LeUL256ToBlock(m_dgtState[0].H, 0, Output, OutOffset);
	}

	Reset();
}

void Blake256::Initialize(Cipher::ISymmetricKey &MacKey)
{
	if (MacKey.Key().size() < 16 || MacKey.Key().size() > 32)
	{
		throw CryptoDigestException(Name(), std::string("Initialize"), std::string("Mac Key has invalid length!"), ErrorCodes::InvalidKey);
	}

	std::vector<uint> config(CONFIG_SIZE);
	size_t i;

	if (MacKey.Nonce().size() != 0)
	{
		if (MacKey.Nonce().size() != 8)
		{
			throw CryptoDigestException(Name(), std::string("Initialize"), std::string("Salt has invalid length!"), ErrorCodes::InvalidNonce);
		}

		config[4] = IntegerTools::LeBytesTo32(MacKey.Nonce(), 0);
		config[5] = IntegerTools::LeBytesTo32(MacKey.Nonce(), 4);
	}

	if (MacKey.Info().size() != 0)
	{
		if (MacKey.Info().size() != 8)
		{
			throw CryptoDigestException(Name(), std::string("Initialize"), std::string("Info has invalid length"), ErrorCodes::InvalidInfo);
		}

		config[6] = IntegerTools::LeBytesTo32(MacKey.Info(), 0);
		config[7] = IntegerTools::LeBytesTo32(MacKey.Info(), 4);
	}

	std::vector<byte> mkey(Blake::BLAKE256_RATE_SIZE, 0x00);
	MemoryTools::Copy(MacKey.Key(), 0, mkey, 0, IntegerTools::Min(MacKey.Key().size(), mkey.size()));
	m_treeParams.KeyLength() = static_cast<byte>(MacKey.Key().size());

	if (m_treeParams.FanOut() > 1)
	{
		// initialize the leaf nodes and add the key 
		for (i = 0; i < m_treeParams.FanOut(); ++i)
		{
			MemoryTools::Copy(mkey, 0, m_msgBuffer, i * Blake::BLAKE256_RATE_SIZE, mkey.size());
			m_treeParams.NodeOffset() = static_cast<byte>(i);
			LoadState( m_treeParams, config, m_dgtState[i]);
		}
		m_msgLength = m_parallelProfile.ParallelMinimumSize();
		m_treeParams.NodeOffset() = 0;
	}
	else
	{
		MemoryTools::Copy(mkey, 0, m_msgBuffer, 0, mkey.size());
		m_msgLength = Blake::BLAKE256_RATE_SIZE;
		LoadState(m_treeParams, config, m_dgtState[0]);
	}
}

void Blake256::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0 || Degree % 2 != 0 || Degree > MAX_PRLDEGREE)
	{
		throw CryptoDigestException(Name(), std::string("ParallelMaxDegree"), std::string("Degree setting is invalid!"), ErrorCodes::NotSupported);
	}

	m_parallelProfile.SetMaxDegree(Degree);
	m_dgtState.clear();
	m_dgtState.resize(Degree);
	m_msgBuffer.clear();
	m_msgBuffer.resize(Degree * Blake::BLAKE256_RATE_SIZE);

	if (Degree > 1 && m_parallelProfile.ProcessorCount() > 1)
	{
		m_treeParams.FanOut() = static_cast<byte>(Degree);
		m_treeParams.MaxDepth() = 2;
		m_treeParams.InnerLength() = static_cast<byte>(Blake::BLAKE256_DIGEST_SIZE);
		m_parallelProfile.IsParallel() = true;
	}
	else
	{
		m_treeParams = BlakeParams(static_cast<byte>(Blake::BLAKE256_DIGEST_SIZE));
		m_parallelProfile.IsParallel() = false;
	}

	Reset();
}

void Blake256::Reset()
{
	std::vector<uint> config(CONFIG_SIZE);
	size_t i;

	if (m_treeParams.FanOut() > 1)
	{
		for (i = 0; i < m_treeParams.FanOut(); ++i)
		{
			m_treeParams.NodeOffset() = static_cast<byte>(i);
			LoadState(m_treeParams, config, m_dgtState[i]);
		}

		m_treeParams.NodeOffset() = 0;
	}
	else
	{
		m_treeParams.NodeOffset() = 0;
		LoadState(m_treeParams, config, m_dgtState[0]);
	}

	MemoryTools::Clear(m_msgBuffer, 0, m_msgBuffer.size());
	m_msgLength = 0;
}

void Blake256::Update(byte Input)
{
	std::vector<byte> tmp(1, Input);
	Update(tmp, 0, 1);
}

void Blake256::Update(uint Input)
{
	std::vector<byte> tmp(sizeof(uint));
	IntegerTools::Le32ToBytes(Input, tmp, 0);
	Update(tmp, 0, tmp.size());
}

void Blake256::Update(ulong Input)
{
	std::vector<byte> tmp(sizeof(ulong));
	IntegerTools::Le64ToBytes(Input, tmp, 0);
	Update(tmp, 0, tmp.size());
}

void Blake256::Update(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	CEXASSERT(Input.size() - InOffset >= Length, "The input buffer is too short!");

	size_t plen;
	size_t tlen;

	if (Length != 0)
	{
		if (m_treeParams.FanOut() > 1)
		{
			tlen = Length + m_msgLength;
			const size_t PRLMIN = m_msgBuffer.size() + (m_parallelProfile.ParallelMinimumSize() - Blake::BLAKE256_RATE_SIZE);

			// input larger than min parallel; process buffer and loop-in remainder
			if (tlen > PRLMIN)
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
				tlen -= m_msgBuffer.size();

				// empty the entire message buffer
				ParallelTools::ParallelFor(0, m_treeParams.FanOut(), [this, &Input, InOffset](size_t i)
				{
					IntegerTools::LeIncreaseW(m_dgtState[i].T, m_dgtState[i].T, Blake::BLAKE256_RATE_SIZE);
					Permute(m_msgBuffer, i * Blake::BLAKE256_RATE_SIZE, m_dgtState[i]);
				});

				// loop in the remainder (no buffering)
				if (Length > PRLMIN)
				{
					// calculate working set size
					plen = Length - m_parallelProfile.ParallelMinimumSize();

					if (plen % m_parallelProfile.ParallelMinimumSize() != 0)
					{
						plen -= (plen % m_parallelProfile.ParallelMinimumSize());
					}

					// process large blocks
					ParallelTools::ParallelFor(0, m_treeParams.FanOut(), [this, &Input, InOffset, plen](size_t i)
					{
						ProcessLeaf(Input, InOffset + (i * Blake::BLAKE256_RATE_SIZE), plen, m_dgtState[i]);
					});

					Length -= plen;
					InOffset += plen;
					tlen -= plen;
				}
			}

			// remainder exceeds buffer size; process first 4 blocks and shift buffer left
			if (tlen > m_msgBuffer.size())
			{
				// fill buffer
				const size_t RMDLEN = m_msgBuffer.size() - m_msgLength;
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
					IntegerTools::LeIncreaseW(m_dgtState[i].T, m_dgtState[i].T, Blake::BLAKE256_RATE_SIZE);
					Permute(m_msgBuffer, i * Blake::BLAKE256_RATE_SIZE, m_dgtState[i]);
				});

				// left rotate the buffer
				m_msgLength -= m_parallelProfile.ParallelMinimumSize();
				const size_t FNLLEN = m_msgBuffer.size() / 2;
				MemoryTools::Copy(m_msgBuffer, FNLLEN, m_msgBuffer, 0, FNLLEN);
			}
		}
		else
		{
			if (m_msgLength + Length > Blake::BLAKE256_RATE_SIZE)
			{
				const size_t RMDLEN = Blake::BLAKE256_RATE_SIZE - m_msgLength;
				if (RMDLEN != 0)
				{
					MemoryTools::Copy(Input, InOffset, m_msgBuffer, m_msgLength, RMDLEN);
				}

				IntegerTools::LeIncreaseW(m_dgtState[0].T, m_dgtState[0].T, Blake::BLAKE256_RATE_SIZE);
				Permute(m_msgBuffer, 0, m_dgtState[0]);
				m_msgLength = 0;
				InOffset += RMDLEN;
				Length -= RMDLEN;
			}

			// loop until last block
			while (Length > Blake::BLAKE256_RATE_SIZE)
			{
				IntegerTools::LeIncreaseW(m_dgtState[0].T, m_dgtState[0].T, Blake::BLAKE256_RATE_SIZE);
				Permute(Input, InOffset, m_dgtState[0]);
				InOffset += Blake::BLAKE256_RATE_SIZE;
				Length -= Blake::BLAKE256_RATE_SIZE;
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

void Blake256::LoadState(BlakeParams &Params, std::vector<uint> &Config, Blake2sState &State)
{
	MemoryTools::Clear(State.T, 0, State.T.size() * sizeof(uint));
	MemoryTools::Clear(State.F, 0, State.F.size() * sizeof(uint));
	MemoryTools::Copy(Blake::IV256, 0, State.H, 0, State.H.size() * sizeof(uint));

	Params.GetConfig<uint>(Config);
	MemoryTools::XOR256(Config, 0, State.H, 0);
}

void Blake256::Permute(const std::vector<byte> &Input, size_t InOffset, Blake2sState &State)
{
	std::array<uint, 8> iv {
		Blake::IV256[0],
		Blake::IV256[1],
		Blake::IV256[2],
		Blake::IV256[3],
		Blake::IV256[4] ^ State.T[0],
		Blake::IV256[5] ^ State.T[1],
		Blake::IV256[6] ^ State.F[0],
		Blake::IV256[7] ^ State.F[1] };

#if defined(__AVX__)
	Blake::PermuteR10P512V(Input, InOffset, State.H, iv);
#else
#	if defined(CEX_DIGEST_COMPACT)
		Blake::PermuteR10P512C(Input, InOffset, State.H, iv);
#	else
		Blake::PermuteR10P512U(Input, InOffset, State.H, iv);
#	endif
#endif
}

void Blake256::ProcessLeaf(const std::vector<byte> &Input, size_t InOffset, size_t Length, Blake2sState &State)
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
