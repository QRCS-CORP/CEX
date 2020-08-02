#include "Blake512.h"
#include "Blake.h"
#include "CpuDetect.h"
#include "IntegerTools.h"
#include "MemoryTools.h"
#include "ParallelTools.h"

NAMESPACE_DIGEST

using Enumeration::DigestConvert;
using Tools::IntegerTools;
using Tools::MemoryTools;
using Tools::ParallelTools;

class Blake512::Blake2bState
{
public:

	std::array<ulong, 2> F = { 0 };
	std::array<ulong, 8> H = { 0 };
	std::array<ulong, 2> T = { 0 };

	Blake2bState()
	{
	}

	~Blake2bState()
	{
		Reset();
	}

	void Reset()
	{
		MemoryTools::Clear(F, 0, F.size() * sizeof(ulong));
		MemoryTools::Clear(H, 0, H.size() * sizeof(ulong));
		MemoryTools::Clear(T, 0, T.size() * sizeof(ulong));
	}
};

//~~~Constructor~~~//

Blake512::Blake512(bool Parallel)
	:
	m_dgtState(Parallel ? 
		DEF_PRLDEGREE : 
		1),
	m_msgBuffer(Parallel ? 
		2UL * DEF_PRLDEGREE * Blake::BLAKE512_RATE_SIZE : 
		Blake::BLAKE512_RATE_SIZE),
	m_msgLength(0),
	m_parallelProfile(Blake::BLAKE512_RATE_SIZE, false, STATE_PRECACHED, false, DEF_PRLDEGREE),
	m_treeParams(Parallel ? 
		BlakeParams(static_cast<byte>(Blake::BLAKE512_DIGEST_SIZE), 0x02, static_cast<byte>(DEF_PRLDEGREE), 0x00, static_cast<byte>(Blake::BLAKE512_DIGEST_SIZE)) : 
		BlakeParams(static_cast<byte>(Blake::BLAKE512_DIGEST_SIZE), 0x01, 0x01, 0x00, 0x00))
{
	//m_parallelProfile.IsParallel() = (m_parallelProfile.IsParallel() == true) ? Parallel : false;

	if (Parallel && !m_parallelProfile.IsParallel())
	{
		throw CryptoDigestException(DigestConvert::ToName(Digests::Blake512), std::string("Constructor"), std::string("This cpu does not support parallel processing!"), ErrorCodes::InvalidParam);
	}

	Reset();
}

Blake512::Blake512(BlakeParams &Params)
	:
	m_dgtState(Params.FanOut() != 0 && Params.FanOut() <= MAX_PRLDEGREE ? 
		Params.FanOut() :
		throw CryptoDigestException(DigestConvert::ToName(Digests::Blake512), std::string("Constructor"), std::string("The FanOut parameter can not be zero or exceed the maximum of 64!"), ErrorCodes::IllegalOperation)),
	m_msgBuffer(Params.FanOut() > 0 ? 
		2UL * Params.FanOut() * Blake::BLAKE512_RATE_SIZE :
		Blake::BLAKE512_RATE_SIZE),
	m_msgLength(0),
	m_parallelProfile(Blake::BLAKE512_RATE_SIZE, false, STATE_PRECACHED, false, Params.FanOut()),
	m_treeParams(Params)
{
	//m_parallelProfile.IsParallel() == true ? m_treeParams.FanOut() > 1 : false;

	if (m_parallelProfile.IsParallel())
	{
		if (Params.LeafLength() != 0 && (Params.LeafLength() < Blake::BLAKE512_RATE_SIZE || Params.LeafLength() % Blake::BLAKE512_RATE_SIZE != 0))
		{
			throw CryptoDigestException(DigestConvert::ToName(Digests::Blake512), std::string("Constructor"), std::string("The LeafLength parameter is invalid! Must be evenly divisible by digest block size!"), ErrorCodes::InvalidSize);
		}
		if (Params.FanOut() < 2 || Params.FanOut() % 2 != 0)
		{
			throw CryptoDigestException(DigestConvert::ToName(Digests::Blake512), std::string("Constructor"), std::string("The FanOut parameter is invalid! Must be an even number greater than 1!"), ErrorCodes::InvalidParam);
		}
	}
	else
	{
		// fixed at defaults for sequential; depth 1, fanout 1, leaf length unlimited
		m_treeParams = BlakeParams(static_cast<byte>(Blake::BLAKE512_DIGEST_SIZE));
	}

	Reset();
}

Blake512::~Blake512()
{
	m_msgLength = 0;
	IntegerTools::Clear(m_msgBuffer);
	m_dgtState.clear();
}

//~~~Accessors~~~//

size_t Blake512::BlockSize() 
{ 
	return Blake::BLAKE512_RATE_SIZE; 
}

size_t Blake512::DigestSize()
{
	return Blake::BLAKE512_DIGEST_SIZE; 
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
	if (Output.size() < Blake::BLAKE512_DIGEST_SIZE)
	{
		throw CryptoDigestException(Name(), std::string("Compute"), std::string("The output vector is too small!"), ErrorCodes::InvalidSize);
	}

	Update(Input, 0, Input.size());
	Finalize(Output, 0);
}

void Blake512::Finalize(std::vector<byte> &Output, size_t OutOffset)
{
	if (Output.size() - OutOffset < Blake::BLAKE512_DIGEST_SIZE)
	{
		throw CryptoDigestException(Name(), std::string("Finalize"), std::string("The output vector is too small!"), ErrorCodes::InvalidSize);
	}

	size_t bcnt;
	size_t blen;
	size_t i;
	ulong pblk;

	if (m_treeParams.FanOut() > 1)
	{
		std::vector<byte> codes(m_treeParams.FanOut() * Blake::BLAKE512_DIGEST_SIZE);

		// clear the unused buffer
		MemoryTools::Clear(m_msgBuffer, m_msgLength, m_msgBuffer.size() - m_msgLength);
		pblk = 0xFFFFFFFFFFFFFFFFULL;

		// process unaligned blocks
		if (m_msgLength > m_parallelProfile.ParallelMinimumSize())
		{
			bcnt = (m_msgLength % Blake::BLAKE512_RATE_SIZE != 0) ? ((m_msgLength - m_parallelProfile.ParallelMinimumSize()) / Blake::BLAKE512_RATE_SIZE) + 1 :
				((m_msgLength - m_parallelProfile.ParallelMinimumSize()) / Blake::BLAKE512_RATE_SIZE);

			for (i = 0; i < bcnt; ++i)
			{
				// process partial block set
				IntegerTools::LeIncreaseW(m_dgtState[i].T, m_dgtState[i].T, Blake::BLAKE512_RATE_SIZE);
				Permute(m_msgBuffer, (i * Blake::BLAKE512_RATE_SIZE), m_dgtState[i]);
				MemoryTools::Copy(m_msgBuffer, m_parallelProfile.ParallelMinimumSize() + (i * Blake::BLAKE512_RATE_SIZE), m_msgBuffer, i * Blake::BLAKE512_RATE_SIZE, Blake::BLAKE512_RATE_SIZE);
				m_msgLength -= Blake::BLAKE512_RATE_SIZE;
			}

			if (m_msgLength % Blake::BLAKE512_RATE_SIZE != 0)
			{
				pblk = bcnt - 1;
			}
		}

		// process last blocks
		for (i = 0; i < m_treeParams.FanOut(); ++i)
		{
			// apply f0 bit reversal constant to final blocks
			m_dgtState[i].F[0] = 0xFFFFFFFFFFFFFFFFULL;
			blen = Blake::BLAKE512_RATE_SIZE;

			// f1 constant on last block
			if (i == m_treeParams.FanOut() - 1)
			{
				m_dgtState[i].F[1] = 0xFFFFFFFFFFFFFFFFULL;
			}

			if (i == pblk)
			{
				blen = m_msgLength % Blake::BLAKE512_RATE_SIZE;
				m_msgLength += Blake::BLAKE512_RATE_SIZE - blen;
				MemoryTools::Clear(m_msgBuffer, (i * Blake::BLAKE512_RATE_SIZE) + blen, Blake::BLAKE512_RATE_SIZE - blen);
			}
			else if (m_msgLength < Blake::BLAKE512_RATE_SIZE)
			{
				blen = m_msgLength;
				MemoryTools::Clear(m_msgBuffer, (i * Blake::BLAKE512_RATE_SIZE) + blen, Blake::BLAKE512_RATE_SIZE - blen);
			}
			else
			{
				// misra
			}

			IntegerTools::LeIncreaseW(m_dgtState[i].T, m_dgtState[i].T, blen);
			Permute(m_msgBuffer, i * Blake::BLAKE512_RATE_SIZE, m_dgtState[i]);
			m_msgLength -= Blake::BLAKE512_RATE_SIZE;
			IntegerTools::LeULL512ToBlock(m_dgtState[i].H, 0, codes, i * Blake::BLAKE512_DIGEST_SIZE);
		}

		// set up the root node
		m_msgLength = 0;
		BlakeParams rootp = m_treeParams;
		rootp.NodeDepth() = 1;
		rootp.NodeOffset() = 0;
		rootp.MaxDepth() = 2;
		std::vector<ulong> config(CONFIG_SIZE);
		LoadState(m_dgtState[0], rootp, config);

		// load blocks
		for (i = 0; i < m_treeParams.FanOut(); ++i)
		{
			Update(codes, i * Blake::BLAKE512_DIGEST_SIZE, Blake::BLAKE512_DIGEST_SIZE);
		}

		// compress all but last block
		for (i = 0; i < codes.size() - Blake::BLAKE512_RATE_SIZE; i += Blake::BLAKE512_RATE_SIZE)
		{
			IntegerTools::LeIncreaseW(m_dgtState[0].T, m_dgtState[0].T, Blake::BLAKE512_RATE_SIZE);
			Permute(m_msgBuffer, i, m_dgtState[0]);
		}

		// apply f0 and f1 flags
		m_dgtState[0].F[0] = 0xFFFFFFFFFFFFFFFFULL;
		m_dgtState[0].F[1] = 0xFFFFFFFFFFFFFFFFULL;
		// last compression
		IntegerTools::LeIncreaseW(m_dgtState[0].T, m_dgtState[0].T, Blake::BLAKE512_RATE_SIZE);
		Permute(m_msgBuffer, m_msgLength - Blake::BLAKE512_RATE_SIZE, m_dgtState[0]);
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
		IntegerTools::LeIncreaseW(m_dgtState[0].T, m_dgtState[0].T, m_msgLength);
		Permute(m_msgBuffer, 0, m_dgtState[0]);
		IntegerTools::LeULL512ToBlock(m_dgtState[0].H, 0, Output, OutOffset);
	}

	Reset();
}

void Blake512::Initialize(Cipher::ISymmetricKey &MacKey)
{
	size_t i;

	if (MacKey.Key().size() < 32 || MacKey.Key().size() > 64)
	{
		throw CryptoDigestException(Name(), std::string("Initialize"), std::string("Mac Key has invalid length!"), ErrorCodes::InvalidKey);
	}

	std::vector<ulong> config(CONFIG_SIZE);

	if (MacKey.IV().size() != 0)
	{
		if (MacKey.IV().size() != 16)
		{
			throw CryptoDigestException(Name(), std::string("Initialize"), std::string("Salt has invalid length!"), ErrorCodes::InvalidNonce);
		}

		config[4] = IntegerTools::LeBytesTo64(MacKey.IV(), 0);
		config[5] = IntegerTools::LeBytesTo64(MacKey.IV(), 8);
	}

	if (MacKey.Info().size() != 0)
	{
		if (MacKey.Info().size() != 16)
		{
			throw CryptoDigestException(Name(), std::string("Initialize"), std::string("Info has invalid length"), ErrorCodes::InvalidInfo);
		}

		config[6] = IntegerTools::LeBytesTo64(MacKey.Info(), 0);
		config[7] = IntegerTools::LeBytesTo64(MacKey.Info(), 8);
	}

	std::vector<byte> mkey(Blake::BLAKE512_RATE_SIZE, 0);
	MemoryTools::Copy(MacKey.Key(), 0, mkey, 0, IntegerTools::Min(MacKey.Key().size(), mkey.size()));
	m_treeParams.KeyLength() = static_cast<byte>(MacKey.Key().size());

	if (m_treeParams.FanOut() > 1)
	{
		// initialize the leaf nodes and add the key 
		for (i = 0; i < m_treeParams.FanOut(); ++i)
		{
			MemoryTools::Copy(mkey, 0, m_msgBuffer, i * Blake::BLAKE512_RATE_SIZE, mkey.size());
			m_treeParams.NodeOffset() = static_cast<byte>(i);
			LoadState(m_dgtState[i], m_treeParams, config);
		}
		m_msgLength = m_parallelProfile.ParallelMinimumSize();
		m_treeParams.NodeOffset() = 0;
	}
	else
	{
		MemoryTools::Copy(mkey, 0, m_msgBuffer, 0, mkey.size());
		m_msgLength = Blake::BLAKE512_RATE_SIZE;
		LoadState(m_dgtState[0], m_treeParams, config);
	}
}

void Blake512::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0 || Degree % 2 != 0 || Degree > MAX_PRLDEGREE)
	{
		throw CryptoDigestException(Name(), std::string("ParallelMaxDegree"), std::string("Degree setting is invalid!"), ErrorCodes::NotSupported);
	}

	m_parallelProfile.SetMaxDegree(Degree);
	m_dgtState.clear();
	m_dgtState.resize(Degree);
	m_msgBuffer.clear();
	m_msgBuffer.resize(Degree * Blake::BLAKE512_RATE_SIZE);

	if (Degree > 1 && m_parallelProfile.ProcessorCount() > 1)
	{
		m_treeParams.FanOut() = static_cast<byte>(Degree);
		m_treeParams.MaxDepth() = 2;
		m_treeParams.InnerLength() = static_cast<byte>(Blake::BLAKE512_DIGEST_SIZE);
		m_parallelProfile.IsParallel() = true;
	}
	else
	{
		m_treeParams = BlakeParams(static_cast<byte>(Blake::BLAKE512_DIGEST_SIZE));
		m_parallelProfile.IsParallel() = false;
	}

	Reset();
}

void Blake512::Reset()
{
	std::vector<ulong> config(CONFIG_SIZE);
	size_t i;

	if (m_treeParams.FanOut() > 1)
	{
		for (i = 0; i < m_treeParams.FanOut(); ++i)
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

void Blake512::Update(uint Input)
{
	std::vector<byte> tmp(sizeof(uint));
	IntegerTools::Le32ToBytes(Input, tmp, 0);
	Update(tmp, 0, tmp.size());
}

void Blake512::Update(ulong Input)
{
	std::vector<byte> tmp(sizeof(ulong));
	IntegerTools::Le64ToBytes(Input, tmp, 0);
	Update(tmp, 0, tmp.size());
}

void Blake512::Update(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	CEXASSERT(Input.size() - InOffset >= Length, "The input buffer is too short!");

	size_t plen;
	size_t tlen;

	if (Length != 0)
	{
		if (m_treeParams.FanOut() > 1)
		{
			tlen = Length + m_msgLength;
			const size_t PRLMIN = m_msgBuffer.size() + (m_parallelProfile.ParallelMinimumSize() - Blake::BLAKE512_RATE_SIZE);

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

				// empty the message buffer
				ParallelTools::ParallelFor(0, m_treeParams.FanOut(), [this, &Input, InOffset](size_t i)
				{
					IntegerTools::LeIncreaseW(m_dgtState[i].T, m_dgtState[i].T, Blake::BLAKE512_RATE_SIZE);
					Permute(m_msgBuffer, i * Blake::BLAKE512_RATE_SIZE, m_dgtState[i]);
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
						ProcessLeaf(Input, InOffset + (i * Blake::BLAKE512_RATE_SIZE), plen, m_dgtState[i]);
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
					IntegerTools::LeIncreaseW(m_dgtState[i].T, m_dgtState[i].T, Blake::BLAKE512_RATE_SIZE);
					Permute(m_msgBuffer, i * Blake::BLAKE512_RATE_SIZE, m_dgtState[i]);
				});

				// left rotate the buffer
				m_msgLength -= m_parallelProfile.ParallelMinimumSize();
				const size_t FNLLEN = m_msgBuffer.size() / 2;
				MemoryTools::Copy(m_msgBuffer, FNLLEN, m_msgBuffer, 0, FNLLEN);
			}
		}
		else
		{
			if (m_msgLength + Length > Blake::BLAKE512_RATE_SIZE)
			{
				const size_t RMDLEN = Blake::BLAKE512_RATE_SIZE - m_msgLength;
				if (RMDLEN != 0)
				{
					MemoryTools::Copy(Input, InOffset, m_msgBuffer, m_msgLength, RMDLEN);
				}

				IntegerTools::LeIncreaseW(m_dgtState[0].T, m_dgtState[0].T, Blake::BLAKE512_RATE_SIZE);
				Permute(m_msgBuffer, 0, m_dgtState[0]);
				m_msgLength = 0;
				InOffset += RMDLEN;
				Length -= RMDLEN;
			}

			// loop until last block
			while (Length > Blake::BLAKE512_RATE_SIZE)
			{
				IntegerTools::LeIncreaseW(m_dgtState[0].T, m_dgtState[0].T, Blake::BLAKE512_RATE_SIZE);
				Permute(Input, InOffset, m_dgtState[0]);
				InOffset += Blake::BLAKE512_RATE_SIZE;
				Length -= Blake::BLAKE512_RATE_SIZE;
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
	MemoryTools::Clear(State.T, 0, State.T.size() * sizeof(ulong));
	MemoryTools::Clear(State.F, 0, State.F.size() * sizeof(ulong));
	MemoryTools::Copy(Blake::IV512, 0, State.H, 0, State.H.size() * sizeof(ulong));

	Params.GetConfig<ulong>(Config);
	MemoryTools::XOR512(Config, 0, State.H, 0);
}

void Blake512::Permute(const std::vector<byte> &Input, size_t InOffset, Blake2bState &State)
{
	std::array<ulong, 8> iv {
		Blake::IV512[0],
		Blake::IV512[1],
		Blake::IV512[2],
		Blake::IV512[3],
		Blake::IV512[4] ^ State.T[0],
		Blake::IV512[5] ^ State.T[1],
		Blake::IV512[6] ^ State.F[0],
		Blake::IV512[7] ^ State.F[1] };

#if defined(CEX_HAS_AVX2)
	Blake::PermuteR12P1024V(Input, InOffset, State.H, iv);
#else
#	if defined(CEX_DIGEST_COMPACT)
		Blake::PermuteR12P1024C(Input, InOffset, State.H, iv);
#	else
		Blake::PermuteR12P1024U(Input, InOffset, State.H, iv);
#	endif
#endif
}

void Blake512::ProcessLeaf(const std::vector<byte> &Input, size_t InOffset, ulong Length, Blake2bState &State)
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
