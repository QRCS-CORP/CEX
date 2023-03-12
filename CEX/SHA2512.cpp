#include "SHA2512.h"
#include "SHA2.h"
#include "IntegerTools.h"
#include "MemoryTools.h"
#include "ParallelTools.h"

NAMESPACE_DIGEST

using Enumeration::DigestConvert;
using Tools::IntegerTools;
using Tools::MemoryTools;
using Tools::ParallelTools;

class SHA2512::SHA2512State
{
public:

	std::array<uint64_t, 8> H = { 0 };
	std::array<uint64_t, 2> T = { 0 };

	SHA2512State()
	{
	}

	~SHA2512State()
	{
		MemoryTools::Clear(H, 0, H.size() * sizeof(uint64_t));
		MemoryTools::Clear(T, 0, T.size() * sizeof(uint64_t));
	}

	void Increase(size_t Length)
	{
		T[0] += Length;

		if (T[0] > 0x1FFFFFFFFFFFFFFFULL)
		{
			T[1] += static_cast<uint64_t>(T[0] >> 61);
			T[0] &= 0x1FFFFFFFFFFFFFFFULL;
		}
	}

	void Reset()
	{
		T[0] = 0;
		T[1] = 0;
		MemoryTools::Copy(SHA2::SHA2512State, 0, H, 0, H.size() * sizeof(uint64_t));
	}
};

//~~~Constructor~~~//

SHA2512::SHA2512(bool Parallel)
	:
	m_dgtState(Parallel ? 
		DEF_PRLDEGREE : 
		1),
	m_msgBuffer(Parallel ? 
		DEF_PRLDEGREE * SHA2::SHA2512_RATE_SIZE : 
		SHA2::SHA2512_RATE_SIZE),
	m_msgLength(0),
	m_parallelProfile(SHA2::SHA2512_RATE_SIZE, Parallel, false, STATE_PRECACHED, false, DEF_PRLDEGREE),
	m_treeParams(Parallel ? SHA2Params(SHA2::SHA2512_DIGEST_SIZE, static_cast<uint8_t>(SHA2::SHA2512_RATE_SIZE), static_cast<uint8_t>(DEF_PRLDEGREE)) :
		SHA2Params(SHA2::SHA2512_DIGEST_SIZE, 0UL, 0x00))
{
	Reset();
}

SHA2512::SHA2512(SHA2Params &Params)
	:
	m_dgtState(Params.FanOut() != 0 && Params.FanOut() <= MAX_PRLDEGREE ? 
		Params.FanOut() :
		throw CryptoDigestException(DigestConvert::ToName(Digests::SHA2512), std::string("Constructor"), std::string("The FanOut parameter can not be zero or exceed the maximum of 64!"), ErrorCodes::IllegalOperation)),
	m_msgBuffer(SHA2::SHA2512_RATE_SIZE),
	m_msgLength(0),
	m_parallelProfile(SHA2::SHA2512_RATE_SIZE, static_cast<bool>(Params.FanOut() > 1), false, STATE_PRECACHED, false, Params.FanOut()),
	m_treeParams(Params)
{
	Reset();
}

SHA2512::~SHA2512()
{
	m_msgLength = 0;
	IntegerTools::Clear(m_msgBuffer);
	IntegerTools::Clear(m_dgtState);
}

//~~~Accessors~~~//

size_t SHA2512::BlockSize() 
{ 
	return SHA2::SHA2512_RATE_SIZE; 
}

size_t SHA2512::DigestSize() 
{ 
	return SHA2::SHA2512_DIGEST_SIZE; 
}

const Digests SHA2512::Enumeral()
{ 
	return Digests::SHA2512; 
}

const bool SHA2512::IsParallel() 
{ 
	return m_parallelProfile.IsParallel(); 
}

const std::string SHA2512::Name() 
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

const size_t SHA2512::ParallelBlockSize() 
{ 
	return m_parallelProfile.ParallelBlockSize(); 
}

ParallelOptions &SHA2512::ParallelProfile()
{
	return m_parallelProfile; 
}

//~~~Public Functions~~~//

void SHA2512::Compute(const std::vector<uint8_t> &Input, std::vector<uint8_t> &Output)
{
	if (Output.size() < SHA2::SHA2512_DIGEST_SIZE)
	{
		throw CryptoDigestException(Name(), std::string("Compute"), std::string("The output vector is too small!"), ErrorCodes::InvalidSize);
	}

	Update(Input, 0, Input.size());
	Finalize(Output, 0);
}

void SHA2512::Finalize(std::vector<uint8_t> &Output, size_t OutOffset)
{
	if (Output.size() - OutOffset < SHA2::SHA2512_DIGEST_SIZE)
	{
		throw CryptoDigestException(Name(), std::string("Finalize"), std::string("The output vector is too small!"), ErrorCodes::InvalidSize);
	}

	size_t bctr;
	size_t boff;
	size_t i;

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
			bctr = 0;

			while (m_msgLength != 0)
			{
				const size_t MSGRMD = (m_msgLength >= SHA2::SHA2512_RATE_SIZE) ? SHA2::SHA2512_RATE_SIZE : m_msgLength;
				HashFinal(m_msgBuffer, bctr * SHA2::SHA2512_RATE_SIZE, MSGRMD, m_dgtState[bctr]);
				m_msgLength -= MSGRMD;
				++bctr;
			}
		}

		// initialize root state
		SHA2512State proot;
		proot.Reset();

		// add state blocks as contiguous message input
		for (i = 0; i < m_dgtState.size(); ++i)
		{
			IntegerTools::BeULL512ToBlock(m_dgtState[i].H, 0, m_msgBuffer, i * SHA2::SHA2512_RATE_SIZE);
			m_msgLength += SHA2::SHA2512_DIGEST_SIZE;
		}

		// compress full blocks
		boff = 0;
		if (m_msgLength >= SHA2::SHA2512_RATE_SIZE)
		{
			const size_t BLKRMD = m_msgLength - (m_msgLength % SHA2::SHA2512_RATE_SIZE);

			for (i = 0; i < BLKRMD / SHA2::SHA2512_RATE_SIZE; ++i)
			{
				Permute(m_msgBuffer, i * SHA2::SHA2512_RATE_SIZE, proot);
			}

			m_msgLength -= BLKRMD;
			boff = BLKRMD;
		}

		// finalize and store
		HashFinal(m_msgBuffer, boff, m_msgLength, proot);
		IntegerTools::BeULL512ToBlock(proot.H, 0, Output, OutOffset);
	}
	else
	{
		// finalize and store
		HashFinal(m_msgBuffer, 0, m_msgLength, m_dgtState[0]);
		IntegerTools::BeULL512ToBlock(m_dgtState[0].H, 0, Output, OutOffset);
	}

	Reset();
}

void SHA2512::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0 || Degree % 2 != 0 || Degree > MAX_PRLDEGREE)
	{
		throw CryptoDigestException(Name(), std::string("ParallelMaxDegree"), std::string("Degree setting is invalid!"), ErrorCodes::NotSupported);
	}

	m_parallelProfile.SetMaxDegree(Degree);

	Reset();
}

void SHA2512::Reset()
{
	m_dgtState.clear();
	m_dgtState.resize(m_parallelProfile.IsParallel() ? m_parallelProfile.ParallelMaxDegree() : 1);
	m_msgBuffer.clear();
	m_msgBuffer.resize(m_parallelProfile.IsParallel() ? m_parallelProfile.ParallelMaxDegree() * SHA2::SHA2512_RATE_SIZE : SHA2::SHA2512_RATE_SIZE);
	m_msgLength = 0;
	std::vector<uint8_t> params(SHA2::SHA2512_RATE_SIZE, 0x1F);

	for (size_t i = 0; i < m_dgtState.size(); ++i)
	{
		m_dgtState[i].Reset();

		if (m_parallelProfile.IsParallel())
		{
			m_treeParams.NodeOffset() = static_cast<uint32_t>(i);
			MemoryTools::Copy(m_treeParams.ToBytes(), 0, params, 0, m_treeParams.GetHeaderSize());
			Permute(params, 0, m_dgtState[i]);
		}
	}
}

void SHA2512::Update(uint8_t Input)
{
	std::vector<uint8_t> inp(1, Input);
	Update(inp, 0, 1);
}

void SHA2512::Update(uint32_t Input)
{
	std::vector<uint8_t> tmp(sizeof(uint32_t));
	IntegerTools::Le32ToBytes(Input, tmp, 0);
	Update(tmp, 0, tmp.size());
}

void SHA2512::Update(uint64_t Input)
{
	std::vector<uint8_t> tmp(sizeof(uint64_t));
	IntegerTools::Le64ToBytes(Input, tmp, 0);
	Update(tmp, 0, tmp.size());
}

void SHA2512::Update(const std::vector<uint8_t> &Input, size_t InOffset, size_t Length)
{
	CEXASSERT(Input.size() - InOffset >= Length, "The input buffer is too int16_t!");

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
					Permute(m_msgBuffer, i * SHA2::SHA2512_RATE_SIZE, m_dgtState[i]);
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
					ProcessLeaf(Input, InOffset + (i * SHA2::SHA2512_RATE_SIZE), m_dgtState[i], PRCLEN);
				});

				Length -= PRCLEN;
				InOffset += PRCLEN;
			}

			if (Length >= m_parallelProfile.ParallelMinimumSize())
			{
				const size_t PRMLEN = Length - (Length % m_parallelProfile.ParallelMinimumSize());
				ParallelTools::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Input, InOffset, PRMLEN](size_t i)
				{
					ProcessLeaf(Input, InOffset + (i * SHA2::SHA2512_RATE_SIZE), m_dgtState[i], PRMLEN);
				});

				Length -= PRMLEN;
				InOffset += PRMLEN;
			}
		}
		else
		{
			if (m_msgLength != 0 && (m_msgLength + Length >= SHA2::SHA2512_RATE_SIZE))
			{
				const size_t RMDLEN = SHA2::SHA2512_RATE_SIZE - m_msgLength;
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
			while (Length >= SHA2::SHA2512_RATE_SIZE)
			{
				Permute(Input, InOffset, m_dgtState[0]);
				InOffset += SHA2::SHA2512_RATE_SIZE;
				Length -= SHA2::SHA2512_RATE_SIZE;
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

void SHA2512::HashFinal(std::vector<uint8_t> &Input, size_t InOffset, size_t Length, SHA2512State &State)
{
	State.Increase(Length);
	uint64_t bitLen = (State.T[0] << 3);

	if (Length == SHA2::SHA2512_RATE_SIZE)
	{
		Permute(Input, InOffset, State);
		Length = 0;
	}

	Input[InOffset + Length] = 128;
	++Length;

	// padding
	if (Length < SHA2::SHA2512_RATE_SIZE)
	{
		MemoryTools::Clear(Input, InOffset + Length, SHA2::SHA2512_RATE_SIZE - Length);
	}

	if (Length > 112)
	{
		Permute(Input, InOffset, State);
		MemoryTools::Clear(Input, InOffset, SHA2::SHA2512_RATE_SIZE);
	}

	// finalize state with counter and last compression
	IntegerTools::Be64ToBytes(State.T[1], Input, InOffset + 112);
	IntegerTools::Be64ToBytes(bitLen, Input, InOffset + 120);
	Permute(Input, InOffset, State);
}

void SHA2512::Permute(const std::vector<uint8_t> &Input, size_t InOffset, SHA2512State &State)
{
#if defined(CEX_DIGEST_COMPACT)
	SHA2::PermuteR80P1024C(Input, InOffset, State.H);
#else
	SHA2::PermuteR80P1024U(Input, InOffset, State.H);
#endif

	State.Increase(SHA2::SHA2512_RATE_SIZE);
}

void SHA2512::ProcessLeaf(const std::vector<uint8_t> &Input, size_t InOffset, SHA2512State &State, uint64_t Length)
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
