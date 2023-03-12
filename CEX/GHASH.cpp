#include "GHASH.h"
#include "CpuDetect.h"
#include "IntegerTools.h"
#if defined(CEX_HAS_AVX2)
#	include "Intrinsics.h"
#	include <wmmintrin.h>
#endif

NAMESPACE_DIGEST

using Tools::IntegerTools;
using Tools::MemoryTools;

const bool GHASH::HAS_CMUL = HasGmul();

class GHASH::GhashState
{
public:

	std::array<uint64_t, CMUL::CMUL_STATE_SIZE> State = { 0 };
	std::array<uint8_t, CMUL::CMUL_BLOCK_SIZE> Buffer = { 0 };
	size_t Position = 0;

	GhashState()
	{
	}

	~GhashState()
	{
		Reset();
	}

	void Reset()
	{
		Position = 0;
		MemoryTools::Clear(Buffer, 0, Buffer.size());
		MemoryTools::Clear(State, 0, State.size() * sizeof(uint64_t));
	}
};

const std::string GHASH::CLASS_NAME("GHASH");

//~~~Constructor~~~//

GHASH::GHASH()
	:
	m_dgtState(new GhashState)
{
}

GHASH::~GHASH()
{
	Reset();
}

//~~~Public Functions~~~//

void GHASH::Clear()
{
	MemoryTools::Clear(m_dgtState->Buffer, 0, m_dgtState->Buffer.size());
	m_dgtState->Position = 0;
}

void GHASH::Finalize(std::vector<uint8_t> &Output, size_t ADLength, size_t TxtLength)
{
	if (m_dgtState->Position != 0)
	{
		if (m_dgtState->Position != CMUL::CMUL_BLOCK_SIZE)
		{
			MemoryTools::Clear(m_dgtState->Buffer, m_dgtState->Position, m_dgtState->Buffer.size() - m_dgtState->Position);
		}

		MemoryTools::XOR(m_dgtState->Buffer, 0, Output, 0, m_dgtState->Position);
		Permute(m_dgtState->State, Output);
	}

	std::vector<uint8_t> tmpb(CMUL::CMUL_BLOCK_SIZE);
	IntegerTools::Be64ToBytes(static_cast<uint64_t>(ADLength) * 8, tmpb, 0);
	IntegerTools::Be64ToBytes(static_cast<uint64_t>(TxtLength) * 8, tmpb, 8);
	MemoryTools::XOR128(tmpb, 0, Output, 0);

	Permute(m_dgtState->State, Output);
}

void GHASH::Initialize(const std::vector<uint64_t> &Key)
{
	MemoryTools::Copy(Key, 0, m_dgtState->State, 0, Key.size() * sizeof(uint64_t));
}

void GHASH::Multiply(const std::vector<uint8_t> &Input, std::vector<uint8_t> &Output, size_t Length)
{
	size_t boff;

	boff = 0;

	while (Length != 0)
	{
		const size_t RMDLEN = IntegerTools::Min(Length, CMUL::CMUL_BLOCK_SIZE);
		MemoryTools::XOR(Input, boff, Output, 0, RMDLEN);
		Permute(m_dgtState->State, Output);
		boff += RMDLEN;
		Length -= RMDLEN;
	}
}

void GHASH::Reset()
{
	m_dgtState->Reset();
}
const size_t GHASH::TagSize()
{
	return TAG_SIZE;
}

void GHASH::Update(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t Length)
{
	if (Length != 0)
	{
		if (m_dgtState->Position == CMUL::CMUL_BLOCK_SIZE)
		{
			MemoryTools::XOR128(m_dgtState->Buffer, 0, Output, 0);
			Permute(m_dgtState->State, Output);
			m_dgtState->Position = 0;
		}

		const size_t RMDLEN = CMUL::CMUL_BLOCK_SIZE - m_dgtState->Position;

		if (Length > RMDLEN)
		{
			MemoryTools::Copy(Input, InOffset, m_dgtState->Buffer, m_dgtState->Position, RMDLEN);
			MemoryTools::XOR128(m_dgtState->Buffer, 0, Output, 0);
			Permute(m_dgtState->State, Output);
			m_dgtState->Position = 0;
			Length -= RMDLEN;
			InOffset += RMDLEN;

			while (Length > CMUL::CMUL_BLOCK_SIZE)
			{
				MemoryTools::XOR128(Input, InOffset, Output, 0);
				Permute(m_dgtState->State, Output);
				Length -= CMUL::CMUL_BLOCK_SIZE;
				InOffset += CMUL::CMUL_BLOCK_SIZE;
			}
		}

		if (Length > 0)
		{
			MemoryTools::Copy(Input, InOffset, m_dgtState->Buffer, m_dgtState->Position, Length);
			m_dgtState->Position += Length;
		}
	}
}

void GHASH::Permute(std::array<uint64_t, CMUL::CMUL_STATE_SIZE> &State, std::vector<uint8_t> &Output)
{
	std::array<uint8_t, 16> tmp = { 0 };

	MemoryTools::COPY128(Output, 0, tmp, 0);

	if (HAS_CMUL)
	{
		CMUL::PermuteR128P128V(State, tmp);
	}
	else
	{
#if defined(CEX_DIGEST_COMPACT)
		CMUL::PermuteR128P128C(State, tmp);
#else
		CMUL::PermuteR128P128U(State, tmp);
#endif
	}

	MemoryTools::COPY128(tmp, 0, Output, 0);
}

bool GHASH::HasGmul()
{
	CpuDetect dtc;

	return dtc.CMUL() && dtc.AVX();
}

NAMESPACE_DIGESTEND
