#include "GHASH.h"
#include "CpuDetect.h"
#include "IntegerTools.h"
#if defined(__AVX2__)
#	include "Intrinsics.h"
#	include <wmmintrin.h>
#endif

NAMESPACE_DIGEST

using Utility::IntegerTools;
using Utility::MemoryTools;

const bool GHASH::HAS_CMUL = HasGmul();

class GHASH::GhashState
{
public:

	std::array<ulong, CMUL::CMUL_STATE_SIZE> State;
	std::array<byte, CMUL::CMUL_BLOCK_SIZE> Buffer;
	size_t Position;

	GhashState()
		:
		Position(0)
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
		MemoryTools::Clear(State, 0, State.size() * sizeof(ulong));
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

void GHASH::Finalize(std::vector<byte> &Output, size_t ADLength, size_t TxtLength)
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

	std::vector<byte> tmpb(CMUL::CMUL_BLOCK_SIZE);
	IntegerTools::Be64ToBytes(static_cast<ulong>(ADLength) * 8, tmpb, 0);
	IntegerTools::Be64ToBytes(static_cast<ulong>(TxtLength) * 8, tmpb, 8);
	MemoryTools::XOR128(tmpb, 0, Output, 0);

	Permute(m_dgtState->State, Output);
}

void GHASH::Initialize(const std::vector<ulong> &Key)
{
	MemoryTools::Copy(Key, 0, m_dgtState->State, 0, Key.size() * sizeof(ulong));
}

void GHASH::Multiply(const std::vector<byte> &Input, std::vector<byte> &Output, size_t Length)
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

void GHASH::Update(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t Length)
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

void GHASH::Permute(std::array<ulong, CMUL::CMUL_STATE_SIZE> &State, std::vector<byte> &Output)
{
	std::array<byte, 16> tmp;

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
