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

	std::array<byte, CMUL::CMUL_BLOCK_SIZE> Buffer;
	std::array<ulong, CMUL::CMUL_STATE_SIZE> State;
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
	m_ghashState(new GhashState)
{
}

GHASH::~GHASH()
{
	Reset();
}

//~~~Public Functions~~~//

void GHASH::Clear()
{
	MemoryTools::Clear(m_ghashState->Buffer, 0, m_ghashState->Buffer.size());
	m_ghashState->Position = 0;
}

void GHASH::Finalize(std::vector<byte> &Output, size_t Counter, size_t Length)
{
	if (m_ghashState->Position != 0)
	{
		if (m_ghashState->Position != CMUL::CMUL_BLOCK_SIZE)
		{
			MemoryTools::Clear(m_ghashState->Buffer, m_ghashState->Position, m_ghashState->Buffer.size() - m_ghashState->Position);
		}

		MemoryTools::XOR(m_ghashState->Buffer, 0, Output, 0, m_ghashState->Position);
		Permute(m_ghashState->State, Output);
	}

	std::vector<byte> tmpb(CMUL::CMUL_BLOCK_SIZE);
	IntegerTools::Be64ToBytes(static_cast<ulong>(Counter) * 8, tmpb, 0);
	IntegerTools::Be64ToBytes(static_cast<ulong>(Length) * 8, tmpb, 8);
	MemoryTools::XOR128(tmpb, 0, Output, 0);

	Permute(m_ghashState->State, Output);
}

void GHASH::Initialize(const std::vector<ulong> &Key)
{
	MemoryTools::Copy(Key, 0, m_ghashState->State, 0, Key.size() * sizeof(ulong));
}

void GHASH::Multiply(const std::vector<byte> &Input, std::vector<byte> &Output, size_t Length)
{
	size_t boff;

	boff = 0;

	while (Length != 0)
	{
		const size_t RMDLEN = IntegerTools::Min(Length, CMUL::CMUL_BLOCK_SIZE);
		MemoryTools::XOR(Input, boff, Output, 0, RMDLEN);
		Permute(m_ghashState->State, Output);
		boff += RMDLEN;
		Length -= RMDLEN;
	}
}

void GHASH::Reset()
{
	m_ghashState->Reset();
}

void GHASH::Update(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t Length)
{
	if (Length != 0)
	{
		if (m_ghashState->Position == CMUL::CMUL_BLOCK_SIZE)
		{
			MemoryTools::XOR128(m_ghashState->Buffer, 0, Output, 0);
			Permute(m_ghashState->State, Output);
			m_ghashState->Position = 0;
		}

		const size_t RMDLEN = CMUL::CMUL_BLOCK_SIZE - m_ghashState->Position;

		if (Length > RMDLEN)
		{
			MemoryTools::Copy(Input, InOffset, m_ghashState->Buffer, m_ghashState->Position, RMDLEN);
			MemoryTools::XOR128(m_ghashState->Buffer, 0, Output, 0);
			Permute(m_ghashState->State, Output);
			m_ghashState->Position = 0;
			Length -= RMDLEN;
			InOffset += RMDLEN;

			while (Length > CMUL::CMUL_BLOCK_SIZE)
			{
				MemoryTools::XOR128(Input, InOffset, Output, 0);
				Permute(m_ghashState->State, Output);
				Length -= CMUL::CMUL_BLOCK_SIZE;
				InOffset += CMUL::CMUL_BLOCK_SIZE;
			}
		}

		if (Length > 0)
		{
			MemoryTools::Copy(Input, InOffset, m_ghashState->Buffer, m_ghashState->Position, Length);
			m_ghashState->Position += Length;
		}
	}
}

void GHASH::Permute(std::array<ulong, CMUL::CMUL_STATE_SIZE> &State, std::vector<byte> &Output)
{
	std::array<byte, 16> tmp;
	std::memcpy(tmp.data(), Output.data(), 16);

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

	std::memcpy(Output.data(), tmp.data(), 16);
}

bool GHASH::HasGmul()
{
	CpuDetect dtc;

	return dtc.CMUL() && dtc.AVX();
}

NAMESPACE_DIGESTEND
