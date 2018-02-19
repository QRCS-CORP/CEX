#include "GHASH.h"
#include "CpuDetect.h"
#include "IntUtils.h"
#if defined(__AVX2__)
#	include "Intrinsics.h"
#	include <wmmintrin.h>
#endif

NAMESPACE_MAC

const std::string GHASH::CLASS_NAME("GHASH");

//~~~Constructor~~~//

GHASH::GHASH()
	:
	m_ghashKey(0),
	m_hasCMul(false),
	m_msgBuffer(BLOCK_SIZE),
	m_msgOffset(0)
{
	Detect();
}

GHASH::~GHASH()
{
	Reset();
}

//~~~Accessors~~~//

bool GHASH::HasSimd128() 
{ 
	return m_hasCMul; 
}

//~~~Public Functions~~~//

void GHASH::FinalizeBlock(std::vector<byte> &Output, size_t AdSize, size_t TextSize)
{
	if (m_msgOffset != 0)
	{
		if (m_msgOffset != BLOCK_SIZE)
		{
			Utility::MemUtils::Clear(m_msgBuffer, m_msgOffset, m_msgBuffer.size() - m_msgOffset);
		}

		ProcessSegment(m_msgBuffer, 0, Output, m_msgOffset);
	}

	std::vector<byte> fnlBlock(BLOCK_SIZE);
	Utility::IntUtils::Be64ToBytes(8 * AdSize, fnlBlock, 0);
	Utility::IntUtils::Be64ToBytes(8 * TextSize, fnlBlock, 8);
	Utility::MemUtils::XOR128(fnlBlock, 0, Output, 0);

	GcmMultiply(Output);
}

void GHASH::Initialize(const std::vector<ulong> &Key)
{
	m_ghashKey.resize(Key.size());
	std::memcpy(&m_ghashKey[0], &Key[0], Key.size() * sizeof(ulong));
}

void GHASH::ProcessBlock(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output)
{
	Utility::MemUtils::XOR128(Input, InOffset, Output, 0);
	GcmMultiply(Output);
}

void GHASH::ProcessSegment(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t Length)
{
	while (Length != 0)
	{
		const size_t DIFFSZE = Utility::IntUtils::Min(Length, BLOCK_SIZE);
		Utility::MemUtils::XorBlock(Input, InOffset, Output, 0, DIFFSZE);
		GcmMultiply(Output);
		InOffset += DIFFSZE;
		Length -= DIFFSZE;
	}
}

void GHASH::Reset(bool Erase)
{
	if (Erase)
	{
		if (m_ghashKey.size() != 0)
		{
			Utility::MemUtils::Clear(m_ghashKey, 0, m_ghashKey.size() * sizeof(ulong));
		}

		m_hasCMul = false;
	}

	if (m_msgBuffer.size() != 0)
	{
		Utility::MemUtils::Clear(m_msgBuffer, 0, m_msgBuffer.size());
	}

	m_msgOffset = 0;
}

void GHASH::Update(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t Length)
{
	if (Length != 0)
	{
		if (m_msgOffset == BLOCK_SIZE)
		{
			ProcessBlock(m_msgBuffer, 0, Output);
			m_msgOffset = 0;
		}

		const size_t RMDSZE = BLOCK_SIZE - m_msgOffset;
		if (Length > RMDSZE)
		{
			Utility::MemUtils::Copy(Input, InOffset, m_msgBuffer, m_msgOffset, RMDSZE);
			ProcessBlock(m_msgBuffer, 0, Output);
			m_msgOffset = 0;
			Length -= RMDSZE;
			InOffset += RMDSZE;

			while (Length > BLOCK_SIZE)
			{
				ProcessBlock(Input, InOffset, Output);
				Length -= BLOCK_SIZE;
				InOffset += BLOCK_SIZE;
			}
		}

		if (Length > 0)
		{
			Utility::MemUtils::Copy(Input, InOffset, m_msgBuffer, m_msgOffset, Length);
			m_msgOffset += Length;
		}
	}
}

void GHASH::Detect()
{
	Common::CpuDetect detect;
	m_hasCMul = detect.CMUL() && detect.SSSE3();
}

void GHASH::GcmMultiply(std::vector<byte> &X)
{
	if (m_hasCMul)
	{
		MultiplyW(m_ghashKey, X);
	}
	else
	{
		Multiply(m_ghashKey, X);
	}
}

void GHASH::Multiply(const std::vector<ulong> &H, std::vector<byte> &X)
{
	const ulong X0 = Utility::IntUtils::BeBytesTo64(X, 0);
	const ulong X1 = Utility::IntUtils::BeBytesTo64(X, 8);
	const ulong R = 0xE100000000000000ULL;
	ulong T0 = H[0];
	ulong T1 = H[1];
	ulong Z0 = 0;
	ulong Z1 = 0;
	ulong maskPos = 0x8000000000000000ULL;
	ulong xMask = 0;
	ulong xCarry = 0;

	for (size_t i = 0; i != 64; ++i)
	{
		xMask = Utility::IntUtils::ExpandMask<ulong>(X0 & maskPos);
		maskPos >>= 1;
		Z0 ^= T0 & xMask;
		Z1 ^= T1 & xMask;
		xCarry = R & Utility::IntUtils::ExpandMask<ulong>(T1 & 1);
		T1 = (T1 >> 1) | (T0 << 63);
		T0 = (T0 >> 1) ^ xCarry;
	}

	maskPos = 0x8000000000000000ULL;

	for (size_t i = 0; i != 63; ++i)
	{
		xMask = Utility::IntUtils::ExpandMask<ulong>(X1 & maskPos);
		maskPos >>= 1;
		Z0 ^= T0 & xMask;
		Z1 ^= T1 & xMask;
		xCarry = R & Utility::IntUtils::ExpandMask<ulong>(T1 & 1);
		T1 = (T1 >> 1) | (T0 << 63);
		T0 = (T0 >> 1) ^ xCarry;
	}

	xMask = Utility::IntUtils::ExpandMask<ulong>(X1 & maskPos);
	Z0 ^= T0 & xMask;
	Z1 ^= T1 & xMask;
	Utility::IntUtils::Be64ToBytes(Z0, X, 0);
	Utility::IntUtils::Be64ToBytes(Z1, X, 8);
}

void GHASH::MultiplyW(const std::vector<ulong> &H, std::vector<byte> &X)
{
#if defined(__AVX2__)

	const __m128i MASK = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
	__m128i A = _mm_loadu_si128(reinterpret_cast<const __m128i*>(X.data()));
	__m128i B = _mm_loadu_si128(reinterpret_cast<const __m128i*>(H.data()));
	__m128i T0, T1, T2, T3, T4, T5;

	A = _mm_shuffle_epi8(A, MASK);
	B = _mm_shuffle_epi8(B, _mm_set_epi8(8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7));
	B = _mm_shuffle_epi8(B, MASK);
	T0 = _mm_clmulepi64_si128(A, B, 0x00);
	T1 = _mm_clmulepi64_si128(A, B, 0x01);
	T2 = _mm_clmulepi64_si128(A, B, 0x10);
	T3 = _mm_clmulepi64_si128(A, B, 0x11);
	T1 = _mm_xor_si128(T1, T2);
	T2 = _mm_slli_si128(T1, 8);
	T1 = _mm_srli_si128(T1, 8);
	T0 = _mm_xor_si128(T0, T2);
	T3 = _mm_xor_si128(T3, T1);
	T4 = _mm_srli_epi32(T0, 31);
	T0 = _mm_slli_epi32(T0, 1);
	T5 = _mm_srli_epi32(T3, 31);
	T3 = _mm_slli_epi32(T3, 1);
	T2 = _mm_srli_si128(T4, 12);
	T5 = _mm_slli_si128(T5, 4);
	T4 = _mm_slli_si128(T4, 4);
	T0 = _mm_or_si128(T0, T4);
	T3 = _mm_or_si128(T3, T5);
	T3 = _mm_or_si128(T3, T2);
	T4 = _mm_slli_epi32(T0, 31);
	T5 = _mm_slli_epi32(T0, 30);
	T2 = _mm_slli_epi32(T0, 25);
	T4 = _mm_xor_si128(T4, T5);
	T4 = _mm_xor_si128(T4, T2);
	T5 = _mm_srli_si128(T4, 4);
	T3 = _mm_xor_si128(T3, T5);
	T4 = _mm_slli_si128(T4, 12);
	T0 = _mm_xor_si128(T0, T4);
	T3 = _mm_xor_si128(T3, T0);
	T4 = _mm_srli_epi32(T0, 1);
	T1 = _mm_srli_epi32(T0, 2);
	T2 = _mm_srli_epi32(T0, 7);
	T3 = _mm_xor_si128(T3, T1);
	T3 = _mm_xor_si128(T3, T2);
	T3 = _mm_xor_si128(T3, T4);
	T3 = _mm_shuffle_epi8(T3, MASK);

	_mm_storeu_si128(reinterpret_cast<__m128i*>(X.data()), T3);

#else
	Multiply(H, X);
#endif
}

NAMESPACE_MACEND
