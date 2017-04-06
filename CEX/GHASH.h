#ifndef _CEX_GHASH_H
#define _CEX_GHASH_H

#include "CpuDetect.h"
#include "IntUtils.h"
#include "Intrinsics.h"
#include "SimdProfiles.h"
#include <wmmintrin.h>

NAMESPACE_MAC

using Utility::IntUtils;

/// <summary>
/// Instantiate the GHASH class; this is an internal class used by GMAC and GCM mode
/// </summary>
class GHASH
{
private:

	static const size_t BLOCK_SIZE = 16;

	std::vector<ulong> m_ghashKey;
	bool m_hasCMul;
	std::vector<byte> m_msgBuffer;
	size_t m_msgOffset;

public:

	/// <summary>
	/// 128bit SIMD instructions are available on this system
	/// </summary>
	bool HasSimd128() { return m_hasCMul; }

	/// <summary>
	/// Instantiate this class; this is an internal class used by GMAC and GCM mode
	/// </summary>
	///
	/// <param name="Key">The ghash key</param>
	explicit GHASH(std::vector<ulong> &Key)
		:
		m_ghashKey(Key),
		m_hasCMul(false),
		m_msgBuffer(BLOCK_SIZE),
		m_msgOffset(0)
	{
		Detect();
	}

	virtual ~GHASH()
	{
		Reset();
	}

	void FinalizeBlock(std::vector<byte> &Output, size_t AdSize, size_t TextSize)
	{

		if (m_msgOffset != 0)
		{
			if (m_msgOffset != BLOCK_SIZE)
				memset(&m_msgBuffer[m_msgOffset], (byte)0, m_msgBuffer.size() - m_msgOffset);

			ProcessSegment(m_msgBuffer, 0, Output, m_msgOffset);
		}

		std::vector<byte> fnlBlock(BLOCK_SIZE);
		IntUtils::Be64ToBytes(8 * AdSize, fnlBlock, 0);
		IntUtils::Be64ToBytes(8 * TextSize, fnlBlock, 8);
		IntUtils::XORBLK(fnlBlock, 0, Output, 0, BLOCK_SIZE);
		GcmMultiply(Output);
	}

	void Reset(bool Erase = false)
	{
		if (Erase)
		{
			if (m_ghashKey.size() != 0)
				memset(&m_ghashKey[0], (byte)0, m_ghashKey.size());
			m_hasCMul = false;
		}

		if (m_msgBuffer.size() != 0)
			memset(&m_msgBuffer[0], (byte)0, m_msgBuffer.size());

		m_msgOffset = 0;
	}

	void ProcessBlock(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output)
	{
		IntUtils::XORBLK(Input, InOffset, Output, 0, BLOCK_SIZE);
		GcmMultiply(Output);
	}

	void ProcessSegment(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t Length)
	{
		while (Length)
		{
			const size_t DIFF = IntUtils::Min(Length, BLOCK_SIZE);
			IntUtils::XORPRT(Input, InOffset, Output, 0, DIFF);
			GcmMultiply(Output);
			InOffset += DIFF;
			Length -= DIFF;
		}
	}

	void Update(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t Length)
	{
		if (Length == 0)
			return;

		if (m_msgOffset == BLOCK_SIZE)
		{
			ProcessBlock(m_msgBuffer, 0, Output);
			m_msgOffset = 0;
		}

		const size_t RMD = BLOCK_SIZE - m_msgOffset;
		if (Length > RMD)
		{
			memcpy(&m_msgBuffer[m_msgOffset], &Input[InOffset], RMD);
			ProcessBlock(m_msgBuffer, 0, Output);
			m_msgOffset = 0;
			Length -= RMD;
			InOffset += RMD;

			while (Length > BLOCK_SIZE)
			{
				ProcessBlock(Input, InOffset, Output);
				Length -= BLOCK_SIZE;
				InOffset += BLOCK_SIZE;
			}
		}

		if (Length > 0)
		{
			memcpy(&m_msgBuffer[m_msgOffset], &Input[InOffset], Length);
			m_msgOffset += Length;
		}
	}

private:

	void Detect()
	{
		Common::CpuDetect detect;
		m_hasCMul = detect.CMUL() && detect.SSSE3();
	}

	void GcmMultiply(std::vector<byte> &X)
	{
		if (m_hasCMul)
			PMultiply(m_ghashKey, X);
		else
			LMultiply(m_ghashKey, X);
	}

	void LMultiply(const std::vector<ulong> &H, std::vector<byte> &X)
	{
		const ulong X0 = IntUtils::BytesToBe64(X, 0);
		const ulong X1 = IntUtils::BytesToBe64(X, 8);
		const ulong R = 0xE100000000000000;
		ulong T0 = H[0];
		ulong T1 = H[1];
		ulong Z0 = 0;
		ulong Z1 = 0;
		ulong maskPos = 0x8000000000000000;
		ulong xMask = 0;
		ulong xCarry = 0;

		for (size_t i = 0; i != 64; ++i)
		{
			xMask = IntUtils::ExpandMask<ulong>(X0 & maskPos);
			maskPos >>= 1;
			Z0 ^= T0 & xMask;
			Z1 ^= T1 & xMask;
			xCarry = R & IntUtils::ExpandMask<ulong>(T1 & 1);
			T1 = (T1 >> 1) | (T0 << 63);
			T0 = (T0 >> 1) ^ xCarry;
		}

		maskPos = 0x8000000000000000;

		for (size_t i = 0; i != 63; ++i)
		{
			xMask = IntUtils::ExpandMask<ulong>(X1 & maskPos);
			maskPos >>= 1;
			Z0 ^= T0 & xMask;
			Z1 ^= T1 & xMask;
			xCarry = R & IntUtils::ExpandMask<ulong>(T1 & 1);
			T1 = (T1 >> 1) | (T0 << 63);
			T0 = (T0 >> 1) ^ xCarry;
		}

		xMask = IntUtils::ExpandMask<ulong>(X1 & maskPos);
		Z0 ^= T0 & xMask;
		Z1 ^= T1 & xMask;
		IntUtils::Be64ToBytes(Z0, X, 0);
		IntUtils::Be64ToBytes(Z1, X, 8);
	}

	void PMultiply(const std::vector<ulong> &H, std::vector<byte> &X)
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
		LMultiply(H, X);
#endif
	}
};

NAMESPACE_MACEND
#endif