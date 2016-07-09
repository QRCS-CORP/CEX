#include "IntUtils.h"

NAMESPACE_UTILITY

uint IntUtils::BitPrecision(ulong Value)
{
	if (!Value)
		return 0;

	uint l = 0, h = 8 * sizeof(Value);

	while (h - l > 1)
	{
		uint t = (l + h) / 2;
		if (Value >> t)
			l = t;
		else
			h = t;
	}

	return h;
}

uint IntUtils::BytePrecision(ulong Value)
{
	uint i;
	for (i = sizeof(Value); i; --i)
		if (Value >> (i - 1) * 8)
			break;

	return i;
}

ulong IntUtils::Crop(ulong Value, uint size)
{
	if (size < 8 * sizeof(Value))
		return (Value & ((1L << size) - 1));
	else
		return Value;
}

uint IntUtils::Parity(ulong Value)
{
	for (size_t i = 8 * sizeof(Value) / 2; i>0; i /= 2)
		Value ^= Value >> i;
	return (uint)Value & 1;
}

void IntUtils::XOR32(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Output[0] ^= Input[0];
	Output[1] ^= Input[1];
	Output[2] ^= Input[2];
	Output[3] ^= Input[3];
}

void IntUtils::XOR32(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	Output[OutOffset] ^= Input[InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
}

void IntUtils::XOR64(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Output[0] ^= Input[0];
	Output[1] ^= Input[1];
	Output[2] ^= Input[2];
	Output[3] ^= Input[3];
	Output[4] ^= Input[4];
	Output[5] ^= Input[5];
	Output[6] ^= Input[6];
	Output[7] ^= Input[7];
}

void IntUtils::XOR64(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	Output[OutOffset] ^= Input[InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
}

#if defined(HAS_MINSSE)
void IntUtils::XOR128(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	_mm_storeu_si128((__m128i*)(void*)&Output[0], _mm_xor_si128(_mm_loadu_si128((const __m128i*)(const void*)&Input[0]), _mm_loadu_si128((const __m128i*)(const void*)&Output[0])));
}
#elif
void IntUtils::XOR128(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Output[0] ^= Input[0];
	Output[1] ^= Input[1];
	Output[2] ^= Input[2];
	Output[3] ^= Input[3];
	Output[4] ^= Input[4];
	Output[5] ^= Input[5];
	Output[6] ^= Input[6];
	Output[7] ^= Input[7];
	Output[8] ^= Input[8];
	Output[9] ^= Input[9];
	Output[10] ^= Input[10];
	Output[11] ^= Input[11];
	Output[12] ^= Input[12];
	Output[13] ^= Input[13];
	Output[14] ^= Input[14];
	Output[15] ^= Input[15];
}
#endif

#if defined(HAS_MINSSE)
void IntUtils::XOR128(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	_mm_storeu_si128((__m128i*)(void*)&Output[OutOffset], _mm_xor_si128(_mm_loadu_si128((const __m128i*)(const void*)&Input[InOffset]), _mm_loadu_si128((const __m128i*)(const void*)&Output[OutOffset])));
}
#elif
void IntUtils::XOR128(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	Output[OutOffset] ^= Input[InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
}
#endif

#if defined(HAS_MINSSE)
void IntUtils::XOR256(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	_mm_storeu_si128((__m128i*)(void*)&Output[0], _mm_xor_si128(_mm_loadu_si128((const __m128i*)(const void*)&Input[0]), _mm_loadu_si128((const __m128i*)(const void*)&Output[0])));
	_mm_storeu_si128((__m128i*)(void*)&Output[16], _mm_xor_si128(_mm_loadu_si128((const __m128i*)(const void*)&Input[16]), _mm_loadu_si128((const __m128i*)(const void*)&Output[16])));
}
#elif
void IntUtils::XOR256(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Output[0] ^= Input[0];
	Output[1] ^= Input[1];
	Output[2] ^= Input[2];
	Output[3] ^= Input[3];
	Output[4] ^= Input[4];
	Output[5] ^= Input[5];
	Output[6] ^= Input[6];
	Output[7] ^= Input[7];
	Output[8] ^= Input[8];
	Output[9] ^= Input[9];
	Output[10] ^= Input[10];
	Output[11] ^= Input[11];
	Output[12] ^= Input[12];
	Output[13] ^= Input[13];
	Output[14] ^= Input[14];
	Output[15] ^= Input[15];
	Output[16] ^= Input[16];
	Output[17] ^= Input[17];
	Output[18] ^= Input[18];
	Output[19] ^= Input[19];
	Output[20] ^= Input[20];
	Output[21] ^= Input[21];
	Output[22] ^= Input[22];
	Output[23] ^= Input[23];
	Output[24] ^= Input[24];
	Output[25] ^= Input[25];
	Output[26] ^= Input[26];
	Output[27] ^= Input[27];
	Output[28] ^= Input[28];
	Output[29] ^= Input[29];
	Output[30] ^= Input[30];
	Output[31] ^= Input[21];
}
#endif

#if defined(HAS_MINSSE)
void IntUtils::XOR256(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	_mm_storeu_si128((__m128i*)(void*)&Output[OutOffset], _mm_xor_si128(_mm_loadu_si128((const __m128i*)(const void*)&Input[InOffset]), _mm_loadu_si128((const __m128i*)(const void*)&Output[OutOffset])));
	_mm_storeu_si128((__m128i*)(void*)&Output[OutOffset + 16], _mm_xor_si128(_mm_loadu_si128((const __m128i*)(const void*)&Input[InOffset + 16]), _mm_loadu_si128((const __m128i*)(const void*)&Output[OutOffset + 16])));
}
#elif
void IntUtils::XOR256(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	Output[OutOffset] ^= Input[InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
}
#endif

#if defined(HAS_MINSSE)
void IntUtils::XOR2X64(const std::vector<ulong> &Input, size_t InOffset, std::vector<ulong> &Output, size_t OutOffset)
{
	_mm_storeu_si128((__m128i*)(void*)&Output[OutOffset], _mm_xor_si128(_mm_loadu_si128((const __m128i*)(const void*)&Input[InOffset]), _mm_loadu_si128((const __m128i*)(const void*)&Output[OutOffset])));
}
#elif
void IntUtils::XOR2X64(const std::vector<ulong> &Input, size_t InOffset, std::vector<ulong> &Output, size_t OutOffset)
{
	Output[OutOffset] ^= Input[InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
}
#endif

#if defined(HAS_MINSSE)
void IntUtils::XOR4X64(const std::vector<ulong> &Input, size_t InOffset, std::vector<ulong> &Output, size_t OutOffset)
{
	_mm_storeu_si128((__m128i*)(void*)&Output[OutOffset], _mm_xor_si128(_mm_loadu_si128((const __m128i*)(const void*)&Input[InOffset]), _mm_loadu_si128((const __m128i*)(const void*)&Output[OutOffset])));
	_mm_storeu_si128((__m128i*)(void*)&Output[OutOffset + 2], _mm_xor_si128(_mm_loadu_si128((const __m128i*)(const void*)&Input[InOffset + 2]), _mm_loadu_si128((const __m128i*)(const void*)&Output[OutOffset + 2])));
}
#elif
void IntUtils::XOR4X64(const std::vector<ulong> &Input, size_t InOffset, std::vector<ulong> &Output, size_t OutOffset)
{
	Output[OutOffset] ^= Input[InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
}
#endif



#if defined(HAS_MINSSE)
void IntUtils::XOR8X64(const std::vector<ulong> &Input, size_t InOffset, std::vector<ulong> &Output, size_t OutOffset)
{
	_mm_storeu_si128((__m128i*)(void*)&Output[OutOffset], _mm_xor_si128(_mm_loadu_si128((const __m128i*)(const void*)&Input[InOffset]), _mm_loadu_si128((const __m128i*)(const void*)&Output[OutOffset])));
	_mm_storeu_si128((__m128i*)(void*)&Output[OutOffset + 2], _mm_xor_si128(_mm_loadu_si128((const __m128i*)(const void*)&Input[InOffset + 2]), _mm_loadu_si128((const __m128i*)(const void*)&Output[OutOffset + 2])));
	_mm_storeu_si128((__m128i*)(void*)&Output[OutOffset + 4], _mm_xor_si128(_mm_loadu_si128((const __m128i*)(const void*)&Input[InOffset + 4]), _mm_loadu_si128((const __m128i*)(const void*)&Output[OutOffset + 4])));
	_mm_storeu_si128((__m128i*)(void*)&Output[OutOffset + 6], _mm_xor_si128(_mm_loadu_si128((const __m128i*)(const void*)&Input[InOffset + 6]), _mm_loadu_si128((const __m128i*)(const void*)&Output[OutOffset + 6])));
}
#elif
void IntUtils::XOR4X64(const std::vector<ulong> &Input, size_t InOffset, std::vector<ulong> &Output, size_t OutOffset)
{
	Output[OutOffset] ^= Input[InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
}
#endif



#if defined(HAS_MINSSE)
void IntUtils::XOR4X32(const std::vector<uint> &Input, size_t InOffset, std::vector<uint> &Output, size_t OutOffset)
{
	_mm_storeu_si128((__m128i*)(void*)&Output[OutOffset], _mm_xor_si128(_mm_loadu_si128((const __m128i*)(const void*)&Input[InOffset]), _mm_loadu_si128((const __m128i*)(const void*)&Output[OutOffset])));
}
#elif
void IntUtils::XOR4X32(const std::vector<uint> &Input, size_t InOffset, std::vector<uint> &Output, size_t OutOffset)
{
	Output[OutOffset] ^= Input[InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
}
#endif

#if defined(HAS_MINSSE)
void IntUtils::XOR8X32(const std::vector<uint> &Input, size_t InOffset, std::vector<uint> &Output, size_t OutOffset)
{
	_mm_storeu_si128((__m128i*)(void*)&Output[OutOffset], _mm_xor_si128(_mm_loadu_si128((const __m128i*)(const void*)&Input[InOffset]), _mm_loadu_si128((const __m128i*)(const void*)&Output[OutOffset])));
	_mm_storeu_si128((__m128i*)(void*)&Output[OutOffset + 4], _mm_xor_si128(_mm_loadu_si128((const __m128i*)(const void*)&Input[InOffset + 4]), _mm_loadu_si128((const __m128i*)(const void*)&Output[OutOffset + 4])));
}
#elif
void IntUtils::XOR8X32(const std::vector<uint> &Input, size_t InOffset, std::vector<uint> &Output, size_t OutOffset)
{
	Output[OutOffset] ^= Input[InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
	Output[++OutOffset] ^= Input[++InOffset];
}
#endif

void IntUtils::XORBLK(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Size)
{
	const size_t BLOCK = 16;
	size_t ctr = 0;

	do
	{
		XOR128(Input, InOffset + ctr, Output, OutOffset + ctr);
		ctr += BLOCK;

	} while (ctr != Size);
}

NAMESPACE_UTILITYEND