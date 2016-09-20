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

void IntUtils::IXOR128(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
#if defined(HAS_MINSSE)
	_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset]), _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset])), _mm_loadu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset]))));
#else
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
#endif
}

void IntUtils::IXOR256(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
#if defined(HAS_MINSSE)
	_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset]), _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset])), _mm_loadu_si128((const __m128i*)(const void*)&Output[OutOffset])));
	_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset + 16]), _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset + 16])), _mm_loadu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset + 16]))));
#else
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
#endif
}

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

void IntUtils::XOR256(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
#if defined(HAS_MINSSE)
	_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset]), _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset])), _mm_loadu_si128((const __m128i*)(const void*)&Output[OutOffset])));
	_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset + 16]), _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset + 16])), _mm_loadu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset + 16]))));
#elif
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
#endif
}

void IntUtils::XORBLK(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Size, bool HasSSE)
{
	const size_t BLOCK = 16;
	size_t ctr = 0;

	do
	{
		if (HasSSE)
			IXOR128(Input, InOffset + ctr, Output, OutOffset + ctr);
		else
			XOR128(Input, InOffset + ctr, Output, OutOffset + ctr);
		ctr += BLOCK;
	} 
	while (ctr != Size);
}

NAMESPACE_UTILITYEND