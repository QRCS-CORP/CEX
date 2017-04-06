#include "ULong256.h"

NAMESPACE_NUMERIC

#if defined(__AVX2__)

void ULong256::LoadBE(ulong X0, ulong X1, ulong X2, ulong X3)
{
	Swap().LoadLE(X0, X1, X2, X3);
}

void ULong256::LoadLE(ulong X0, ulong X1, ulong X2, ulong X3)
{
	Register = _mm256_set_epi64x(X0, X1, X2, X3);
}

ULong256 ULong256::AndNot(const ULong256 &Value)
{
	return ULong256(_mm256_andnot_si256(Register, Value.Register));
}

const size_t ULong256::Length()
{
	return 32;
}

void ULong256::RotL64(const int Shift)
{
	Register = _mm256_or_si256(_mm256_slli_epi64(Register, static_cast<int>(Shift)), _mm256_srli_epi64(Register, static_cast<int>(64 - Shift)));
}

ULong256 ULong256::RotL64(const ULong256 &Value, const int Shift)
{
	return ULong256(_mm256_or_si256(_mm256_slli_epi64(Value.Register, static_cast<int>(Shift)), _mm256_srli_epi64(Value.Register, static_cast<int>(64 - Shift))));
}

void ULong256::RotR64(const int Shift)
{
	RotL64(64 - Shift);
}

ULong256 ULong256::RotR64(const ULong256 &Value, const int Shift)
{
	return RotL64(Value, 64 - Shift);
}

ULong256 ULong256::ShuffleLoadBE(const std::vector<byte> &Input, size_t Offset, size_t Shift)
{
	return ULong256(
		((ulong)Input[Offset] << 56) |
		((ulong)Input[Offset + 1] << 48) |
		((ulong)Input[Offset + 2] << 40) |
		((ulong)Input[Offset + 3] << 32) |
		((ulong)Input[Offset + 4] << 24) |
		((ulong)Input[Offset + 5] << 16) |
		((ulong)Input[Offset + 6] << 8) |
		((ulong)Input[Offset + 7]),
		((ulong)Input[Offset + Shift] << 56) |
		((ulong)Input[Offset + Shift + 1] << 48) |
		((ulong)Input[Offset + Shift + 2] << 40) |
		((ulong)Input[Offset + Shift + 3] << 32) |
		((ulong)Input[Offset + Shift + 4] << 24) |
		((ulong)Input[Offset + Shift + 5] << 16) |
		((ulong)Input[Offset + Shift + 6] << 8) |
		((ulong)Input[Offset + Shift + 7]),
		((ulong)Input[Offset + Shift * 2] << 56) |
		((ulong)Input[Offset + Shift * 2 + 1] << 48) |
		((ulong)Input[Offset + Shift * 2 + 2] << 40) |
		((ulong)Input[Offset + Shift * 2 + 3] << 32) |
		((ulong)Input[Offset + Shift * 2 + 4] << 24) |
		((ulong)Input[Offset + Shift * 2 + 5] << 16) |
		((ulong)Input[Offset + Shift * 2 + 6] << 8) |
		((ulong)Input[Offset + Shift * 2 + 7]),
		((ulong)Input[Offset + Shift * 3] << 56) |
		((ulong)Input[Offset + Shift * 3 + 1] << 48) |
		((ulong)Input[Offset + Shift * 3 + 2] << 40) |
		((ulong)Input[Offset + Shift * 3 + 3] << 32) |
		((ulong)Input[Offset + Shift * 3 + 4] << 24) |
		((ulong)Input[Offset + Shift * 3 + 5] << 16) |
		((ulong)Input[Offset + Shift * 3 + 6] << 8) |
		((ulong)Input[Offset + Shift * 3 + 7])
	);
}

ULong256 ULong256::ShuffleLoadLE(const std::vector<byte> &Input, size_t Offset, size_t Shift)
{
	return ULong256(
		((ulong)Input[Offset]) |
		((ulong)Input[Offset + 1] << 8) |
		((ulong)Input[Offset + 2] << 16) |
		((ulong)Input[Offset + 3] << 24) |
		((ulong)Input[Offset + 4] << 32) |
		((ulong)Input[Offset + 5] << 40) |
		((ulong)Input[Offset + 6] << 48) |
		((ulong)Input[Offset + 7] << 56),
		((ulong)Input[Offset + Shift]) |
		((ulong)Input[Offset + Shift + 1] << 8) |
		((ulong)Input[Offset + Shift + 2] << 16) |
		((ulong)Input[Offset + Shift + 3] << 24) |
		((ulong)Input[Offset + Shift + 4] << 32) |
		((ulong)Input[Offset + Shift + 5] << 40) |
		((ulong)Input[Offset + Shift + 6] << 48) |
		((ulong)Input[Offset + Shift + 7] << 56),
		((ulong)Input[Offset + Shift * 2]) |
		((ulong)Input[Offset + Shift * 2 + 1] << 8) |
		((ulong)Input[Offset + Shift * 2 + 2] << 16) |
		((ulong)Input[Offset + Shift * 2 + 3] << 24) |
		((ulong)Input[Offset + Shift * 2 + 4] << 32) |
		((ulong)Input[Offset + Shift * 2 + 5] << 40) |
		((ulong)Input[Offset + Shift * 2 + 6] << 48) |
		((ulong)Input[Offset + Shift * 2 + 7] << 56),
		((ulong)Input[Offset + Shift * 3]) |
		((ulong)Input[Offset + Shift * 3 + 1] << 8) |
		((ulong)Input[Offset + Shift * 3 + 2] << 16) |
		((ulong)Input[Offset + Shift * 3 + 3] << 24) |
		((ulong)Input[Offset + Shift * 3 + 4] << 32) |
		((ulong)Input[Offset + Shift * 3 + 5] << 40) |
		((ulong)Input[Offset + Shift * 3 + 6] << 48) |
		((ulong)Input[Offset + Shift * 3 + 7] << 56)
	);
}

ULong256 ULong256::Swap() const
{
	__m256i T = Register;

	T = _mm256_shufflehi_epi16(T, _MM_SHUFFLE(2, 3, 0, 1));
	T = _mm256_shufflelo_epi16(T, _MM_SHUFFLE(2, 3, 0, 1));

	return ULong256(_mm256_or_si256(_mm256_srli_epi16(T, 8), _mm256_slli_epi16(T, 8)));
}

ULong256 ULong256::Swap(ULong256 &X)
{
	__m256i T = X.Register;

	T = _mm256_shufflehi_epi16(T, _MM_SHUFFLE(2, 3, 0, 1));
	T = _mm256_shufflelo_epi16(T, _MM_SHUFFLE(2, 3, 0, 1));

	return ULong256(_mm256_or_si256(_mm256_srli_epi16(T, 8), _mm256_slli_epi16(T, 8)));
}

void ULong256::ToUint8(std::vector<byte> &Output, size_t Offset)
{
	memcpy(&Output[Offset], &Register.m256i_u8[0], 32);
}

void ULong256::ToUint16(std::vector<ushort> &Output, size_t Offset)
{
	memcpy(&Output[Offset], &Register.m256i_u16[0], 32);
}

void ULong256::ToUint32(std::vector<uint> &Output, size_t Offset)
{
	memcpy(&Output[Offset], &Register.m256i_u32[0], 32);
}

void ULong256::ToUint64(std::vector<ulong> &Output, size_t Offset)
{
	memcpy(&Output[Offset], &Register.m256i_u64[0], 32);
}

#endif
NAMESPACE_NUMERICEND