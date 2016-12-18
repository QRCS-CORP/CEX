#include "UInt256.h"

NAMESPACE_NUMERIC

void UInt256::LoadBE(uint X0, uint X1, uint X2, uint X3, uint X4, uint X5, uint X6, uint X7)
{
	Swap().LoadLE(X0, X1, X2, X3, X4, X5, X6, X7);
}

void UInt256::LoadBE32(const std::vector<byte> &Input, size_t Offset, UInt256 &X0, UInt256 &X1, UInt256 &X2, UInt256 &X3)
{
	X0.LoadBE(Input, Offset);
	X1.LoadBE(Input, Offset + 32);
	X2.LoadBE(Input, Offset + 64);
	X3.LoadBE(Input, Offset + 96);
	Transpose(X0, X1, X2, X3);
}

void UInt256::LoadBE512(std::vector<byte> &Input, size_t InOffset, std::vector<UInt256> &Output, size_t OutOffset)
{
	Output[OutOffset].LoadBE(Input, InOffset);
	Output[OutOffset + 1].LoadBE(Input, InOffset + 32);
	Output[OutOffset + 2].LoadBE(Input, InOffset + 64);
	Output[OutOffset + 3].LoadBE(Input, InOffset + 96);
	Output[OutOffset + 4].LoadBE(Input, InOffset + 128);
	Output[OutOffset + 5].LoadBE(Input, InOffset + 160);
	Output[OutOffset + 6].LoadBE(Input, InOffset + 192);
	Output[OutOffset + 7].LoadBE(Input, InOffset + 224);
	Output[OutOffset + 8].LoadBE(Input, InOffset + 256);
	Output[OutOffset + 9].LoadBE(Input, InOffset + 288);
	Output[OutOffset + 10].LoadBE(Input, InOffset + 320);
	Output[OutOffset + 11].LoadBE(Input, InOffset + 352);
	Output[OutOffset + 12].LoadBE(Input, InOffset + 384);
	Output[OutOffset + 13].LoadBE(Input, InOffset + 416);
	Output[OutOffset + 14].LoadBE(Input, InOffset + 448);
	Output[OutOffset + 15].LoadBE(Input, InOffset + 480);
}

void UInt256::LoadLE(uint X0, uint X1, uint X2, uint X3, uint X4, uint X5, uint X6, uint X7)
{
	Register = _mm256_set_epi32(X0, X1, X2, X3, X4, X5, X6, X7);
}

void UInt256::LoadLE32(const std::vector<byte> &Input, size_t Offset, UInt256 &X0, UInt256 &X1, UInt256 &X2, UInt256 &X3)
{
	X0.LoadLE(Input, Offset);
	X1.LoadLE(Input, Offset + 32);
	X2.LoadLE(Input, Offset + 64);
	X3.LoadLE(Input, Offset + 96);
	Transpose(X0, X1, X2, X3);
}

void UInt256::LoadLE512(std::vector<byte> &Input, size_t InOffset, std::vector<UInt256> &Output, size_t OutOffset)
{
	Output[OutOffset].LoadLE(Input, InOffset);
	Output[OutOffset + 1].LoadLE(Input, InOffset + 32);
	Output[OutOffset + 2].LoadLE(Input, InOffset + 64);
	Output[OutOffset + 3].LoadLE(Input, InOffset + 96);
	Output[OutOffset + 4].LoadLE(Input, InOffset + 128);
	Output[OutOffset + 5].LoadLE(Input, InOffset + 160);
	Output[OutOffset + 6].LoadLE(Input, InOffset + 192);
	Output[OutOffset + 7].LoadLE(Input, InOffset + 224);
	Output[OutOffset + 8].LoadLE(Input, InOffset + 256);
	Output[OutOffset + 9].LoadLE(Input, InOffset + 288);
	Output[OutOffset + 10].LoadLE(Input, InOffset + 320);
	Output[OutOffset + 11].LoadLE(Input, InOffset + 352);
	Output[OutOffset + 12].LoadLE(Input, InOffset + 384);
	Output[OutOffset + 13].LoadLE(Input, InOffset + 416);
	Output[OutOffset + 14].LoadLE(Input, InOffset + 448);
	Output[OutOffset + 15].LoadLE(Input, InOffset + 480);
}

void UInt256::StoreBE32(std::vector<byte> &Output, size_t Offset, UInt256 &X0, UInt256 &X1, UInt256 &X2, UInt256 &X3)
{
	Transpose(X0, X1, X2, X3);
	X0.StoreBE(Output, Offset);
	X1.StoreBE(Output, Offset + 32);
	X2.StoreBE(Output, Offset + 64);
	X3.StoreBE(Output, Offset + 96);
}

void UInt256::StoreBE512(std::vector<UInt256> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	__m256i W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14, W15;
	__m256i Y0, Y1, Y2, Y3, Y4, Y5, Y6, Y7, Y8, Y9, Y10, Y11, Y12, Y13, Y14, Y15;

	_mm256_merge_epi32(Input[InOffset].Register, Input[InOffset + 1].Register, W0, W1);
	_mm256_merge_epi32(Input[InOffset + 2].Register, Input[InOffset + 3].Register, W2, W3);
	_mm256_merge_epi32(Input[InOffset + 4].Register, Input[InOffset + 5].Register, W4, W5);
	_mm256_merge_epi32(Input[InOffset + 6].Register, Input[InOffset + 7].Register, W6, W7);
	_mm256_merge_epi32(Input[InOffset + 8].Register, Input[InOffset + 9].Register, W8, W9);
	_mm256_merge_epi32(Input[InOffset + 10].Register, Input[InOffset + 11].Register, W10, W11);
	_mm256_merge_epi32(Input[InOffset + 12].Register, Input[InOffset + 13].Register, W12, W13);
	_mm256_merge_epi32(Input[InOffset + 14].Register, Input[InOffset + 15].Register, W14, W15);

	_mm256_merge_epi64(W0, W2, Y0, Y1);
	_mm256_merge_epi64(W4, W6, Y2, Y3);
	_mm256_merge_epi64(W8, W10, Y4, Y5);
	_mm256_merge_epi64(W12, W14, Y6, Y7);
	_mm256_merge_epi64(W1, W3, Y8, Y9);
	_mm256_merge_epi64(W5, W7, Y10, Y11);
	_mm256_merge_epi64(W9, W11, Y12, Y13);
	_mm256_merge_epi64(W13, W15, Y14, Y15);

	_mm256_merge_si128(Y0, Y2, Input[InOffset].Register, Input[InOffset + 1].Register);
	_mm256_merge_si128(Y1, Y3, Input[InOffset + 2].Register, Input[InOffset + 3].Register);
	_mm256_merge_si128(Y8, Y10, Input[InOffset + 4].Register, Input[InOffset + 5].Register);
	_mm256_merge_si128(Y9, Y11, Input[InOffset + 6].Register, Input[InOffset + 7].Register);
	_mm256_merge_si128(Y4, Y6, Input[InOffset + 8].Register, Input[InOffset + 9].Register);
	_mm256_merge_si128(Y5, Y7, Input[InOffset + 10].Register, Input[InOffset + 11].Register);
	_mm256_merge_si128(Y12, Y14, Input[InOffset + 12].Register, Input[InOffset + 13].Register);
	_mm256_merge_si128(Y13, Y15, Input[InOffset + 14].Register, Input[InOffset + 15].Register);

	Input[InOffset].StoreBE(Output, OutOffset);
	Input[InOffset + 8].StoreBE(Output, OutOffset + 32);
	Input[InOffset + 1].StoreBE(Output, OutOffset + 64);
	Input[InOffset + 9].StoreBE(Output, OutOffset + 96);
	Input[InOffset + 2].StoreBE(Output, OutOffset + 128);
	Input[InOffset + 10].StoreBE(Output, OutOffset + 160);
	Input[InOffset + 3].StoreBE(Output, OutOffset + 192);
	Input[InOffset + 11].StoreBE(Output, OutOffset + 224);
	Input[InOffset + 4].StoreBE(Output, OutOffset + 256);
	Input[InOffset + 12].StoreBE(Output, OutOffset + 288);
	Input[InOffset + 5].StoreBE(Output, OutOffset + 320);
	Input[InOffset + 13].StoreBE(Output, OutOffset + 352);
	Input[InOffset + 6].StoreBE(Output, OutOffset + 384);
	Input[InOffset + 14].StoreBE(Output, OutOffset + 416);
	Input[InOffset + 7].StoreBE(Output, OutOffset + 448);
	Input[InOffset + 15].StoreBE(Output, OutOffset + 480);
}

void UInt256::StoreLE32(std::vector<byte> &Output, size_t Offset, UInt256 &X0, UInt256 &X1, UInt256 &X2, UInt256 &X3)
{
	Transpose(X0, X1, X2, X3);
	X0.StoreLE(Output, Offset);
	X1.StoreLE(Output, Offset + 32);
	X2.StoreLE(Output, Offset + 64);
	X3.StoreLE(Output, Offset + 96);
}

void UInt256::StoreLE512(std::vector<UInt256> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	__m256i W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14, W15;
	__m256i Y0, Y1, Y2, Y3, Y4, Y5, Y6, Y7, Y8, Y9, Y10, Y11, Y12, Y13, Y14, Y15;

	_mm256_merge_epi32(Input[InOffset].Register, Input[InOffset + 1].Register, W0, W1);
	_mm256_merge_epi32(Input[InOffset + 2].Register, Input[InOffset + 3].Register, W2, W3);
	_mm256_merge_epi32(Input[InOffset + 4].Register, Input[InOffset + 5].Register, W4, W5);
	_mm256_merge_epi32(Input[InOffset + 6].Register, Input[InOffset + 7].Register, W6, W7);
	_mm256_merge_epi32(Input[InOffset + 8].Register, Input[InOffset + 9].Register, W8, W9);
	_mm256_merge_epi32(Input[InOffset + 10].Register, Input[InOffset + 11].Register, W10, W11);
	_mm256_merge_epi32(Input[InOffset + 12].Register, Input[InOffset + 13].Register, W12, W13);
	_mm256_merge_epi32(Input[InOffset + 14].Register, Input[InOffset + 15].Register, W14, W15);

	_mm256_merge_epi64(W0, W2, Y0, Y1);
	_mm256_merge_epi64(W4, W6, Y2, Y3);
	_mm256_merge_epi64(W8, W10, Y4, Y5);
	_mm256_merge_epi64(W12, W14, Y6, Y7);
	_mm256_merge_epi64(W1, W3, Y8, Y9);
	_mm256_merge_epi64(W5, W7, Y10, Y11);
	_mm256_merge_epi64(W9, W11, Y12, Y13);
	_mm256_merge_epi64(W13, W15, Y14, Y15);

	_mm256_merge_si128(Y0, Y2, Input[InOffset].Register, Input[InOffset + 1].Register);
	_mm256_merge_si128(Y1, Y3, Input[InOffset + 2].Register, Input[InOffset + 3].Register);
	_mm256_merge_si128(Y8, Y10, Input[InOffset + 4].Register, Input[InOffset + 5].Register);
	_mm256_merge_si128(Y9, Y11, Input[InOffset + 6].Register, Input[InOffset + 7].Register);
	_mm256_merge_si128(Y4, Y6, Input[InOffset + 8].Register, Input[InOffset + 9].Register);
	_mm256_merge_si128(Y5, Y7, Input[InOffset + 10].Register, Input[InOffset + 11].Register);
	_mm256_merge_si128(Y12, Y14, Input[InOffset + 12].Register, Input[InOffset + 13].Register);
	_mm256_merge_si128(Y13, Y15, Input[InOffset + 14].Register, Input[InOffset + 15].Register);

	Input[InOffset].StoreLE(Output, OutOffset);
	Input[InOffset + 8].StoreLE(Output, OutOffset + 32);
	Input[InOffset + 1].StoreLE(Output, OutOffset + 64);
	Input[InOffset + 9].StoreLE(Output, OutOffset + 96);
	Input[InOffset + 2].StoreLE(Output, OutOffset + 128);
	Input[InOffset + 10].StoreLE(Output, OutOffset + 160);
	Input[InOffset + 3].StoreLE(Output, OutOffset + 192);
	Input[InOffset + 11].StoreLE(Output, OutOffset + 224);
	Input[InOffset + 4].StoreLE(Output, OutOffset + 256);
	Input[InOffset + 12].StoreLE(Output, OutOffset + 288);
	Input[InOffset + 5].StoreLE(Output, OutOffset + 320);
	Input[InOffset + 13].StoreLE(Output, OutOffset + 352);
	Input[InOffset + 6].StoreLE(Output, OutOffset + 384);
	Input[InOffset + 14].StoreLE(Output, OutOffset + 416);
	Input[InOffset + 7].StoreLE(Output, OutOffset + 448);
	Input[InOffset + 15].StoreLE(Output, OutOffset + 480);
}

UInt256 UInt256::AndNot(const UInt256 &Value)
{
	return UInt256(_mm256_andnot_si256(Register, Value.Register));
}

const size_t UInt256::Length()
{
	return 32;
}

void UInt256::Rotl32(const int Shift)
{
	Register = _mm256_or_si256(_mm256_slli_epi32(Register, static_cast<int>(Shift)), _mm256_srli_epi32(Register, static_cast<int>(32 - Shift)));
}

UInt256 UInt256::Rotl32(const UInt256 &Value, const int Shift)
{
	return UInt256(_mm256_or_si256(_mm256_slli_epi32(Value.Register, static_cast<int>(Shift)), _mm256_srli_epi32(Value.Register, static_cast<int>(32 - Shift))));
}

void UInt256::Rotr32(const int Shift)
{
	Rotl32(32 - Shift);
}

UInt256 UInt256::Rotr32(const UInt256 &Value, const int Shift)
{
	return Rotl32(Value, 32 - Shift);
}

UInt256 UInt256::ShuffleLoadBE(const std::vector<byte> &Input, size_t Offset, size_t Shift)
{
	return UInt256(
		(Input[Offset] << 24) | (Input[Offset + 1] << 16) | (Input[Offset + 2] << 8) | Input[Offset + 3],
		(Input[Offset + Shift] << 24) | (Input[Offset + 1 + Shift] << 16) | (Input[Offset + 2 + Shift] << 8) | Input[Offset + 3 + Shift],
		(Input[Offset + Shift * 2] << 24) | (Input[Offset + 1 + Shift * 2] << 16) | (Input[Offset + 2 + Shift * 2] << 8) | Input[Offset + 3 + Shift * 2],
		(Input[Offset + Shift * 3] << 24) | (Input[Offset + 1 + Shift * 3] << 16) | (Input[Offset + 2 + Shift * 3] << 8) | Input[Offset + 3 + Shift * 3],
		(Input[Offset + Shift * 4] << 24) | (Input[Offset + 1 + Shift * 4] << 16) | (Input[Offset + 2 + Shift * 4] << 8) | Input[Offset + 3 + Shift * 4],
		(Input[Offset + Shift * 5] << 24) | (Input[Offset + 1 + Shift * 5] << 16) | (Input[Offset + 2 + Shift * 5] << 8) | Input[Offset + 3 + Shift * 5],
		(Input[Offset + Shift * 6] << 24) | (Input[Offset + 1 + Shift * 6] << 16) | (Input[Offset + 2 + Shift * 6] << 8) | Input[Offset + 3 + Shift * 6],
		(Input[Offset + Shift * 7] << 24) | (Input[Offset + 1 + Shift * 7] << 16) | (Input[Offset + 2 + Shift * 7] << 8) | Input[Offset + 3 + Shift * 7]);
}

UInt256 UInt256::ShuffleLoadLE(const std::vector<byte> &Input, size_t Offset, size_t Shift)
{
	return UInt256(
		Input[Offset] | (Input[Offset + 1] << 8) | (Input[Offset + 2] << 16) | (Input[Offset + 3] << 24),
		Input[Offset + Shift] | (Input[Offset + 1 + Shift] << 8) | (Input[Offset + 2 + Shift] << 16) | (Input[Offset + 3 + Shift] << 24),
		Input[Offset + Shift * 2] | (Input[Offset + 1 + Shift * 2] << 8) | (Input[Offset + 2 + Shift * 2] << 16) | (Input[Offset + 3 + Shift * 2] << 24),
		Input[Offset + Shift * 3] | (Input[Offset + 1 + Shift * 3] << 8) | (Input[Offset + 2 + Shift * 3] << 16) | (Input[Offset + 3 + Shift * 3] << 24),
		Input[Offset + Shift * 4] | (Input[Offset + 1 + Shift * 4] << 8) | (Input[Offset + 2 + Shift * 4] << 16) | (Input[Offset + 3 + Shift * 4] << 24),
		Input[Offset + Shift * 5] | (Input[Offset + 1 + Shift * 5] << 8) | (Input[Offset + 2 + Shift * 5] << 16) | (Input[Offset + 3 + Shift * 5] << 24),
		Input[Offset + Shift * 6] | (Input[Offset + 1 + Shift * 6] << 8) | (Input[Offset + 2 + Shift * 6] << 16) | (Input[Offset + 3 + Shift * 6] << 24),
		Input[Offset + Shift * 7] | (Input[Offset + 1 + Shift * 7] << 8) | (Input[Offset + 2 + Shift * 7] << 16) | (Input[Offset + 3 + Shift * 7] << 24));
}

UInt256 UInt256::Swap() const
{
	__m256i T = Register;

	T = _mm256_shufflehi_epi16(T, _MM_SHUFFLE(2, 3, 0, 1));
	T = _mm256_shufflelo_epi16(T, _MM_SHUFFLE(2, 3, 0, 1));

	return UInt256(_mm256_or_si256(_mm256_srli_epi16(T, 8), _mm256_slli_epi16(T, 8)));
}

UInt256 UInt256::Swap(UInt256 &X)
{
	__m256i T = X.Register;

	T = _mm256_shufflehi_epi16(T, _MM_SHUFFLE(2, 3, 0, 1));
	T = _mm256_shufflelo_epi16(T, _MM_SHUFFLE(2, 3, 0, 1));

	return UInt256(_mm256_or_si256(_mm256_srli_epi16(T, 8), _mm256_slli_epi16(T, 8)));
}

void UInt256::ToUint8(std::vector<byte> &Output, size_t Offset)
{
	memcpy(&Output[Offset], &Register.m256i_u8[0], 32);
}

void UInt256::ToUint16(std::vector<ushort> &Output, size_t Offset)
{
	memcpy(&Output[Offset], &Register.m256i_u16[0], 32);
}

void UInt256::ToUint32(std::vector<uint> &Output, size_t Offset)
{
	memcpy(&Output[Offset], &Register.m256i_u32[0], 32);
}

void UInt256::ToUint64(std::vector<ulong> &Output, size_t Offset)
{
	memcpy(&Output[Offset], &Register.m256i_u64[0], 32);
}

void UInt256::Transpose(UInt256 &X0, UInt256 &X1, UInt256 &X2, UInt256 &X3)
{
	__m256i T0 = _mm256_unpacklo_epi32(X0.Register, X1.Register);
	__m256i T1 = _mm256_unpacklo_epi32(X2.Register, X3.Register);
	__m256i T2 = _mm256_unpackhi_epi32(X0.Register, X1.Register);
	__m256i T3 = _mm256_unpackhi_epi32(X2.Register, X3.Register);
	X0.Register = _mm256_unpacklo_epi64(T0, T1);
	X1.Register = _mm256_unpackhi_epi64(T0, T1);
	X2.Register = _mm256_unpacklo_epi64(T2, T3);
	X3.Register = _mm256_unpackhi_epi64(T2, T3);
}


NAMESPACE_NUMERICEND