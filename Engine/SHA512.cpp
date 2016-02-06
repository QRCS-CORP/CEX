#include "SHA512.h"
#include "SHA.h"
#include "IntUtils.h"

NAMESPACE_DIGEST

void SHA512::BlockUpdate(const std::vector<byte> &Input, unsigned int InOffset, unsigned int Length)
{
	if ((InOffset + Length) > Input.size())
		throw CryptoDigestException("SHA512:BlockUpdate", "The Input buffer is too short!");

	// fill the current word
	while ((_bufferOffset != 0) && (Length > 0))
	{
		Update(Input[InOffset]);
		InOffset++;
		Length--;
	}

	// process whole words
	while (Length >= _prcBuffer.size())
	{
		ProcessWord(Input, InOffset);
		InOffset += _prcBuffer.size();
		Length -= _prcBuffer.size();
		_btCounter1 += _prcBuffer.size();
	}

	// load in the remainder
	while (Length != 0)
	{
		Update(Input[InOffset]);
		InOffset++;
		Length--;
	}
}

void SHA512::ComputeHash(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Output.resize(DIGEST_SIZE);
	BlockUpdate(Input, 0, Input.size());
	DoFinal(Output, 0);
}

void SHA512::Destroy()
{
	if (!_isDestroyed)
	{
		_isDestroyed = true;
		_btCounter1 = 0;
		_btCounter2 = 0;
		_bufferOffset = 0;
		_H0 = 0, _H1 = 0, _H2 = 0, _H3 = 0, _H4 = 0, _H5 = 0, _H6 = 0, _H7 = 0;
		_wordOffset = 0;

		CEX::Utility::IntUtils::ClearVector(_prcBuffer);
		CEX::Utility::IntUtils::ClearVector(_wordBuffer);
	}
}

unsigned int SHA512::DoFinal(std::vector<byte> &Output, const unsigned int OutOffset)
{
	if (Output.size() - OutOffset < DIGEST_SIZE)
		throw CryptoDigestException("SHA512:DoFinal", "The Output buffer is too short!");

	Finish();
	CEX::Utility::IntUtils::Be64ToBytes(_H0, Output, OutOffset);
	CEX::Utility::IntUtils::Be64ToBytes(_H1, Output, OutOffset + 8);
	CEX::Utility::IntUtils::Be64ToBytes(_H2, Output, OutOffset + 16);
	CEX::Utility::IntUtils::Be64ToBytes(_H3, Output, OutOffset + 24);
	CEX::Utility::IntUtils::Be64ToBytes(_H4, Output, OutOffset + 32);
	CEX::Utility::IntUtils::Be64ToBytes(_H5, Output, OutOffset + 40);
	CEX::Utility::IntUtils::Be64ToBytes(_H6, Output, OutOffset + 48);
	CEX::Utility::IntUtils::Be64ToBytes(_H7, Output, OutOffset + 56);

	Reset();

	return DIGEST_SIZE;
}

void SHA512::Reset()
{
	_btCounter1 = 0;
	_btCounter2 = 0;
	_bufferOffset = 0;
	std::fill(_prcBuffer.begin(), _prcBuffer.end(), 0);
	std::fill(_wordBuffer.begin(), _wordBuffer.end(), 0);
	_wordOffset = 0;

	Initialize();
}

void SHA512::Update(byte Input)
{
	_prcBuffer[_bufferOffset++] = Input;

	if (_bufferOffset == _prcBuffer.size())
	{
		ProcessWord(_prcBuffer, 0);
		_bufferOffset = 0;
	}

	_btCounter1++;
}

// *** Protected Methods *** //

void SHA512::AdjustByteCounts()
{
	if (_btCounter1 > 0x1fffffffffffffffL)
	{
		_btCounter2 += (int64_t)((uint64_t)_btCounter1 >> 61);
		_btCounter1 &= 0x1fffffffffffffffL;
	}
}

void SHA512::Finish()
{
	AdjustByteCounts();

	ulong lowBitLen = _btCounter1 << 3;
	ulong hiBitLen = _btCounter2;

	// add the pad bytes
	Update((byte)128);

	while (_bufferOffset != 0)
		Update((byte)0);

	ProcessLength(lowBitLen, hiBitLen);
	ProcessBlock();
}

void SHA512::Initialize()
{
	_H0 = 0x6a09e667f3bcc908;
	_H1 = 0xbb67ae8584caa73b;
	_H2 = 0x3c6ef372fe94f82b;
	_H3 = 0xa54ff53a5f1d36f1;
	_H4 = 0x510e527fade682d1;
	_H5 = 0x9b05688c2b3e6c1f;
	_H6 = 0x1f83d9abfb41bd6b;
	_H7 = 0x5be0cd19137e2179;
}

void SHA512::ProcessBlock()
{
	AdjustByteCounts();

	// expand 16 word block into 80 word blocks
	_wordBuffer[16] = Sigma1(_wordBuffer[14]) + _wordBuffer[9] + Sigma0(_wordBuffer[1]) + _wordBuffer[0];
	_wordBuffer[17] = Sigma1(_wordBuffer[15]) + _wordBuffer[10] + Sigma0(_wordBuffer[2]) + _wordBuffer[1];
	_wordBuffer[18] = Sigma1(_wordBuffer[16]) + _wordBuffer[11] + Sigma0(_wordBuffer[3]) + _wordBuffer[2];
	_wordBuffer[19] = Sigma1(_wordBuffer[17]) + _wordBuffer[12] + Sigma0(_wordBuffer[4]) + _wordBuffer[3];
	_wordBuffer[20] = Sigma1(_wordBuffer[18]) + _wordBuffer[13] + Sigma0(_wordBuffer[5]) + _wordBuffer[4];
	_wordBuffer[21] = Sigma1(_wordBuffer[19]) + _wordBuffer[14] + Sigma0(_wordBuffer[6]) + _wordBuffer[5];
	_wordBuffer[22] = Sigma1(_wordBuffer[20]) + _wordBuffer[15] + Sigma0(_wordBuffer[7]) + _wordBuffer[6];
	_wordBuffer[23] = Sigma1(_wordBuffer[21]) + _wordBuffer[16] + Sigma0(_wordBuffer[8]) + _wordBuffer[7];
	_wordBuffer[24] = Sigma1(_wordBuffer[22]) + _wordBuffer[17] + Sigma0(_wordBuffer[9]) + _wordBuffer[8];
	_wordBuffer[25] = Sigma1(_wordBuffer[23]) + _wordBuffer[18] + Sigma0(_wordBuffer[10]) + _wordBuffer[9];
	_wordBuffer[26] = Sigma1(_wordBuffer[24]) + _wordBuffer[19] + Sigma0(_wordBuffer[11]) + _wordBuffer[10];
	_wordBuffer[27] = Sigma1(_wordBuffer[25]) + _wordBuffer[20] + Sigma0(_wordBuffer[12]) + _wordBuffer[11];
	_wordBuffer[28] = Sigma1(_wordBuffer[26]) + _wordBuffer[21] + Sigma0(_wordBuffer[13]) + _wordBuffer[12];
	_wordBuffer[29] = Sigma1(_wordBuffer[27]) + _wordBuffer[22] + Sigma0(_wordBuffer[14]) + _wordBuffer[13];
	_wordBuffer[30] = Sigma1(_wordBuffer[28]) + _wordBuffer[23] + Sigma0(_wordBuffer[15]) + _wordBuffer[14];
	_wordBuffer[31] = Sigma1(_wordBuffer[29]) + _wordBuffer[24] + Sigma0(_wordBuffer[16]) + _wordBuffer[15];
	_wordBuffer[32] = Sigma1(_wordBuffer[30]) + _wordBuffer[25] + Sigma0(_wordBuffer[17]) + _wordBuffer[16];
	_wordBuffer[33] = Sigma1(_wordBuffer[31]) + _wordBuffer[26] + Sigma0(_wordBuffer[18]) + _wordBuffer[17];
	_wordBuffer[34] = Sigma1(_wordBuffer[32]) + _wordBuffer[27] + Sigma0(_wordBuffer[19]) + _wordBuffer[18];
	_wordBuffer[35] = Sigma1(_wordBuffer[33]) + _wordBuffer[28] + Sigma0(_wordBuffer[20]) + _wordBuffer[19];
	_wordBuffer[36] = Sigma1(_wordBuffer[34]) + _wordBuffer[29] + Sigma0(_wordBuffer[21]) + _wordBuffer[20];
	_wordBuffer[37] = Sigma1(_wordBuffer[35]) + _wordBuffer[30] + Sigma0(_wordBuffer[22]) + _wordBuffer[21];
	_wordBuffer[38] = Sigma1(_wordBuffer[36]) + _wordBuffer[31] + Sigma0(_wordBuffer[23]) + _wordBuffer[22];
	_wordBuffer[39] = Sigma1(_wordBuffer[37]) + _wordBuffer[32] + Sigma0(_wordBuffer[24]) + _wordBuffer[23];
	_wordBuffer[40] = Sigma1(_wordBuffer[38]) + _wordBuffer[33] + Sigma0(_wordBuffer[25]) + _wordBuffer[24];
	_wordBuffer[41] = Sigma1(_wordBuffer[39]) + _wordBuffer[34] + Sigma0(_wordBuffer[26]) + _wordBuffer[25];
	_wordBuffer[42] = Sigma1(_wordBuffer[40]) + _wordBuffer[35] + Sigma0(_wordBuffer[27]) + _wordBuffer[26];
	_wordBuffer[43] = Sigma1(_wordBuffer[41]) + _wordBuffer[36] + Sigma0(_wordBuffer[28]) + _wordBuffer[27];
	_wordBuffer[44] = Sigma1(_wordBuffer[42]) + _wordBuffer[37] + Sigma0(_wordBuffer[29]) + _wordBuffer[28];
	_wordBuffer[45] = Sigma1(_wordBuffer[43]) + _wordBuffer[38] + Sigma0(_wordBuffer[30]) + _wordBuffer[29];
	_wordBuffer[46] = Sigma1(_wordBuffer[44]) + _wordBuffer[39] + Sigma0(_wordBuffer[31]) + _wordBuffer[30];
	_wordBuffer[47] = Sigma1(_wordBuffer[45]) + _wordBuffer[40] + Sigma0(_wordBuffer[32]) + _wordBuffer[31];
	_wordBuffer[48] = Sigma1(_wordBuffer[46]) + _wordBuffer[41] + Sigma0(_wordBuffer[33]) + _wordBuffer[32];
	_wordBuffer[49] = Sigma1(_wordBuffer[47]) + _wordBuffer[42] + Sigma0(_wordBuffer[34]) + _wordBuffer[33];
	_wordBuffer[50] = Sigma1(_wordBuffer[48]) + _wordBuffer[43] + Sigma0(_wordBuffer[35]) + _wordBuffer[34];
	_wordBuffer[51] = Sigma1(_wordBuffer[49]) + _wordBuffer[44] + Sigma0(_wordBuffer[36]) + _wordBuffer[35];
	_wordBuffer[52] = Sigma1(_wordBuffer[50]) + _wordBuffer[45] + Sigma0(_wordBuffer[37]) + _wordBuffer[36];
	_wordBuffer[53] = Sigma1(_wordBuffer[51]) + _wordBuffer[46] + Sigma0(_wordBuffer[38]) + _wordBuffer[37];
	_wordBuffer[54] = Sigma1(_wordBuffer[52]) + _wordBuffer[47] + Sigma0(_wordBuffer[39]) + _wordBuffer[38];
	_wordBuffer[55] = Sigma1(_wordBuffer[53]) + _wordBuffer[48] + Sigma0(_wordBuffer[40]) + _wordBuffer[39];
	_wordBuffer[56] = Sigma1(_wordBuffer[54]) + _wordBuffer[49] + Sigma0(_wordBuffer[41]) + _wordBuffer[40];
	_wordBuffer[57] = Sigma1(_wordBuffer[55]) + _wordBuffer[50] + Sigma0(_wordBuffer[42]) + _wordBuffer[41];
	_wordBuffer[58] = Sigma1(_wordBuffer[56]) + _wordBuffer[51] + Sigma0(_wordBuffer[43]) + _wordBuffer[42];
	_wordBuffer[59] = Sigma1(_wordBuffer[57]) + _wordBuffer[52] + Sigma0(_wordBuffer[44]) + _wordBuffer[43];
	_wordBuffer[60] = Sigma1(_wordBuffer[58]) + _wordBuffer[53] + Sigma0(_wordBuffer[45]) + _wordBuffer[44];
	_wordBuffer[61] = Sigma1(_wordBuffer[59]) + _wordBuffer[54] + Sigma0(_wordBuffer[46]) + _wordBuffer[45];
	_wordBuffer[62] = Sigma1(_wordBuffer[60]) + _wordBuffer[55] + Sigma0(_wordBuffer[47]) + _wordBuffer[46];
	_wordBuffer[63] = Sigma1(_wordBuffer[61]) + _wordBuffer[56] + Sigma0(_wordBuffer[48]) + _wordBuffer[47];
	_wordBuffer[64] = Sigma1(_wordBuffer[62]) + _wordBuffer[57] + Sigma0(_wordBuffer[49]) + _wordBuffer[48];
	_wordBuffer[65] = Sigma1(_wordBuffer[63]) + _wordBuffer[58] + Sigma0(_wordBuffer[50]) + _wordBuffer[49];
	_wordBuffer[66] = Sigma1(_wordBuffer[64]) + _wordBuffer[59] + Sigma0(_wordBuffer[51]) + _wordBuffer[50];
	_wordBuffer[67] = Sigma1(_wordBuffer[65]) + _wordBuffer[60] + Sigma0(_wordBuffer[52]) + _wordBuffer[51];
	_wordBuffer[68] = Sigma1(_wordBuffer[66]) + _wordBuffer[61] + Sigma0(_wordBuffer[53]) + _wordBuffer[52];
	_wordBuffer[69] = Sigma1(_wordBuffer[67]) + _wordBuffer[62] + Sigma0(_wordBuffer[54]) + _wordBuffer[53];
	_wordBuffer[70] = Sigma1(_wordBuffer[68]) + _wordBuffer[63] + Sigma0(_wordBuffer[55]) + _wordBuffer[54];
	_wordBuffer[71] = Sigma1(_wordBuffer[69]) + _wordBuffer[64] + Sigma0(_wordBuffer[56]) + _wordBuffer[55];
	_wordBuffer[72] = Sigma1(_wordBuffer[70]) + _wordBuffer[65] + Sigma0(_wordBuffer[57]) + _wordBuffer[56];
	_wordBuffer[73] = Sigma1(_wordBuffer[71]) + _wordBuffer[66] + Sigma0(_wordBuffer[58]) + _wordBuffer[57];
	_wordBuffer[74] = Sigma1(_wordBuffer[72]) + _wordBuffer[67] + Sigma0(_wordBuffer[59]) + _wordBuffer[58];
	_wordBuffer[75] = Sigma1(_wordBuffer[73]) + _wordBuffer[68] + Sigma0(_wordBuffer[60]) + _wordBuffer[59];
	_wordBuffer[76] = Sigma1(_wordBuffer[74]) + _wordBuffer[69] + Sigma0(_wordBuffer[61]) + _wordBuffer[60];
	_wordBuffer[77] = Sigma1(_wordBuffer[75]) + _wordBuffer[70] + Sigma0(_wordBuffer[62]) + _wordBuffer[61];
	_wordBuffer[78] = Sigma1(_wordBuffer[76]) + _wordBuffer[71] + Sigma0(_wordBuffer[63]) + _wordBuffer[62];
	_wordBuffer[79] = Sigma1(_wordBuffer[77]) + _wordBuffer[72] + Sigma0(_wordBuffer[64]) + _wordBuffer[63];

	// set up working variables
	ulong w0 = _H0;
	ulong w1 = _H1;
	ulong w2 = _H2;
	ulong w3 = _H3;
	ulong w4 = _H4;
	ulong w5 = _H5;
	ulong w6 = _H6;
	ulong w7 = _H7;
	unsigned int ctr = 0;

	// t = 8 * i
	w7 += Sum1(w4) + Ch(w4, w5, w6) + K64[ctr] + _wordBuffer[ctr];
	w3 += w7;
	w7 += Sum0(w0) + Maj(w0, w1, w2);
	// t = 8 * i + 1
	w6 += Sum1(w3) + Ch(w3, w4, w5) + K64[++ctr] + _wordBuffer[ctr];
	w2 += w6;
	w6 += Sum0(w7) + Maj(w7, w0, w1);
	// t = 8 * i + 2
	w5 += Sum1(w2) + Ch(w2, w3, w4) + K64[++ctr] + _wordBuffer[ctr];
	w1 += w5;
	w5 += Sum0(w6) + Maj(w6, w7, w0);
	// t = 8 * i + 3
	w4 += Sum1(w1) + Ch(w1, w2, w3) + K64[++ctr] + _wordBuffer[ctr];
	w0 += w4;
	w4 += Sum0(w5) + Maj(w5, w6, w7);
	// t = 8 * i + 4
	w3 += Sum1(w0) + Ch(w0, w1, w2) + K64[++ctr] + _wordBuffer[ctr];
	w7 += w3;
	w3 += Sum0(w4) + Maj(w4, w5, w6);
	// t = 8 * i + 5
	w2 += Sum1(w7) + Ch(w7, w0, w1) + K64[++ctr] + _wordBuffer[ctr];
	w6 += w2;
	w2 += Sum0(w3) + Maj(w3, w4, w5);
	// t = 8 * i + 6
	w1 += Sum1(w6) + Ch(w6, w7, w0) + K64[++ctr] + _wordBuffer[ctr];
	w5 += w1;
	w1 += Sum0(w2) + Maj(w2, w3, w4);
	// t = 8 * i + 7
	w0 += Sum1(w5) + Ch(w5, w6, w7) + K64[++ctr] + _wordBuffer[ctr];
	w4 += w0;
	w0 += Sum0(w1) + Maj(w1, w2, w3);

	w7 += Sum1(w4) + Ch(w4, w5, w6) + K64[++ctr] + _wordBuffer[ctr];
	w3 += w7;
	w7 += Sum0(w0) + Maj(w0, w1, w2);
	w6 += Sum1(w3) + Ch(w3, w4, w5) + K64[++ctr] + _wordBuffer[ctr];
	w2 += w6;
	w6 += Sum0(w7) + Maj(w7, w0, w1);
	w5 += Sum1(w2) + Ch(w2, w3, w4) + K64[++ctr] + _wordBuffer[ctr];
	w1 += w5;
	w5 += Sum0(w6) + Maj(w6, w7, w0);
	w4 += Sum1(w1) + Ch(w1, w2, w3) + K64[++ctr] + _wordBuffer[ctr];
	w0 += w4;
	w4 += Sum0(w5) + Maj(w5, w6, w7);
	w3 += Sum1(w0) + Ch(w0, w1, w2) + K64[++ctr] + _wordBuffer[ctr];
	w7 += w3;
	w3 += Sum0(w4) + Maj(w4, w5, w6);
	w2 += Sum1(w7) + Ch(w7, w0, w1) + K64[++ctr] + _wordBuffer[ctr];
	w6 += w2;
	w2 += Sum0(w3) + Maj(w3, w4, w5);
	w1 += Sum1(w6) + Ch(w6, w7, w0) + K64[++ctr] + _wordBuffer[ctr];
	w5 += w1;
	w1 += Sum0(w2) + Maj(w2, w3, w4);
	w0 += Sum1(w5) + Ch(w5, w6, w7) + K64[++ctr] + _wordBuffer[ctr];
	w4 += w0;
	w0 += Sum0(w1) + Maj(w1, w2, w3);

	w7 += Sum1(w4) + Ch(w4, w5, w6) + K64[++ctr] + _wordBuffer[ctr];
	w3 += w7;
	w7 += Sum0(w0) + Maj(w0, w1, w2);
	w6 += Sum1(w3) + Ch(w3, w4, w5) + K64[++ctr] + _wordBuffer[ctr];
	w2 += w6;
	w6 += Sum0(w7) + Maj(w7, w0, w1);
	w5 += Sum1(w2) + Ch(w2, w3, w4) + K64[++ctr] + _wordBuffer[ctr];
	w1 += w5;
	w5 += Sum0(w6) + Maj(w6, w7, w0);
	w4 += Sum1(w1) + Ch(w1, w2, w3) + K64[++ctr] + _wordBuffer[ctr];
	w0 += w4;
	w4 += Sum0(w5) + Maj(w5, w6, w7);
	w3 += Sum1(w0) + Ch(w0, w1, w2) + K64[++ctr] + _wordBuffer[ctr];
	w7 += w3;
	w3 += Sum0(w4) + Maj(w4, w5, w6);
	w2 += Sum1(w7) + Ch(w7, w0, w1) + K64[++ctr] + _wordBuffer[ctr];
	w6 += w2;
	w2 += Sum0(w3) + Maj(w3, w4, w5);
	w1 += Sum1(w6) + Ch(w6, w7, w0) + K64[++ctr] + _wordBuffer[ctr];
	w5 += w1;
	w1 += Sum0(w2) + Maj(w2, w3, w4);
	w0 += Sum1(w5) + Ch(w5, w6, w7) + K64[++ctr] + _wordBuffer[ctr];
	w4 += w0;
	w0 += Sum0(w1) + Maj(w1, w2, w3);

	w7 += Sum1(w4) + Ch(w4, w5, w6) + K64[++ctr] + _wordBuffer[ctr];
	w3 += w7;
	w7 += Sum0(w0) + Maj(w0, w1, w2);
	w6 += Sum1(w3) + Ch(w3, w4, w5) + K64[++ctr] + _wordBuffer[ctr];
	w2 += w6;
	w6 += Sum0(w7) + Maj(w7, w0, w1);
	w5 += Sum1(w2) + Ch(w2, w3, w4) + K64[++ctr] + _wordBuffer[ctr];
	w1 += w5;
	w5 += Sum0(w6) + Maj(w6, w7, w0);
	w4 += Sum1(w1) + Ch(w1, w2, w3) + K64[++ctr] + _wordBuffer[ctr];
	w0 += w4;
	w4 += Sum0(w5) + Maj(w5, w6, w7);
	w3 += Sum1(w0) + Ch(w0, w1, w2) + K64[++ctr] + _wordBuffer[ctr];
	w7 += w3;
	w3 += Sum0(w4) + Maj(w4, w5, w6);
	w2 += Sum1(w7) + Ch(w7, w0, w1) + K64[++ctr] + _wordBuffer[ctr];
	w6 += w2;
	w2 += Sum0(w3) + Maj(w3, w4, w5);
	w1 += Sum1(w6) + Ch(w6, w7, w0) + K64[++ctr] + _wordBuffer[ctr];
	w5 += w1;
	w1 += Sum0(w2) + Maj(w2, w3, w4);
	w0 += Sum1(w5) + Ch(w5, w6, w7) + K64[++ctr] + _wordBuffer[ctr];
	w4 += w0;
	w0 += Sum0(w1) + Maj(w1, w2, w3);

	w7 += Sum1(w4) + Ch(w4, w5, w6) + K64[++ctr] + _wordBuffer[ctr];
	w3 += w7;
	w7 += Sum0(w0) + Maj(w0, w1, w2);
	w6 += Sum1(w3) + Ch(w3, w4, w5) + K64[++ctr] + _wordBuffer[ctr];
	w2 += w6;
	w6 += Sum0(w7) + Maj(w7, w0, w1);
	w5 += Sum1(w2) + Ch(w2, w3, w4) + K64[++ctr] + _wordBuffer[ctr];
	w1 += w5;
	w5 += Sum0(w6) + Maj(w6, w7, w0);
	w4 += Sum1(w1) + Ch(w1, w2, w3) + K64[++ctr] + _wordBuffer[ctr];
	w0 += w4;
	w4 += Sum0(w5) + Maj(w5, w6, w7);
	w3 += Sum1(w0) + Ch(w0, w1, w2) + K64[++ctr] + _wordBuffer[ctr];
	w7 += w3;
	w3 += Sum0(w4) + Maj(w4, w5, w6);
	w2 += Sum1(w7) + Ch(w7, w0, w1) + K64[++ctr] + _wordBuffer[ctr];
	w6 += w2;
	w2 += Sum0(w3) + Maj(w3, w4, w5);
	w1 += Sum1(w6) + Ch(w6, w7, w0) + K64[++ctr] + _wordBuffer[ctr];
	w5 += w1;
	w1 += Sum0(w2) + Maj(w2, w3, w4);
	w0 += Sum1(w5) + Ch(w5, w6, w7) + K64[++ctr] + _wordBuffer[ctr];
	w4 += w0;
	w0 += Sum0(w1) + Maj(w1, w2, w3);

	w7 += Sum1(w4) + Ch(w4, w5, w6) + K64[++ctr] + _wordBuffer[ctr];
	w3 += w7;
	w7 += Sum0(w0) + Maj(w0, w1, w2);
	w6 += Sum1(w3) + Ch(w3, w4, w5) + K64[++ctr] + _wordBuffer[ctr];
	w2 += w6;
	w6 += Sum0(w7) + Maj(w7, w0, w1);
	w5 += Sum1(w2) + Ch(w2, w3, w4) + K64[++ctr] + _wordBuffer[ctr];
	w1 += w5;
	w5 += Sum0(w6) + Maj(w6, w7, w0);
	w4 += Sum1(w1) + Ch(w1, w2, w3) + K64[++ctr] + _wordBuffer[ctr];
	w0 += w4;
	w4 += Sum0(w5) + Maj(w5, w6, w7);
	w3 += Sum1(w0) + Ch(w0, w1, w2) + K64[++ctr] + _wordBuffer[ctr];
	w7 += w3;
	w3 += Sum0(w4) + Maj(w4, w5, w6);
	w2 += Sum1(w7) + Ch(w7, w0, w1) + K64[++ctr] + _wordBuffer[ctr];
	w6 += w2;
	w2 += Sum0(w3) + Maj(w3, w4, w5);
	w1 += Sum1(w6) + Ch(w6, w7, w0) + K64[++ctr] + _wordBuffer[ctr];
	w5 += w1;
	w1 += Sum0(w2) + Maj(w2, w3, w4);
	w0 += Sum1(w5) + Ch(w5, w6, w7) + K64[++ctr] + _wordBuffer[ctr];
	w4 += w0;
	w0 += Sum0(w1) + Maj(w1, w2, w3);

	w7 += Sum1(w4) + Ch(w4, w5, w6) + K64[++ctr] + _wordBuffer[ctr];
	w3 += w7;
	w7 += Sum0(w0) + Maj(w0, w1, w2);
	w6 += Sum1(w3) + Ch(w3, w4, w5) + K64[++ctr] + _wordBuffer[ctr];
	w2 += w6;
	w6 += Sum0(w7) + Maj(w7, w0, w1);
	w5 += Sum1(w2) + Ch(w2, w3, w4) + K64[++ctr] + _wordBuffer[ctr];
	w1 += w5;
	w5 += Sum0(w6) + Maj(w6, w7, w0);
	w4 += Sum1(w1) + Ch(w1, w2, w3) + K64[++ctr] + _wordBuffer[ctr];
	w0 += w4;
	w4 += Sum0(w5) + Maj(w5, w6, w7);
	w3 += Sum1(w0) + Ch(w0, w1, w2) + K64[++ctr] + _wordBuffer[ctr];
	w7 += w3;
	w3 += Sum0(w4) + Maj(w4, w5, w6);
	w2 += Sum1(w7) + Ch(w7, w0, w1) + K64[++ctr] + _wordBuffer[ctr];
	w6 += w2;
	w2 += Sum0(w3) + Maj(w3, w4, w5);
	w1 += Sum1(w6) + Ch(w6, w7, w0) + K64[++ctr] + _wordBuffer[ctr];
	w5 += w1;
	w1 += Sum0(w2) + Maj(w2, w3, w4);
	w0 += Sum1(w5) + Ch(w5, w6, w7) + K64[++ctr] + _wordBuffer[ctr];
	w4 += w0;
	w0 += Sum0(w1) + Maj(w1, w2, w3);

	w7 += Sum1(w4) + Ch(w4, w5, w6) + K64[++ctr] + _wordBuffer[ctr];
	w3 += w7;
	w7 += Sum0(w0) + Maj(w0, w1, w2);
	w6 += Sum1(w3) + Ch(w3, w4, w5) + K64[++ctr] + _wordBuffer[ctr];
	w2 += w6;
	w6 += Sum0(w7) + Maj(w7, w0, w1);
	w5 += Sum1(w2) + Ch(w2, w3, w4) + K64[++ctr] + _wordBuffer[ctr];
	w1 += w5;
	w5 += Sum0(w6) + Maj(w6, w7, w0);
	w4 += Sum1(w1) + Ch(w1, w2, w3) + K64[++ctr] + _wordBuffer[ctr];
	w0 += w4;
	w4 += Sum0(w5) + Maj(w5, w6, w7);
	w3 += Sum1(w0) + Ch(w0, w1, w2) + K64[++ctr] + _wordBuffer[ctr];
	w7 += w3;
	w3 += Sum0(w4) + Maj(w4, w5, w6);
	w2 += Sum1(w7) + Ch(w7, w0, w1) + K64[++ctr] + _wordBuffer[ctr];
	w6 += w2;
	w2 += Sum0(w3) + Maj(w3, w4, w5);
	w1 += Sum1(w6) + Ch(w6, w7, w0) + K64[++ctr] + _wordBuffer[ctr];
	w5 += w1;
	w1 += Sum0(w2) + Maj(w2, w3, w4);
	w0 += Sum1(w5) + Ch(w5, w6, w7) + K64[++ctr] + _wordBuffer[ctr];
	w4 += w0;
	w0 += Sum0(w1) + Maj(w1, w2, w3);

	w7 += Sum1(w4) + Ch(w4, w5, w6) + K64[++ctr] + _wordBuffer[ctr];
	w3 += w7;
	w7 += Sum0(w0) + Maj(w0, w1, w2);
	w6 += Sum1(w3) + Ch(w3, w4, w5) + K64[++ctr] + _wordBuffer[ctr];
	w2 += w6;
	w6 += Sum0(w7) + Maj(w7, w0, w1);
	w5 += Sum1(w2) + Ch(w2, w3, w4) + K64[++ctr] + _wordBuffer[ctr];
	w1 += w5;
	w5 += Sum0(w6) + Maj(w6, w7, w0);
	w4 += Sum1(w1) + Ch(w1, w2, w3) + K64[++ctr] + _wordBuffer[ctr];
	w0 += w4;
	w4 += Sum0(w5) + Maj(w5, w6, w7);
	w3 += Sum1(w0) + Ch(w0, w1, w2) + K64[++ctr] + _wordBuffer[ctr];
	w7 += w3;
	w3 += Sum0(w4) + Maj(w4, w5, w6);
	w2 += Sum1(w7) + Ch(w7, w0, w1) + K64[++ctr] + _wordBuffer[ctr];
	w6 += w2;
	w2 += Sum0(w3) + Maj(w3, w4, w5);
	w1 += Sum1(w6) + Ch(w6, w7, w0) + K64[++ctr] + _wordBuffer[ctr];
	w5 += w1;
	w1 += Sum0(w2) + Maj(w2, w3, w4);
	w0 += Sum1(w5) + Ch(w5, w6, w7) + K64[++ctr] + _wordBuffer[ctr];
	w4 += w0;
	w0 += Sum0(w1) + Maj(w1, w2, w3);

	w7 += Sum1(w4) + Ch(w4, w5, w6) + K64[++ctr] + _wordBuffer[ctr];
	w3 += w7;
	w7 += Sum0(w0) + Maj(w0, w1, w2);
	w6 += Sum1(w3) + Ch(w3, w4, w5) + K64[++ctr] + _wordBuffer[ctr];
	w2 += w6;
	w6 += Sum0(w7) + Maj(w7, w0, w1);
	w5 += Sum1(w2) + Ch(w2, w3, w4) + K64[++ctr] + _wordBuffer[ctr];
	w1 += w5;
	w5 += Sum0(w6) + Maj(w6, w7, w0);
	w4 += Sum1(w1) + Ch(w1, w2, w3) + K64[++ctr] + _wordBuffer[ctr];
	w0 += w4;
	w4 += Sum0(w5) + Maj(w5, w6, w7);
	w3 += Sum1(w0) + Ch(w0, w1, w2) + K64[++ctr] + _wordBuffer[ctr];
	w7 += w3;
	w3 += Sum0(w4) + Maj(w4, w5, w6);
	w2 += Sum1(w7) + Ch(w7, w0, w1) + K64[++ctr] + _wordBuffer[ctr];
	w6 += w2;
	w2 += Sum0(w3) + Maj(w3, w4, w5);
	w1 += Sum1(w6) + Ch(w6, w7, w0) + K64[++ctr] + _wordBuffer[ctr];
	w5 += w1;
	w1 += Sum0(w2) + Maj(w2, w3, w4);
	w0 += Sum1(w5) + Ch(w5, w6, w7) + K64[++ctr] + _wordBuffer[ctr];
	w4 += w0;
	w0 += Sum0(w1) + Maj(w1, w2, w3);

	_H0 += w0;
	_H1 += w1;
	_H2 += w2;
	_H3 += w3;
	_H4 += w4;
	_H5 += w5;
	_H6 += w6;
	_H7 += w7;

	_wordOffset = 0;
	std::fill(_wordBuffer.begin(), _wordBuffer.end(), 0);
}

void SHA512::ProcessLength(ulong LowWord, ulong HiWord)
{
	if (_wordOffset > 14)
		ProcessBlock();

	_wordBuffer[14] = (ulong)HiWord;
	_wordBuffer[15] = (ulong)LowWord;
}

void SHA512::ProcessWord(const std::vector<byte> &Input, unsigned int InOffset)
{
	_wordBuffer[_wordOffset] = CEX::Utility::IntUtils::BytesToBe64(Input, InOffset);

	if (++_wordOffset == 16)
		ProcessBlock();
}

NAMESPACE_DIGESTEND