#include "SHA256.h"
#include "IntUtils.h"

NAMESPACE_DIGEST

using CEX::Utility::IntUtils;

constexpr uint K32[] =
{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

void SHA256::BlockUpdate(const std::vector<byte> &Input, unsigned int InOffset, unsigned int Length)
{
	if ((InOffset + Length) > Input.size())
		throw CryptoDigestException("SHA256:BlockUpdate", "The Input buffer is too short!");

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
		_byteCount += _prcBuffer.size();
	}

	// load in the remainder
	while (Length != 0)
	{
		Update(Input[InOffset]);
		InOffset++;
		Length--;
	}
}

void SHA256::ComputeHash(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Output.resize(DIGEST_SIZE);
	BlockUpdate(Input, 0, Input.size());
	DoFinal(Output, 0);
}

void SHA256::Destroy()
{
	if (!_isDestroyed)
	{
		_isDestroyed = true;
		_bufferOffset = 0;
		_byteCount = 0;
		_H0 = 0, _H1 = 0, _H2 = 0, _H3 = 0, _H4 = 0, _H5 = 0, _H6 = 0, _H7 = 0;
		_wordOffset = 0;

		IntUtils::ClearVector(_prcBuffer);
		IntUtils::ClearVector(_wordBuffer);
	}
}

unsigned int SHA256::DoFinal(std::vector<byte> &Output, const unsigned int OutOffset)
{
	if (Output.size() - OutOffset < DigestSize())
		throw CryptoDigestException("SHA256:DoFinal", "The Output buffer is too short!");

	Finish();
	IntUtils::Be32ToBytes(_H0, Output, OutOffset);
	IntUtils::Be32ToBytes(_H1, Output, OutOffset + 4);
	IntUtils::Be32ToBytes(_H2, Output, OutOffset + 8);
	IntUtils::Be32ToBytes(_H3, Output, OutOffset + 12);
	IntUtils::Be32ToBytes(_H4, Output, OutOffset + 16);
	IntUtils::Be32ToBytes(_H5, Output, OutOffset + 20);
	IntUtils::Be32ToBytes(_H6, Output, OutOffset + 24);
	IntUtils::Be32ToBytes(_H7, Output, OutOffset + 28);

	Reset();

	return DIGEST_SIZE;
}

void SHA256::Reset()
{
	_byteCount = 0;
	_bufferOffset = 0;
	memset(&_prcBuffer[0], (byte)0, _prcBuffer.size());

	Initialize();
}

void SHA256::Update(byte Input)
{
	_prcBuffer[_bufferOffset++] = Input;

	if (_bufferOffset == _prcBuffer.size())
	{
		ProcessWord(_prcBuffer, 0);
		_bufferOffset = 0;
	}

	_byteCount++;
}

// *** Protected Methods *** //

void SHA256::Finish()
{
	int64_t bitLength = (_byteCount << 3);

	Update((byte)128);

	while (_bufferOffset != 0)
		Update((byte)0);

	ProcessLength(bitLength);
	ProcessBlock();
}

void SHA256::Initialize()
{
	// The first 32 bits of the fractional parts of the square roots of the first eight prime numbers
	_H0 = 0x6a09e667;
	_H1 = 0xbb67ae85;
	_H2 = 0x3c6ef372;
	_H3 = 0xa54ff53a;
	_H4 = 0x510e527f;
	_H5 = 0x9b05688c;
	_H6 = 0x1f83d9ab;
	_H7 = 0x5be0cd19;
}

void SHA256::ProcessBlock()
{
	int32_t ctr = 0;
	uint w0 = _H0;
	uint w1 = _H1;
	uint w2 = _H2;
	uint w3 = _H3;
	uint w4 = _H4;
	uint w5 = _H5;
	uint w6 = _H6;
	uint w7 = _H7;

	// expand 16 word block into 64 word blocks
	_wordBuffer[16] = Theta1(_wordBuffer[14]) + _wordBuffer[9] + Theta0(_wordBuffer[1]) + _wordBuffer[0];
	_wordBuffer[17] = Theta1(_wordBuffer[15]) + _wordBuffer[10] + Theta0(_wordBuffer[2]) + _wordBuffer[1];
	_wordBuffer[18] = Theta1(_wordBuffer[16]) + _wordBuffer[11] + Theta0(_wordBuffer[3]) + _wordBuffer[2];
	_wordBuffer[19] = Theta1(_wordBuffer[17]) + _wordBuffer[12] + Theta0(_wordBuffer[4]) + _wordBuffer[3];
	_wordBuffer[20] = Theta1(_wordBuffer[18]) + _wordBuffer[13] + Theta0(_wordBuffer[5]) + _wordBuffer[4];
	_wordBuffer[21] = Theta1(_wordBuffer[19]) + _wordBuffer[14] + Theta0(_wordBuffer[6]) + _wordBuffer[5];
	_wordBuffer[22] = Theta1(_wordBuffer[20]) + _wordBuffer[15] + Theta0(_wordBuffer[7]) + _wordBuffer[6];
	_wordBuffer[23] = Theta1(_wordBuffer[21]) + _wordBuffer[16] + Theta0(_wordBuffer[8]) + _wordBuffer[7];
	_wordBuffer[24] = Theta1(_wordBuffer[22]) + _wordBuffer[17] + Theta0(_wordBuffer[9]) + _wordBuffer[8];
	_wordBuffer[25] = Theta1(_wordBuffer[23]) + _wordBuffer[18] + Theta0(_wordBuffer[10]) + _wordBuffer[9];
	_wordBuffer[26] = Theta1(_wordBuffer[24]) + _wordBuffer[19] + Theta0(_wordBuffer[11]) + _wordBuffer[10];
	_wordBuffer[27] = Theta1(_wordBuffer[25]) + _wordBuffer[20] + Theta0(_wordBuffer[12]) + _wordBuffer[11];
	_wordBuffer[28] = Theta1(_wordBuffer[26]) + _wordBuffer[21] + Theta0(_wordBuffer[13]) + _wordBuffer[12];
	_wordBuffer[29] = Theta1(_wordBuffer[27]) + _wordBuffer[22] + Theta0(_wordBuffer[14]) + _wordBuffer[13];
	_wordBuffer[30] = Theta1(_wordBuffer[28]) + _wordBuffer[23] + Theta0(_wordBuffer[15]) + _wordBuffer[14];
	_wordBuffer[31] = Theta1(_wordBuffer[29]) + _wordBuffer[24] + Theta0(_wordBuffer[16]) + _wordBuffer[15];
	_wordBuffer[32] = Theta1(_wordBuffer[30]) + _wordBuffer[25] + Theta0(_wordBuffer[17]) + _wordBuffer[16];
	_wordBuffer[33] = Theta1(_wordBuffer[31]) + _wordBuffer[26] + Theta0(_wordBuffer[18]) + _wordBuffer[17];
	_wordBuffer[34] = Theta1(_wordBuffer[32]) + _wordBuffer[27] + Theta0(_wordBuffer[19]) + _wordBuffer[18];
	_wordBuffer[35] = Theta1(_wordBuffer[33]) + _wordBuffer[28] + Theta0(_wordBuffer[20]) + _wordBuffer[19];
	_wordBuffer[36] = Theta1(_wordBuffer[34]) + _wordBuffer[29] + Theta0(_wordBuffer[21]) + _wordBuffer[20];
	_wordBuffer[37] = Theta1(_wordBuffer[35]) + _wordBuffer[30] + Theta0(_wordBuffer[22]) + _wordBuffer[21];
	_wordBuffer[38] = Theta1(_wordBuffer[36]) + _wordBuffer[31] + Theta0(_wordBuffer[23]) + _wordBuffer[22];
	_wordBuffer[39] = Theta1(_wordBuffer[37]) + _wordBuffer[32] + Theta0(_wordBuffer[24]) + _wordBuffer[23];
	_wordBuffer[40] = Theta1(_wordBuffer[38]) + _wordBuffer[33] + Theta0(_wordBuffer[25]) + _wordBuffer[24];
	_wordBuffer[41] = Theta1(_wordBuffer[39]) + _wordBuffer[34] + Theta0(_wordBuffer[26]) + _wordBuffer[25];
	_wordBuffer[42] = Theta1(_wordBuffer[40]) + _wordBuffer[35] + Theta0(_wordBuffer[27]) + _wordBuffer[26];
	_wordBuffer[43] = Theta1(_wordBuffer[41]) + _wordBuffer[36] + Theta0(_wordBuffer[28]) + _wordBuffer[27];
	_wordBuffer[44] = Theta1(_wordBuffer[42]) + _wordBuffer[37] + Theta0(_wordBuffer[29]) + _wordBuffer[28];
	_wordBuffer[45] = Theta1(_wordBuffer[43]) + _wordBuffer[38] + Theta0(_wordBuffer[30]) + _wordBuffer[29];
	_wordBuffer[46] = Theta1(_wordBuffer[44]) + _wordBuffer[39] + Theta0(_wordBuffer[31]) + _wordBuffer[30];
	_wordBuffer[47] = Theta1(_wordBuffer[45]) + _wordBuffer[40] + Theta0(_wordBuffer[32]) + _wordBuffer[31];
	_wordBuffer[48] = Theta1(_wordBuffer[46]) + _wordBuffer[41] + Theta0(_wordBuffer[33]) + _wordBuffer[32];
	_wordBuffer[49] = Theta1(_wordBuffer[47]) + _wordBuffer[42] + Theta0(_wordBuffer[34]) + _wordBuffer[33];
	_wordBuffer[50] = Theta1(_wordBuffer[48]) + _wordBuffer[43] + Theta0(_wordBuffer[35]) + _wordBuffer[34];
	_wordBuffer[51] = Theta1(_wordBuffer[49]) + _wordBuffer[44] + Theta0(_wordBuffer[36]) + _wordBuffer[35];
	_wordBuffer[52] = Theta1(_wordBuffer[50]) + _wordBuffer[45] + Theta0(_wordBuffer[37]) + _wordBuffer[36];
	_wordBuffer[53] = Theta1(_wordBuffer[51]) + _wordBuffer[46] + Theta0(_wordBuffer[38]) + _wordBuffer[37];
	_wordBuffer[54] = Theta1(_wordBuffer[52]) + _wordBuffer[47] + Theta0(_wordBuffer[39]) + _wordBuffer[38];
	_wordBuffer[55] = Theta1(_wordBuffer[53]) + _wordBuffer[48] + Theta0(_wordBuffer[40]) + _wordBuffer[39];
	_wordBuffer[56] = Theta1(_wordBuffer[54]) + _wordBuffer[49] + Theta0(_wordBuffer[41]) + _wordBuffer[40];
	_wordBuffer[57] = Theta1(_wordBuffer[55]) + _wordBuffer[50] + Theta0(_wordBuffer[42]) + _wordBuffer[41];
	_wordBuffer[58] = Theta1(_wordBuffer[56]) + _wordBuffer[51] + Theta0(_wordBuffer[43]) + _wordBuffer[42];
	_wordBuffer[59] = Theta1(_wordBuffer[57]) + _wordBuffer[52] + Theta0(_wordBuffer[44]) + _wordBuffer[43];
	_wordBuffer[60] = Theta1(_wordBuffer[58]) + _wordBuffer[53] + Theta0(_wordBuffer[45]) + _wordBuffer[44];
	_wordBuffer[61] = Theta1(_wordBuffer[59]) + _wordBuffer[54] + Theta0(_wordBuffer[46]) + _wordBuffer[45];
	_wordBuffer[62] = Theta1(_wordBuffer[60]) + _wordBuffer[55] + Theta0(_wordBuffer[47]) + _wordBuffer[46];
	_wordBuffer[63] = Theta1(_wordBuffer[61]) + _wordBuffer[56] + Theta0(_wordBuffer[48]) + _wordBuffer[47];

	// t = 8 * i
	w7 += Sum1Ch(w4, w5, w6) + K32[ctr] + _wordBuffer[ctr];
	w3 += w7;
	w7 += Sum0Maj(w0, w1, w2);
	// t = 8 * i + 1
	w6 += Sum1Ch(w3, w4, w5) + K32[++ctr] + _wordBuffer[ctr];
	w2 += w6;
	w6 += Sum0Maj(w7, w0, w1);
	// t = 8 * i + 2
	w5 += Sum1Ch(w2, w3, w4) + K32[++ctr] + _wordBuffer[ctr];
	w1 += w5;
	w5 += Sum0Maj(w6, w7, w0);
	// t = 8 * i + 3
	w4 += Sum1Ch(w1, w2, w3) + K32[++ctr] + _wordBuffer[ctr];
	w0 += w4;
	w4 += Sum0Maj(w5, w6, w7);
	// t = 8 * i + 4
	w3 += Sum1Ch(w0, w1, w2) + K32[++ctr] + _wordBuffer[ctr];
	w7 += w3;
	w3 += Sum0Maj(w4, w5, w6);
	// t = 8 * i + 5
	w2 += Sum1Ch(w7, w0, w1) + K32[++ctr] + _wordBuffer[ctr];
	w6 += w2;
	w2 += Sum0Maj(w3, w4, w5);
	// t = 8 * i + 6
	w1 += Sum1Ch(w6, w7, w0) + K32[++ctr] + _wordBuffer[ctr];
	w5 += w1;
	w1 += Sum0Maj(w2, w3, w4);
	// t = 8 * i + 7
	w0 += Sum1Ch(w5, w6, w7) + K32[++ctr] + _wordBuffer[ctr];
	w4 += w0;
	w0 += Sum0Maj(w1, w2, w3);

	w7 += Sum1Ch(w4, w5, w6) + K32[++ctr] + _wordBuffer[ctr];
	w3 += w7;
	w7 += Sum0Maj(w0, w1, w2);
	w6 += Sum1Ch(w3, w4, w5) + K32[++ctr] + _wordBuffer[ctr];
	w2 += w6;
	w6 += Sum0Maj(w7, w0, w1);
	w5 += Sum1Ch(w2, w3, w4) + K32[++ctr] + _wordBuffer[ctr];
	w1 += w5;
	w5 += Sum0Maj(w6, w7, w0);
	w4 += Sum1Ch(w1, w2, w3) + K32[++ctr] + _wordBuffer[ctr];
	w0 += w4;
	w4 += Sum0Maj(w5, w6, w7);
	w3 += Sum1Ch(w0, w1, w2) + K32[++ctr] + _wordBuffer[ctr];
	w7 += w3;
	w3 += Sum0Maj(w4, w5, w6);
	w2 += Sum1Ch(w7, w0, w1) + K32[++ctr] + _wordBuffer[ctr];
	w6 += w2;
	w2 += Sum0Maj(w3, w4, w5);
	w1 += Sum1Ch(w6, w7, w0) + K32[++ctr] + _wordBuffer[ctr];
	w5 += w1;
	w1 += Sum0Maj(w2, w3, w4);
	w0 += Sum1Ch(w5, w6, w7) + K32[++ctr] + _wordBuffer[ctr];
	w4 += w0;
	w0 += Sum0Maj(w1, w2, w3);

	w7 += Sum1Ch(w4, w5, w6) + K32[++ctr] + _wordBuffer[ctr];
	w3 += w7;
	w7 += Sum0Maj(w0, w1, w2);
	w6 += Sum1Ch(w3, w4, w5) + K32[++ctr] + _wordBuffer[ctr];
	w2 += w6;
	w6 += Sum0Maj(w7, w0, w1);
	w5 += Sum1Ch(w2, w3, w4) + K32[++ctr] + _wordBuffer[ctr];
	w1 += w5;
	w5 += Sum0Maj(w6, w7, w0);
	w4 += Sum1Ch(w1, w2, w3) + K32[++ctr] + _wordBuffer[ctr];
	w0 += w4;
	w4 += Sum0Maj(w5, w6, w7);
	w3 += Sum1Ch(w0, w1, w2) + K32[++ctr] + _wordBuffer[ctr];
	w7 += w3;
	w3 += Sum0Maj(w4, w5, w6);
	w2 += Sum1Ch(w7, w0, w1) + K32[++ctr] + _wordBuffer[ctr];
	w6 += w2;
	w2 += Sum0Maj(w3, w4, w5);
	w1 += Sum1Ch(w6, w7, w0) + K32[++ctr] + _wordBuffer[ctr];
	w5 += w1;
	w1 += Sum0Maj(w2, w3, w4);
	w0 += Sum1Ch(w5, w6, w7) + K32[++ctr] + _wordBuffer[ctr];
	w4 += w0;
	w0 += Sum0Maj(w1, w2, w3);

	w7 += Sum1Ch(w4, w5, w6) + K32[++ctr] + _wordBuffer[ctr];
	w3 += w7;
	w7 += Sum0Maj(w0, w1, w2);
	w6 += Sum1Ch(w3, w4, w5) + K32[++ctr] + _wordBuffer[ctr];
	w2 += w6;
	w6 += Sum0Maj(w7, w0, w1);
	w5 += Sum1Ch(w2, w3, w4) + K32[++ctr] + _wordBuffer[ctr];
	w1 += w5;
	w5 += Sum0Maj(w6, w7, w0);
	w4 += Sum1Ch(w1, w2, w3) + K32[++ctr] + _wordBuffer[ctr];
	w0 += w4;
	w4 += Sum0Maj(w5, w6, w7);
	w3 += Sum1Ch(w0, w1, w2) + K32[++ctr] + _wordBuffer[ctr];
	w7 += w3;
	w3 += Sum0Maj(w4, w5, w6);
	w2 += Sum1Ch(w7, w0, w1) + K32[++ctr] + _wordBuffer[ctr];
	w6 += w2;
	w2 += Sum0Maj(w3, w4, w5);
	w1 += Sum1Ch(w6, w7, w0) + K32[++ctr] + _wordBuffer[ctr];
	w5 += w1;
	w1 += Sum0Maj(w2, w3, w4);
	w0 += Sum1Ch(w5, w6, w7) + K32[++ctr] + _wordBuffer[ctr];
	w4 += w0;
	w0 += Sum0Maj(w1, w2, w3);

	w7 += Sum1Ch(w4, w5, w6) + K32[++ctr] + _wordBuffer[ctr];
	w3 += w7;
	w7 += Sum0Maj(w0, w1, w2);
	w6 += Sum1Ch(w3, w4, w5) + K32[++ctr] + _wordBuffer[ctr];
	w2 += w6;
	w6 += Sum0Maj(w7, w0, w1);
	w5 += Sum1Ch(w2, w3, w4) + K32[++ctr] + _wordBuffer[ctr];
	w1 += w5;
	w5 += Sum0Maj(w6, w7, w0);
	w4 += Sum1Ch(w1, w2, w3) + K32[++ctr] + _wordBuffer[ctr];
	w0 += w4;
	w4 += Sum0Maj(w5, w6, w7);
	w3 += Sum1Ch(w0, w1, w2) + K32[++ctr] + _wordBuffer[ctr];
	w7 += w3;
	w3 += Sum0Maj(w4, w5, w6);
	w2 += Sum1Ch(w7, w0, w1) + K32[++ctr] + _wordBuffer[ctr];
	w6 += w2;
	w2 += Sum0Maj(w3, w4, w5);
	w1 += Sum1Ch(w6, w7, w0) + K32[++ctr] + _wordBuffer[ctr];
	w5 += w1;
	w1 += Sum0Maj(w2, w3, w4);
	w0 += Sum1Ch(w5, w6, w7) + K32[++ctr] + _wordBuffer[ctr];
	w4 += w0;
	w0 += Sum0Maj(w1, w2, w3);

	w7 += Sum1Ch(w4, w5, w6) + K32[++ctr] + _wordBuffer[ctr];
	w3 += w7;
	w7 += Sum0Maj(w0, w1, w2);
	w6 += Sum1Ch(w3, w4, w5) + K32[++ctr] + _wordBuffer[ctr];
	w2 += w6;
	w6 += Sum0Maj(w7, w0, w1);
	w5 += Sum1Ch(w2, w3, w4) + K32[++ctr] + _wordBuffer[ctr];
	w1 += w5;
	w5 += Sum0Maj(w6, w7, w0);
	w4 += Sum1Ch(w1, w2, w3) + K32[++ctr] + _wordBuffer[ctr];
	w0 += w4;
	w4 += Sum0Maj(w5, w6, w7);
	w3 += Sum1Ch(w0, w1, w2) + K32[++ctr] + _wordBuffer[ctr];
	w7 += w3;
	w3 += Sum0Maj(w4, w5, w6);
	w2 += Sum1Ch(w7, w0, w1) + K32[++ctr] + _wordBuffer[ctr];
	w6 += w2;
	w2 += Sum0Maj(w3, w4, w5);
	w1 += Sum1Ch(w6, w7, w0) + K32[++ctr] + _wordBuffer[ctr];
	w5 += w1;
	w1 += Sum0Maj(w2, w3, w4);
	w0 += Sum1Ch(w5, w6, w7) + K32[++ctr] + _wordBuffer[ctr];
	w4 += w0;
	w0 += Sum0Maj(w1, w2, w3);

	w7 += Sum1Ch(w4, w5, w6) + K32[++ctr] + _wordBuffer[ctr];
	w3 += w7;
	w7 += Sum0Maj(w0, w1, w2);
	w6 += Sum1Ch(w3, w4, w5) + K32[++ctr] + _wordBuffer[ctr];
	w2 += w6;
	w6 += Sum0Maj(w7, w0, w1);
	w5 += Sum1Ch(w2, w3, w4) + K32[++ctr] + _wordBuffer[ctr];
	w1 += w5;
	w5 += Sum0Maj(w6, w7, w0);
	w4 += Sum1Ch(w1, w2, w3) + K32[++ctr] + _wordBuffer[ctr];
	w0 += w4;
	w4 += Sum0Maj(w5, w6, w7);
	w3 += Sum1Ch(w0, w1, w2) + K32[++ctr] + _wordBuffer[ctr];
	w7 += w3;
	w3 += Sum0Maj(w4, w5, w6);
	w2 += Sum1Ch(w7, w0, w1) + K32[++ctr] + _wordBuffer[ctr];
	w6 += w2;
	w2 += Sum0Maj(w3, w4, w5);
	w1 += Sum1Ch(w6, w7, w0) + K32[++ctr] + _wordBuffer[ctr];
	w5 += w1;
	w1 += Sum0Maj(w2, w3, w4);
	w0 += Sum1Ch(w5, w6, w7) + K32[++ctr] + _wordBuffer[ctr];
	w4 += w0;
	w0 += Sum0Maj(w1, w2, w3);

	w7 += Sum1Ch(w4, w5, w6) + K32[++ctr] + _wordBuffer[ctr];
	w3 += w7;
	w7 += Sum0Maj(w0, w1, w2);
	w6 += Sum1Ch(w3, w4, w5) + K32[++ctr] + _wordBuffer[ctr];
	w2 += w6;
	w6 += Sum0Maj(w7, w0, w1);
	w5 += Sum1Ch(w2, w3, w4) + K32[++ctr] + _wordBuffer[ctr];
	w1 += w5;
	w5 += Sum0Maj(w6, w7, w0);
	w4 += Sum1Ch(w1, w2, w3) + K32[++ctr] + _wordBuffer[ctr];
	w0 += w4;
	w4 += Sum0Maj(w5, w6, w7);
	w3 += Sum1Ch(w0, w1, w2) + K32[++ctr] + _wordBuffer[ctr];
	w7 += w3;
	w3 += Sum0Maj(w4, w5, w6);
	w2 += Sum1Ch(w7, w0, w1) + K32[++ctr] + _wordBuffer[ctr];
	w6 += w2;
	w2 += Sum0Maj(w3, w4, w5);
	w1 += Sum1Ch(w6, w7, w0) + K32[++ctr] + _wordBuffer[ctr];
	w5 += w1;
	w1 += Sum0Maj(w2, w3, w4);
	w0 += Sum1Ch(w5, w6, w7) + K32[++ctr] + _wordBuffer[ctr];
	w4 += w0;
	w0 += Sum0Maj(w1, w2, w3);

	_H0 += w0;
	_H1 += w1;
	_H2 += w2;
	_H3 += w3;
	_H4 += w4;
	_H5 += w5;
	_H6 += w6;
	_H7 += w7;

	// reset the offset and clear the word buffer
	_wordOffset = 0;
	std::fill(_wordBuffer.begin(), _wordBuffer.end(), 0);
}

void SHA256::ProcessLength(ulong BitLength)
{
	if (_wordOffset > 14)
		ProcessBlock();

	_wordBuffer[14] = (uint)((uint64_t)BitLength >> 32);
	_wordBuffer[15] = (uint)((uint64_t)BitLength);
}

void SHA256::ProcessWord(const std::vector<byte> &Input, unsigned int Offset)
{
	_wordBuffer[_wordOffset] = IntUtils::BytesToBe32(Input, Offset);

	if (++_wordOffset == 16)
		ProcessBlock();
}

NAMESPACE_DIGESTEND