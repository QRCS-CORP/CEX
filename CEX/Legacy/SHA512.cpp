#include "SHA512.h"
#include "SHA.h"
#include "IntUtils.h"

NAMESPACE_DIGEST

using CEX::Utility::IntUtils;

void SHA512::BlockUpdate(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
#if defined(CPPEXCEPTIONS_ENABLED)
	if ((InOffset + Length) > Input.size())
		throw CryptoDigestException("SHA512:BlockUpdate", "The Input buffer is too short!");
#endif

	// fill the current word
	while ((m_bufferOffset != 0) && (Length > 0))
	{
		Update(Input[InOffset]);
		InOffset++;
		Length--;
	}

	// process whole words
	while (Length >= m_prcBuffer.size())
	{
		ProcessWord(Input, InOffset);
		InOffset += m_prcBuffer.size();
		Length -= m_prcBuffer.size();
		m_btCounter1 += m_prcBuffer.size();
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
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_btCounter1 = 0;
		m_btCounter2 = 0;
		m_bufferOffset = 0;
		H0 = 0, H1 = 0, H2 = 0, H3 = 0, H4 = 0, H5 = 0, H6 = 0, H7 = 0;
		m_wordOffset = 0;

		IntUtils::ClearVector(m_prcBuffer);
		IntUtils::ClearVector(m_wordBuffer);
	}
}

size_t SHA512::DoFinal(std::vector<byte> &Output, const size_t OutOffset)
{
#if defined(CPPEXCEPTIONS_ENABLED)
	if (Output.size() - OutOffset < DIGEST_SIZE)
		throw CryptoDigestException("SHA512:DoFinal", "The Output buffer is too short!");
#endif

	Finish();
	IntUtils::Be64ToBytes(H0, Output, OutOffset);
	IntUtils::Be64ToBytes(H1, Output, OutOffset + 8);
	IntUtils::Be64ToBytes(H2, Output, OutOffset + 16);
	IntUtils::Be64ToBytes(H3, Output, OutOffset + 24);
	IntUtils::Be64ToBytes(H4, Output, OutOffset + 32);
	IntUtils::Be64ToBytes(H5, Output, OutOffset + 40);
	IntUtils::Be64ToBytes(H6, Output, OutOffset + 48);
	IntUtils::Be64ToBytes(H7, Output, OutOffset + 56);

	Reset();

	return DIGEST_SIZE;
}

void SHA512::Reset()
{
	m_btCounter1 = 0;
	m_btCounter2 = 0;
	m_bufferOffset = 0;
	std::fill(m_prcBuffer.begin(), m_prcBuffer.end(), 0);
	std::fill(m_wordBuffer.begin(), m_wordBuffer.end(), 0);
	m_wordOffset = 0;

	Initialize();
}

void SHA512::Update(byte Input)
{
	m_prcBuffer[m_bufferOffset++] = Input;

	if (m_bufferOffset == m_prcBuffer.size())
	{
		ProcessWord(m_prcBuffer, 0);
		m_bufferOffset = 0;
	}

	m_btCounter1++;
}

//~~~Protected Methods~~~//

void SHA512::AdjustByteCounts()
{
	if (m_btCounter1 > 0x1fffffffffffffffL)
	{
		m_btCounter2 += (int64_t)((uint64_t)m_btCounter1 >> 61);
		m_btCounter1 &= 0x1fffffffffffffffL;
	}
}

void SHA512::Finish()
{
	AdjustByteCounts();

	ulong lowBitLen = m_btCounter1 << 3;
	ulong hiBitLen = m_btCounter2;

	// add the pad bytes
	Update((byte)128);

	while (m_bufferOffset != 0)
		Update((byte)0);

	ProcessLength(lowBitLen, hiBitLen);
	ProcessBlock();
}

void SHA512::Initialize()
{
	H0 = 0x6a09e667f3bcc908;
	H1 = 0xbb67ae8584caa73b;
	H2 = 0x3c6ef372fe94f82b;
	H3 = 0xa54ff53a5f1d36f1;
	H4 = 0x510e527fade682d1;
	H5 = 0x9b05688c2b3e6c1f;
	H6 = 0x1f83d9abfb41bd6b;
	H7 = 0x5be0cd19137e2179;
}

void SHA512::ProcessBlock()
{
	AdjustByteCounts();

	// expand 16 word block into 80 word blocks
	m_wordBuffer[16] = Sigma1(m_wordBuffer[14]) + m_wordBuffer[9] + Sigma0(m_wordBuffer[1]) + m_wordBuffer[0];
	m_wordBuffer[17] = Sigma1(m_wordBuffer[15]) + m_wordBuffer[10] + Sigma0(m_wordBuffer[2]) + m_wordBuffer[1];
	m_wordBuffer[18] = Sigma1(m_wordBuffer[16]) + m_wordBuffer[11] + Sigma0(m_wordBuffer[3]) + m_wordBuffer[2];
	m_wordBuffer[19] = Sigma1(m_wordBuffer[17]) + m_wordBuffer[12] + Sigma0(m_wordBuffer[4]) + m_wordBuffer[3];
	m_wordBuffer[20] = Sigma1(m_wordBuffer[18]) + m_wordBuffer[13] + Sigma0(m_wordBuffer[5]) + m_wordBuffer[4];
	m_wordBuffer[21] = Sigma1(m_wordBuffer[19]) + m_wordBuffer[14] + Sigma0(m_wordBuffer[6]) + m_wordBuffer[5];
	m_wordBuffer[22] = Sigma1(m_wordBuffer[20]) + m_wordBuffer[15] + Sigma0(m_wordBuffer[7]) + m_wordBuffer[6];
	m_wordBuffer[23] = Sigma1(m_wordBuffer[21]) + m_wordBuffer[16] + Sigma0(m_wordBuffer[8]) + m_wordBuffer[7];
	m_wordBuffer[24] = Sigma1(m_wordBuffer[22]) + m_wordBuffer[17] + Sigma0(m_wordBuffer[9]) + m_wordBuffer[8];
	m_wordBuffer[25] = Sigma1(m_wordBuffer[23]) + m_wordBuffer[18] + Sigma0(m_wordBuffer[10]) + m_wordBuffer[9];
	m_wordBuffer[26] = Sigma1(m_wordBuffer[24]) + m_wordBuffer[19] + Sigma0(m_wordBuffer[11]) + m_wordBuffer[10];
	m_wordBuffer[27] = Sigma1(m_wordBuffer[25]) + m_wordBuffer[20] + Sigma0(m_wordBuffer[12]) + m_wordBuffer[11];
	m_wordBuffer[28] = Sigma1(m_wordBuffer[26]) + m_wordBuffer[21] + Sigma0(m_wordBuffer[13]) + m_wordBuffer[12];
	m_wordBuffer[29] = Sigma1(m_wordBuffer[27]) + m_wordBuffer[22] + Sigma0(m_wordBuffer[14]) + m_wordBuffer[13];
	m_wordBuffer[30] = Sigma1(m_wordBuffer[28]) + m_wordBuffer[23] + Sigma0(m_wordBuffer[15]) + m_wordBuffer[14];
	m_wordBuffer[31] = Sigma1(m_wordBuffer[29]) + m_wordBuffer[24] + Sigma0(m_wordBuffer[16]) + m_wordBuffer[15];
	m_wordBuffer[32] = Sigma1(m_wordBuffer[30]) + m_wordBuffer[25] + Sigma0(m_wordBuffer[17]) + m_wordBuffer[16];
	m_wordBuffer[33] = Sigma1(m_wordBuffer[31]) + m_wordBuffer[26] + Sigma0(m_wordBuffer[18]) + m_wordBuffer[17];
	m_wordBuffer[34] = Sigma1(m_wordBuffer[32]) + m_wordBuffer[27] + Sigma0(m_wordBuffer[19]) + m_wordBuffer[18];
	m_wordBuffer[35] = Sigma1(m_wordBuffer[33]) + m_wordBuffer[28] + Sigma0(m_wordBuffer[20]) + m_wordBuffer[19];
	m_wordBuffer[36] = Sigma1(m_wordBuffer[34]) + m_wordBuffer[29] + Sigma0(m_wordBuffer[21]) + m_wordBuffer[20];
	m_wordBuffer[37] = Sigma1(m_wordBuffer[35]) + m_wordBuffer[30] + Sigma0(m_wordBuffer[22]) + m_wordBuffer[21];
	m_wordBuffer[38] = Sigma1(m_wordBuffer[36]) + m_wordBuffer[31] + Sigma0(m_wordBuffer[23]) + m_wordBuffer[22];
	m_wordBuffer[39] = Sigma1(m_wordBuffer[37]) + m_wordBuffer[32] + Sigma0(m_wordBuffer[24]) + m_wordBuffer[23];
	m_wordBuffer[40] = Sigma1(m_wordBuffer[38]) + m_wordBuffer[33] + Sigma0(m_wordBuffer[25]) + m_wordBuffer[24];
	m_wordBuffer[41] = Sigma1(m_wordBuffer[39]) + m_wordBuffer[34] + Sigma0(m_wordBuffer[26]) + m_wordBuffer[25];
	m_wordBuffer[42] = Sigma1(m_wordBuffer[40]) + m_wordBuffer[35] + Sigma0(m_wordBuffer[27]) + m_wordBuffer[26];
	m_wordBuffer[43] = Sigma1(m_wordBuffer[41]) + m_wordBuffer[36] + Sigma0(m_wordBuffer[28]) + m_wordBuffer[27];
	m_wordBuffer[44] = Sigma1(m_wordBuffer[42]) + m_wordBuffer[37] + Sigma0(m_wordBuffer[29]) + m_wordBuffer[28];
	m_wordBuffer[45] = Sigma1(m_wordBuffer[43]) + m_wordBuffer[38] + Sigma0(m_wordBuffer[30]) + m_wordBuffer[29];
	m_wordBuffer[46] = Sigma1(m_wordBuffer[44]) + m_wordBuffer[39] + Sigma0(m_wordBuffer[31]) + m_wordBuffer[30];
	m_wordBuffer[47] = Sigma1(m_wordBuffer[45]) + m_wordBuffer[40] + Sigma0(m_wordBuffer[32]) + m_wordBuffer[31];
	m_wordBuffer[48] = Sigma1(m_wordBuffer[46]) + m_wordBuffer[41] + Sigma0(m_wordBuffer[33]) + m_wordBuffer[32];
	m_wordBuffer[49] = Sigma1(m_wordBuffer[47]) + m_wordBuffer[42] + Sigma0(m_wordBuffer[34]) + m_wordBuffer[33];
	m_wordBuffer[50] = Sigma1(m_wordBuffer[48]) + m_wordBuffer[43] + Sigma0(m_wordBuffer[35]) + m_wordBuffer[34];
	m_wordBuffer[51] = Sigma1(m_wordBuffer[49]) + m_wordBuffer[44] + Sigma0(m_wordBuffer[36]) + m_wordBuffer[35];
	m_wordBuffer[52] = Sigma1(m_wordBuffer[50]) + m_wordBuffer[45] + Sigma0(m_wordBuffer[37]) + m_wordBuffer[36];
	m_wordBuffer[53] = Sigma1(m_wordBuffer[51]) + m_wordBuffer[46] + Sigma0(m_wordBuffer[38]) + m_wordBuffer[37];
	m_wordBuffer[54] = Sigma1(m_wordBuffer[52]) + m_wordBuffer[47] + Sigma0(m_wordBuffer[39]) + m_wordBuffer[38];
	m_wordBuffer[55] = Sigma1(m_wordBuffer[53]) + m_wordBuffer[48] + Sigma0(m_wordBuffer[40]) + m_wordBuffer[39];
	m_wordBuffer[56] = Sigma1(m_wordBuffer[54]) + m_wordBuffer[49] + Sigma0(m_wordBuffer[41]) + m_wordBuffer[40];
	m_wordBuffer[57] = Sigma1(m_wordBuffer[55]) + m_wordBuffer[50] + Sigma0(m_wordBuffer[42]) + m_wordBuffer[41];
	m_wordBuffer[58] = Sigma1(m_wordBuffer[56]) + m_wordBuffer[51] + Sigma0(m_wordBuffer[43]) + m_wordBuffer[42];
	m_wordBuffer[59] = Sigma1(m_wordBuffer[57]) + m_wordBuffer[52] + Sigma0(m_wordBuffer[44]) + m_wordBuffer[43];
	m_wordBuffer[60] = Sigma1(m_wordBuffer[58]) + m_wordBuffer[53] + Sigma0(m_wordBuffer[45]) + m_wordBuffer[44];
	m_wordBuffer[61] = Sigma1(m_wordBuffer[59]) + m_wordBuffer[54] + Sigma0(m_wordBuffer[46]) + m_wordBuffer[45];
	m_wordBuffer[62] = Sigma1(m_wordBuffer[60]) + m_wordBuffer[55] + Sigma0(m_wordBuffer[47]) + m_wordBuffer[46];
	m_wordBuffer[63] = Sigma1(m_wordBuffer[61]) + m_wordBuffer[56] + Sigma0(m_wordBuffer[48]) + m_wordBuffer[47];
	m_wordBuffer[64] = Sigma1(m_wordBuffer[62]) + m_wordBuffer[57] + Sigma0(m_wordBuffer[49]) + m_wordBuffer[48];
	m_wordBuffer[65] = Sigma1(m_wordBuffer[63]) + m_wordBuffer[58] + Sigma0(m_wordBuffer[50]) + m_wordBuffer[49];
	m_wordBuffer[66] = Sigma1(m_wordBuffer[64]) + m_wordBuffer[59] + Sigma0(m_wordBuffer[51]) + m_wordBuffer[50];
	m_wordBuffer[67] = Sigma1(m_wordBuffer[65]) + m_wordBuffer[60] + Sigma0(m_wordBuffer[52]) + m_wordBuffer[51];
	m_wordBuffer[68] = Sigma1(m_wordBuffer[66]) + m_wordBuffer[61] + Sigma0(m_wordBuffer[53]) + m_wordBuffer[52];
	m_wordBuffer[69] = Sigma1(m_wordBuffer[67]) + m_wordBuffer[62] + Sigma0(m_wordBuffer[54]) + m_wordBuffer[53];
	m_wordBuffer[70] = Sigma1(m_wordBuffer[68]) + m_wordBuffer[63] + Sigma0(m_wordBuffer[55]) + m_wordBuffer[54];
	m_wordBuffer[71] = Sigma1(m_wordBuffer[69]) + m_wordBuffer[64] + Sigma0(m_wordBuffer[56]) + m_wordBuffer[55];
	m_wordBuffer[72] = Sigma1(m_wordBuffer[70]) + m_wordBuffer[65] + Sigma0(m_wordBuffer[57]) + m_wordBuffer[56];
	m_wordBuffer[73] = Sigma1(m_wordBuffer[71]) + m_wordBuffer[66] + Sigma0(m_wordBuffer[58]) + m_wordBuffer[57];
	m_wordBuffer[74] = Sigma1(m_wordBuffer[72]) + m_wordBuffer[67] + Sigma0(m_wordBuffer[59]) + m_wordBuffer[58];
	m_wordBuffer[75] = Sigma1(m_wordBuffer[73]) + m_wordBuffer[68] + Sigma0(m_wordBuffer[60]) + m_wordBuffer[59];
	m_wordBuffer[76] = Sigma1(m_wordBuffer[74]) + m_wordBuffer[69] + Sigma0(m_wordBuffer[61]) + m_wordBuffer[60];
	m_wordBuffer[77] = Sigma1(m_wordBuffer[75]) + m_wordBuffer[70] + Sigma0(m_wordBuffer[62]) + m_wordBuffer[61];
	m_wordBuffer[78] = Sigma1(m_wordBuffer[76]) + m_wordBuffer[71] + Sigma0(m_wordBuffer[63]) + m_wordBuffer[62];
	m_wordBuffer[79] = Sigma1(m_wordBuffer[77]) + m_wordBuffer[72] + Sigma0(m_wordBuffer[64]) + m_wordBuffer[63];

	// set up working variables
	ulong w0 = H0;
	ulong w1 = H1;
	ulong w2 = H2;
	ulong w3 = H3;
	ulong w4 = H4;
	ulong w5 = H5;
	ulong w6 = H6;
	ulong w7 = H7;
	size_t ctr = 0;

	// t = 8 * i
	w7 += Sum1(w4) + Ch(w4, w5, w6) + K64[ctr] + m_wordBuffer[ctr];
	w3 += w7;
	w7 += Sum0(w0) + Maj(w0, w1, w2);
	// t = 8 * i + 1
	w6 += Sum1(w3) + Ch(w3, w4, w5) + K64[++ctr] + m_wordBuffer[ctr];
	w2 += w6;
	w6 += Sum0(w7) + Maj(w7, w0, w1);
	// t = 8 * i + 2
	w5 += Sum1(w2) + Ch(w2, w3, w4) + K64[++ctr] + m_wordBuffer[ctr];
	w1 += w5;
	w5 += Sum0(w6) + Maj(w6, w7, w0);
	// t = 8 * i + 3
	w4 += Sum1(w1) + Ch(w1, w2, w3) + K64[++ctr] + m_wordBuffer[ctr];
	w0 += w4;
	w4 += Sum0(w5) + Maj(w5, w6, w7);
	// t = 8 * i + 4
	w3 += Sum1(w0) + Ch(w0, w1, w2) + K64[++ctr] + m_wordBuffer[ctr];
	w7 += w3;
	w3 += Sum0(w4) + Maj(w4, w5, w6);
	// t = 8 * i + 5
	w2 += Sum1(w7) + Ch(w7, w0, w1) + K64[++ctr] + m_wordBuffer[ctr];
	w6 += w2;
	w2 += Sum0(w3) + Maj(w3, w4, w5);
	// t = 8 * i + 6
	w1 += Sum1(w6) + Ch(w6, w7, w0) + K64[++ctr] + m_wordBuffer[ctr];
	w5 += w1;
	w1 += Sum0(w2) + Maj(w2, w3, w4);
	// t = 8 * i + 7
	w0 += Sum1(w5) + Ch(w5, w6, w7) + K64[++ctr] + m_wordBuffer[ctr];
	w4 += w0;
	w0 += Sum0(w1) + Maj(w1, w2, w3);

	w7 += Sum1(w4) + Ch(w4, w5, w6) + K64[++ctr] + m_wordBuffer[ctr];
	w3 += w7;
	w7 += Sum0(w0) + Maj(w0, w1, w2);
	w6 += Sum1(w3) + Ch(w3, w4, w5) + K64[++ctr] + m_wordBuffer[ctr];
	w2 += w6;
	w6 += Sum0(w7) + Maj(w7, w0, w1);
	w5 += Sum1(w2) + Ch(w2, w3, w4) + K64[++ctr] + m_wordBuffer[ctr];
	w1 += w5;
	w5 += Sum0(w6) + Maj(w6, w7, w0);
	w4 += Sum1(w1) + Ch(w1, w2, w3) + K64[++ctr] + m_wordBuffer[ctr];
	w0 += w4;
	w4 += Sum0(w5) + Maj(w5, w6, w7);
	w3 += Sum1(w0) + Ch(w0, w1, w2) + K64[++ctr] + m_wordBuffer[ctr];
	w7 += w3;
	w3 += Sum0(w4) + Maj(w4, w5, w6);
	w2 += Sum1(w7) + Ch(w7, w0, w1) + K64[++ctr] + m_wordBuffer[ctr];
	w6 += w2;
	w2 += Sum0(w3) + Maj(w3, w4, w5);
	w1 += Sum1(w6) + Ch(w6, w7, w0) + K64[++ctr] + m_wordBuffer[ctr];
	w5 += w1;
	w1 += Sum0(w2) + Maj(w2, w3, w4);
	w0 += Sum1(w5) + Ch(w5, w6, w7) + K64[++ctr] + m_wordBuffer[ctr];
	w4 += w0;
	w0 += Sum0(w1) + Maj(w1, w2, w3);

	w7 += Sum1(w4) + Ch(w4, w5, w6) + K64[++ctr] + m_wordBuffer[ctr];
	w3 += w7;
	w7 += Sum0(w0) + Maj(w0, w1, w2);
	w6 += Sum1(w3) + Ch(w3, w4, w5) + K64[++ctr] + m_wordBuffer[ctr];
	w2 += w6;
	w6 += Sum0(w7) + Maj(w7, w0, w1);
	w5 += Sum1(w2) + Ch(w2, w3, w4) + K64[++ctr] + m_wordBuffer[ctr];
	w1 += w5;
	w5 += Sum0(w6) + Maj(w6, w7, w0);
	w4 += Sum1(w1) + Ch(w1, w2, w3) + K64[++ctr] + m_wordBuffer[ctr];
	w0 += w4;
	w4 += Sum0(w5) + Maj(w5, w6, w7);
	w3 += Sum1(w0) + Ch(w0, w1, w2) + K64[++ctr] + m_wordBuffer[ctr];
	w7 += w3;
	w3 += Sum0(w4) + Maj(w4, w5, w6);
	w2 += Sum1(w7) + Ch(w7, w0, w1) + K64[++ctr] + m_wordBuffer[ctr];
	w6 += w2;
	w2 += Sum0(w3) + Maj(w3, w4, w5);
	w1 += Sum1(w6) + Ch(w6, w7, w0) + K64[++ctr] + m_wordBuffer[ctr];
	w5 += w1;
	w1 += Sum0(w2) + Maj(w2, w3, w4);
	w0 += Sum1(w5) + Ch(w5, w6, w7) + K64[++ctr] + m_wordBuffer[ctr];
	w4 += w0;
	w0 += Sum0(w1) + Maj(w1, w2, w3);

	w7 += Sum1(w4) + Ch(w4, w5, w6) + K64[++ctr] + m_wordBuffer[ctr];
	w3 += w7;
	w7 += Sum0(w0) + Maj(w0, w1, w2);
	w6 += Sum1(w3) + Ch(w3, w4, w5) + K64[++ctr] + m_wordBuffer[ctr];
	w2 += w6;
	w6 += Sum0(w7) + Maj(w7, w0, w1);
	w5 += Sum1(w2) + Ch(w2, w3, w4) + K64[++ctr] + m_wordBuffer[ctr];
	w1 += w5;
	w5 += Sum0(w6) + Maj(w6, w7, w0);
	w4 += Sum1(w1) + Ch(w1, w2, w3) + K64[++ctr] + m_wordBuffer[ctr];
	w0 += w4;
	w4 += Sum0(w5) + Maj(w5, w6, w7);
	w3 += Sum1(w0) + Ch(w0, w1, w2) + K64[++ctr] + m_wordBuffer[ctr];
	w7 += w3;
	w3 += Sum0(w4) + Maj(w4, w5, w6);
	w2 += Sum1(w7) + Ch(w7, w0, w1) + K64[++ctr] + m_wordBuffer[ctr];
	w6 += w2;
	w2 += Sum0(w3) + Maj(w3, w4, w5);
	w1 += Sum1(w6) + Ch(w6, w7, w0) + K64[++ctr] + m_wordBuffer[ctr];
	w5 += w1;
	w1 += Sum0(w2) + Maj(w2, w3, w4);
	w0 += Sum1(w5) + Ch(w5, w6, w7) + K64[++ctr] + m_wordBuffer[ctr];
	w4 += w0;
	w0 += Sum0(w1) + Maj(w1, w2, w3);

	w7 += Sum1(w4) + Ch(w4, w5, w6) + K64[++ctr] + m_wordBuffer[ctr];
	w3 += w7;
	w7 += Sum0(w0) + Maj(w0, w1, w2);
	w6 += Sum1(w3) + Ch(w3, w4, w5) + K64[++ctr] + m_wordBuffer[ctr];
	w2 += w6;
	w6 += Sum0(w7) + Maj(w7, w0, w1);
	w5 += Sum1(w2) + Ch(w2, w3, w4) + K64[++ctr] + m_wordBuffer[ctr];
	w1 += w5;
	w5 += Sum0(w6) + Maj(w6, w7, w0);
	w4 += Sum1(w1) + Ch(w1, w2, w3) + K64[++ctr] + m_wordBuffer[ctr];
	w0 += w4;
	w4 += Sum0(w5) + Maj(w5, w6, w7);
	w3 += Sum1(w0) + Ch(w0, w1, w2) + K64[++ctr] + m_wordBuffer[ctr];
	w7 += w3;
	w3 += Sum0(w4) + Maj(w4, w5, w6);
	w2 += Sum1(w7) + Ch(w7, w0, w1) + K64[++ctr] + m_wordBuffer[ctr];
	w6 += w2;
	w2 += Sum0(w3) + Maj(w3, w4, w5);
	w1 += Sum1(w6) + Ch(w6, w7, w0) + K64[++ctr] + m_wordBuffer[ctr];
	w5 += w1;
	w1 += Sum0(w2) + Maj(w2, w3, w4);
	w0 += Sum1(w5) + Ch(w5, w6, w7) + K64[++ctr] + m_wordBuffer[ctr];
	w4 += w0;
	w0 += Sum0(w1) + Maj(w1, w2, w3);

	w7 += Sum1(w4) + Ch(w4, w5, w6) + K64[++ctr] + m_wordBuffer[ctr];
	w3 += w7;
	w7 += Sum0(w0) + Maj(w0, w1, w2);
	w6 += Sum1(w3) + Ch(w3, w4, w5) + K64[++ctr] + m_wordBuffer[ctr];
	w2 += w6;
	w6 += Sum0(w7) + Maj(w7, w0, w1);
	w5 += Sum1(w2) + Ch(w2, w3, w4) + K64[++ctr] + m_wordBuffer[ctr];
	w1 += w5;
	w5 += Sum0(w6) + Maj(w6, w7, w0);
	w4 += Sum1(w1) + Ch(w1, w2, w3) + K64[++ctr] + m_wordBuffer[ctr];
	w0 += w4;
	w4 += Sum0(w5) + Maj(w5, w6, w7);
	w3 += Sum1(w0) + Ch(w0, w1, w2) + K64[++ctr] + m_wordBuffer[ctr];
	w7 += w3;
	w3 += Sum0(w4) + Maj(w4, w5, w6);
	w2 += Sum1(w7) + Ch(w7, w0, w1) + K64[++ctr] + m_wordBuffer[ctr];
	w6 += w2;
	w2 += Sum0(w3) + Maj(w3, w4, w5);
	w1 += Sum1(w6) + Ch(w6, w7, w0) + K64[++ctr] + m_wordBuffer[ctr];
	w5 += w1;
	w1 += Sum0(w2) + Maj(w2, w3, w4);
	w0 += Sum1(w5) + Ch(w5, w6, w7) + K64[++ctr] + m_wordBuffer[ctr];
	w4 += w0;
	w0 += Sum0(w1) + Maj(w1, w2, w3);

	w7 += Sum1(w4) + Ch(w4, w5, w6) + K64[++ctr] + m_wordBuffer[ctr];
	w3 += w7;
	w7 += Sum0(w0) + Maj(w0, w1, w2);
	w6 += Sum1(w3) + Ch(w3, w4, w5) + K64[++ctr] + m_wordBuffer[ctr];
	w2 += w6;
	w6 += Sum0(w7) + Maj(w7, w0, w1);
	w5 += Sum1(w2) + Ch(w2, w3, w4) + K64[++ctr] + m_wordBuffer[ctr];
	w1 += w5;
	w5 += Sum0(w6) + Maj(w6, w7, w0);
	w4 += Sum1(w1) + Ch(w1, w2, w3) + K64[++ctr] + m_wordBuffer[ctr];
	w0 += w4;
	w4 += Sum0(w5) + Maj(w5, w6, w7);
	w3 += Sum1(w0) + Ch(w0, w1, w2) + K64[++ctr] + m_wordBuffer[ctr];
	w7 += w3;
	w3 += Sum0(w4) + Maj(w4, w5, w6);
	w2 += Sum1(w7) + Ch(w7, w0, w1) + K64[++ctr] + m_wordBuffer[ctr];
	w6 += w2;
	w2 += Sum0(w3) + Maj(w3, w4, w5);
	w1 += Sum1(w6) + Ch(w6, w7, w0) + K64[++ctr] + m_wordBuffer[ctr];
	w5 += w1;
	w1 += Sum0(w2) + Maj(w2, w3, w4);
	w0 += Sum1(w5) + Ch(w5, w6, w7) + K64[++ctr] + m_wordBuffer[ctr];
	w4 += w0;
	w0 += Sum0(w1) + Maj(w1, w2, w3);

	w7 += Sum1(w4) + Ch(w4, w5, w6) + K64[++ctr] + m_wordBuffer[ctr];
	w3 += w7;
	w7 += Sum0(w0) + Maj(w0, w1, w2);
	w6 += Sum1(w3) + Ch(w3, w4, w5) + K64[++ctr] + m_wordBuffer[ctr];
	w2 += w6;
	w6 += Sum0(w7) + Maj(w7, w0, w1);
	w5 += Sum1(w2) + Ch(w2, w3, w4) + K64[++ctr] + m_wordBuffer[ctr];
	w1 += w5;
	w5 += Sum0(w6) + Maj(w6, w7, w0);
	w4 += Sum1(w1) + Ch(w1, w2, w3) + K64[++ctr] + m_wordBuffer[ctr];
	w0 += w4;
	w4 += Sum0(w5) + Maj(w5, w6, w7);
	w3 += Sum1(w0) + Ch(w0, w1, w2) + K64[++ctr] + m_wordBuffer[ctr];
	w7 += w3;
	w3 += Sum0(w4) + Maj(w4, w5, w6);
	w2 += Sum1(w7) + Ch(w7, w0, w1) + K64[++ctr] + m_wordBuffer[ctr];
	w6 += w2;
	w2 += Sum0(w3) + Maj(w3, w4, w5);
	w1 += Sum1(w6) + Ch(w6, w7, w0) + K64[++ctr] + m_wordBuffer[ctr];
	w5 += w1;
	w1 += Sum0(w2) + Maj(w2, w3, w4);
	w0 += Sum1(w5) + Ch(w5, w6, w7) + K64[++ctr] + m_wordBuffer[ctr];
	w4 += w0;
	w0 += Sum0(w1) + Maj(w1, w2, w3);

	w7 += Sum1(w4) + Ch(w4, w5, w6) + K64[++ctr] + m_wordBuffer[ctr];
	w3 += w7;
	w7 += Sum0(w0) + Maj(w0, w1, w2);
	w6 += Sum1(w3) + Ch(w3, w4, w5) + K64[++ctr] + m_wordBuffer[ctr];
	w2 += w6;
	w6 += Sum0(w7) + Maj(w7, w0, w1);
	w5 += Sum1(w2) + Ch(w2, w3, w4) + K64[++ctr] + m_wordBuffer[ctr];
	w1 += w5;
	w5 += Sum0(w6) + Maj(w6, w7, w0);
	w4 += Sum1(w1) + Ch(w1, w2, w3) + K64[++ctr] + m_wordBuffer[ctr];
	w0 += w4;
	w4 += Sum0(w5) + Maj(w5, w6, w7);
	w3 += Sum1(w0) + Ch(w0, w1, w2) + K64[++ctr] + m_wordBuffer[ctr];
	w7 += w3;
	w3 += Sum0(w4) + Maj(w4, w5, w6);
	w2 += Sum1(w7) + Ch(w7, w0, w1) + K64[++ctr] + m_wordBuffer[ctr];
	w6 += w2;
	w2 += Sum0(w3) + Maj(w3, w4, w5);
	w1 += Sum1(w6) + Ch(w6, w7, w0) + K64[++ctr] + m_wordBuffer[ctr];
	w5 += w1;
	w1 += Sum0(w2) + Maj(w2, w3, w4);
	w0 += Sum1(w5) + Ch(w5, w6, w7) + K64[++ctr] + m_wordBuffer[ctr];
	w4 += w0;
	w0 += Sum0(w1) + Maj(w1, w2, w3);

	w7 += Sum1(w4) + Ch(w4, w5, w6) + K64[++ctr] + m_wordBuffer[ctr];
	w3 += w7;
	w7 += Sum0(w0) + Maj(w0, w1, w2);
	w6 += Sum1(w3) + Ch(w3, w4, w5) + K64[++ctr] + m_wordBuffer[ctr];
	w2 += w6;
	w6 += Sum0(w7) + Maj(w7, w0, w1);
	w5 += Sum1(w2) + Ch(w2, w3, w4) + K64[++ctr] + m_wordBuffer[ctr];
	w1 += w5;
	w5 += Sum0(w6) + Maj(w6, w7, w0);
	w4 += Sum1(w1) + Ch(w1, w2, w3) + K64[++ctr] + m_wordBuffer[ctr];
	w0 += w4;
	w4 += Sum0(w5) + Maj(w5, w6, w7);
	w3 += Sum1(w0) + Ch(w0, w1, w2) + K64[++ctr] + m_wordBuffer[ctr];
	w7 += w3;
	w3 += Sum0(w4) + Maj(w4, w5, w6);
	w2 += Sum1(w7) + Ch(w7, w0, w1) + K64[++ctr] + m_wordBuffer[ctr];
	w6 += w2;
	w2 += Sum0(w3) + Maj(w3, w4, w5);
	w1 += Sum1(w6) + Ch(w6, w7, w0) + K64[++ctr] + m_wordBuffer[ctr];
	w5 += w1;
	w1 += Sum0(w2) + Maj(w2, w3, w4);
	w0 += Sum1(w5) + Ch(w5, w6, w7) + K64[++ctr] + m_wordBuffer[ctr];
	w4 += w0;
	w0 += Sum0(w1) + Maj(w1, w2, w3);

	H0 += w0;
	H1 += w1;
	H2 += w2;
	H3 += w3;
	H4 += w4;
	H5 += w5;
	H6 += w6;
	H7 += w7;

	m_wordOffset = 0;
	memset(m_wordBuffer.data(), 0, m_wordBuffer.size() * sizeof(ulong));
}

void SHA512::ProcessLength(ulong LowWord, ulong HiWord)
{
	if (m_wordOffset > 14)
		ProcessBlock();

	m_wordBuffer[14] = (ulong)HiWord;
	m_wordBuffer[15] = (ulong)LowWord;
}

void SHA512::ProcessWord(const std::vector<byte> &Input, size_t InOffset)
{
	m_wordBuffer[m_wordOffset] = IntUtils::BytesToBe64(Input, InOffset);

	if (++m_wordOffset == 16)
		ProcessBlock();
}

NAMESPACE_DIGESTEND