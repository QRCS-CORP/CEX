#include "SHA256.h"
#include "SHA.h"
#include "IntUtils.h"

NAMESPACE_DIGEST

void SHA256::BlockUpdate(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
#if defined(CPPEXCEPTIONS_ENABLED)
	if ((InOffset + Length) > Input.size())
		throw CryptoDigestException("SHA256:BlockUpdate", "The Input buffer is too short!");
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
		m_byteCount += m_prcBuffer.size();
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
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_bufferOffset = 0;
		m_byteCount = 0;
		H0 = 0, H1 = 0, H2 = 0, H3 = 0, H4 = 0, H5 = 0, H6 = 0, H7 = 0;
		m_wordOffset = 0;

		CEX::Utility::IntUtils::ClearVector(m_prcBuffer);
		CEX::Utility::IntUtils::ClearVector(m_wordBuffer);
	}
}

size_t SHA256::DoFinal(std::vector<byte> &Output, const size_t OutOffset)
{
#if defined(CPPEXCEPTIONS_ENABLED)
	if (Output.size() - OutOffset < DigestSize())
		throw CryptoDigestException("SHA256:DoFinal", "The Output buffer is too short!");
#endif

	Finish();
	CEX::Utility::IntUtils::Be32ToBytes(H0, Output, OutOffset);
	CEX::Utility::IntUtils::Be32ToBytes(H1, Output, OutOffset + 4);
	CEX::Utility::IntUtils::Be32ToBytes(H2, Output, OutOffset + 8);
	CEX::Utility::IntUtils::Be32ToBytes(H3, Output, OutOffset + 12);
	CEX::Utility::IntUtils::Be32ToBytes(H4, Output, OutOffset + 16);
	CEX::Utility::IntUtils::Be32ToBytes(H5, Output, OutOffset + 20);
	CEX::Utility::IntUtils::Be32ToBytes(H6, Output, OutOffset + 24);
	CEX::Utility::IntUtils::Be32ToBytes(H7, Output, OutOffset + 28);

	Reset();

	return DIGEST_SIZE;
}

void SHA256::Reset()
{
	m_byteCount = 0;
	m_bufferOffset = 0;
	memset(&m_prcBuffer[0], (byte)0, m_prcBuffer.size());

	Initialize();
}

void SHA256::Update(byte Input)
{
	m_prcBuffer[m_bufferOffset++] = Input;

	if (m_bufferOffset == m_prcBuffer.size())
	{
		ProcessWord(m_prcBuffer, 0);
		m_bufferOffset = 0;
	}

	m_byteCount++;
}

// *** Protected Methods *** //

void SHA256::Finish()
{
	int64_t bitLength = (m_byteCount << 3);

	Update((byte)128);

	while (m_bufferOffset != 0)
		Update((byte)0);

	ProcessLength(bitLength);
	ProcessBlock();
}

void SHA256::Initialize()
{
	// The first 32 bits of the fractional parts of the square roots of the first eight prime numbers
	H0 = 0x6a09e667;
	H1 = 0xbb67ae85;
	H2 = 0x3c6ef372;
	H3 = 0xa54ff53a;
	H4 = 0x510e527f;
	H5 = 0x9b05688c;
	H6 = 0x1f83d9ab;
	H7 = 0x5be0cd19;
}

void SHA256::ProcessBlock()
{
	int32_t ctr = 0;
	uint w0 = H0;
	uint w1 = H1;
	uint w2 = H2;
	uint w3 = H3;
	uint w4 = H4;
	uint w5 = H5;
	uint w6 = H6;
	uint w7 = H7;

	// expand 16 word block into 64 blocks
	m_wordBuffer[16] = Theta1(m_wordBuffer[14]) + m_wordBuffer[9] + Theta0(m_wordBuffer[1]) + m_wordBuffer[0];
	m_wordBuffer[17] = Theta1(m_wordBuffer[15]) + m_wordBuffer[10] + Theta0(m_wordBuffer[2]) + m_wordBuffer[1];
	m_wordBuffer[18] = Theta1(m_wordBuffer[16]) + m_wordBuffer[11] + Theta0(m_wordBuffer[3]) + m_wordBuffer[2];
	m_wordBuffer[19] = Theta1(m_wordBuffer[17]) + m_wordBuffer[12] + Theta0(m_wordBuffer[4]) + m_wordBuffer[3];
	m_wordBuffer[20] = Theta1(m_wordBuffer[18]) + m_wordBuffer[13] + Theta0(m_wordBuffer[5]) + m_wordBuffer[4];
	m_wordBuffer[21] = Theta1(m_wordBuffer[19]) + m_wordBuffer[14] + Theta0(m_wordBuffer[6]) + m_wordBuffer[5];
	m_wordBuffer[22] = Theta1(m_wordBuffer[20]) + m_wordBuffer[15] + Theta0(m_wordBuffer[7]) + m_wordBuffer[6];
	m_wordBuffer[23] = Theta1(m_wordBuffer[21]) + m_wordBuffer[16] + Theta0(m_wordBuffer[8]) + m_wordBuffer[7];
	m_wordBuffer[24] = Theta1(m_wordBuffer[22]) + m_wordBuffer[17] + Theta0(m_wordBuffer[9]) + m_wordBuffer[8];
	m_wordBuffer[25] = Theta1(m_wordBuffer[23]) + m_wordBuffer[18] + Theta0(m_wordBuffer[10]) + m_wordBuffer[9];
	m_wordBuffer[26] = Theta1(m_wordBuffer[24]) + m_wordBuffer[19] + Theta0(m_wordBuffer[11]) + m_wordBuffer[10];
	m_wordBuffer[27] = Theta1(m_wordBuffer[25]) + m_wordBuffer[20] + Theta0(m_wordBuffer[12]) + m_wordBuffer[11];
	m_wordBuffer[28] = Theta1(m_wordBuffer[26]) + m_wordBuffer[21] + Theta0(m_wordBuffer[13]) + m_wordBuffer[12];
	m_wordBuffer[29] = Theta1(m_wordBuffer[27]) + m_wordBuffer[22] + Theta0(m_wordBuffer[14]) + m_wordBuffer[13];
	m_wordBuffer[30] = Theta1(m_wordBuffer[28]) + m_wordBuffer[23] + Theta0(m_wordBuffer[15]) + m_wordBuffer[14];
	m_wordBuffer[31] = Theta1(m_wordBuffer[29]) + m_wordBuffer[24] + Theta0(m_wordBuffer[16]) + m_wordBuffer[15];
	m_wordBuffer[32] = Theta1(m_wordBuffer[30]) + m_wordBuffer[25] + Theta0(m_wordBuffer[17]) + m_wordBuffer[16];
	m_wordBuffer[33] = Theta1(m_wordBuffer[31]) + m_wordBuffer[26] + Theta0(m_wordBuffer[18]) + m_wordBuffer[17];
	m_wordBuffer[34] = Theta1(m_wordBuffer[32]) + m_wordBuffer[27] + Theta0(m_wordBuffer[19]) + m_wordBuffer[18];
	m_wordBuffer[35] = Theta1(m_wordBuffer[33]) + m_wordBuffer[28] + Theta0(m_wordBuffer[20]) + m_wordBuffer[19];
	m_wordBuffer[36] = Theta1(m_wordBuffer[34]) + m_wordBuffer[29] + Theta0(m_wordBuffer[21]) + m_wordBuffer[20];
	m_wordBuffer[37] = Theta1(m_wordBuffer[35]) + m_wordBuffer[30] + Theta0(m_wordBuffer[22]) + m_wordBuffer[21];
	m_wordBuffer[38] = Theta1(m_wordBuffer[36]) + m_wordBuffer[31] + Theta0(m_wordBuffer[23]) + m_wordBuffer[22];
	m_wordBuffer[39] = Theta1(m_wordBuffer[37]) + m_wordBuffer[32] + Theta0(m_wordBuffer[24]) + m_wordBuffer[23];
	m_wordBuffer[40] = Theta1(m_wordBuffer[38]) + m_wordBuffer[33] + Theta0(m_wordBuffer[25]) + m_wordBuffer[24];
	m_wordBuffer[41] = Theta1(m_wordBuffer[39]) + m_wordBuffer[34] + Theta0(m_wordBuffer[26]) + m_wordBuffer[25];
	m_wordBuffer[42] = Theta1(m_wordBuffer[40]) + m_wordBuffer[35] + Theta0(m_wordBuffer[27]) + m_wordBuffer[26];
	m_wordBuffer[43] = Theta1(m_wordBuffer[41]) + m_wordBuffer[36] + Theta0(m_wordBuffer[28]) + m_wordBuffer[27];
	m_wordBuffer[44] = Theta1(m_wordBuffer[42]) + m_wordBuffer[37] + Theta0(m_wordBuffer[29]) + m_wordBuffer[28];
	m_wordBuffer[45] = Theta1(m_wordBuffer[43]) + m_wordBuffer[38] + Theta0(m_wordBuffer[30]) + m_wordBuffer[29];
	m_wordBuffer[46] = Theta1(m_wordBuffer[44]) + m_wordBuffer[39] + Theta0(m_wordBuffer[31]) + m_wordBuffer[30];
	m_wordBuffer[47] = Theta1(m_wordBuffer[45]) + m_wordBuffer[40] + Theta0(m_wordBuffer[32]) + m_wordBuffer[31];
	m_wordBuffer[48] = Theta1(m_wordBuffer[46]) + m_wordBuffer[41] + Theta0(m_wordBuffer[33]) + m_wordBuffer[32];
	m_wordBuffer[49] = Theta1(m_wordBuffer[47]) + m_wordBuffer[42] + Theta0(m_wordBuffer[34]) + m_wordBuffer[33];
	m_wordBuffer[50] = Theta1(m_wordBuffer[48]) + m_wordBuffer[43] + Theta0(m_wordBuffer[35]) + m_wordBuffer[34];
	m_wordBuffer[51] = Theta1(m_wordBuffer[49]) + m_wordBuffer[44] + Theta0(m_wordBuffer[36]) + m_wordBuffer[35];
	m_wordBuffer[52] = Theta1(m_wordBuffer[50]) + m_wordBuffer[45] + Theta0(m_wordBuffer[37]) + m_wordBuffer[36];
	m_wordBuffer[53] = Theta1(m_wordBuffer[51]) + m_wordBuffer[46] + Theta0(m_wordBuffer[38]) + m_wordBuffer[37];
	m_wordBuffer[54] = Theta1(m_wordBuffer[52]) + m_wordBuffer[47] + Theta0(m_wordBuffer[39]) + m_wordBuffer[38];
	m_wordBuffer[55] = Theta1(m_wordBuffer[53]) + m_wordBuffer[48] + Theta0(m_wordBuffer[40]) + m_wordBuffer[39];
	m_wordBuffer[56] = Theta1(m_wordBuffer[54]) + m_wordBuffer[49] + Theta0(m_wordBuffer[41]) + m_wordBuffer[40];
	m_wordBuffer[57] = Theta1(m_wordBuffer[55]) + m_wordBuffer[50] + Theta0(m_wordBuffer[42]) + m_wordBuffer[41];
	m_wordBuffer[58] = Theta1(m_wordBuffer[56]) + m_wordBuffer[51] + Theta0(m_wordBuffer[43]) + m_wordBuffer[42];
	m_wordBuffer[59] = Theta1(m_wordBuffer[57]) + m_wordBuffer[52] + Theta0(m_wordBuffer[44]) + m_wordBuffer[43];
	m_wordBuffer[60] = Theta1(m_wordBuffer[58]) + m_wordBuffer[53] + Theta0(m_wordBuffer[45]) + m_wordBuffer[44];
	m_wordBuffer[61] = Theta1(m_wordBuffer[59]) + m_wordBuffer[54] + Theta0(m_wordBuffer[46]) + m_wordBuffer[45];
	m_wordBuffer[62] = Theta1(m_wordBuffer[60]) + m_wordBuffer[55] + Theta0(m_wordBuffer[47]) + m_wordBuffer[46];
	m_wordBuffer[63] = Theta1(m_wordBuffer[61]) + m_wordBuffer[56] + Theta0(m_wordBuffer[48]) + m_wordBuffer[47];

	// t = 8 * i
	w7 += Sum1Ch(w4, w5, w6) + K32[ctr] + m_wordBuffer[ctr];
	w3 += w7;
	w7 += Sum0Maj(w0, w1, w2);
	// t = 8 * i + 1
	w6 += Sum1Ch(w3, w4, w5) + K32[++ctr] + m_wordBuffer[ctr];
	w2 += w6;
	w6 += Sum0Maj(w7, w0, w1);
	// t = 8 * i + 2
	w5 += Sum1Ch(w2, w3, w4) + K32[++ctr] + m_wordBuffer[ctr];
	w1 += w5;
	w5 += Sum0Maj(w6, w7, w0);
	// t = 8 * i + 3
	w4 += Sum1Ch(w1, w2, w3) + K32[++ctr] + m_wordBuffer[ctr];
	w0 += w4;
	w4 += Sum0Maj(w5, w6, w7);
	// t = 8 * i + 4
	w3 += Sum1Ch(w0, w1, w2) + K32[++ctr] + m_wordBuffer[ctr];
	w7 += w3;
	w3 += Sum0Maj(w4, w5, w6);
	// t = 8 * i + 5
	w2 += Sum1Ch(w7, w0, w1) + K32[++ctr] + m_wordBuffer[ctr];
	w6 += w2;
	w2 += Sum0Maj(w3, w4, w5);
	// t = 8 * i + 6
	w1 += Sum1Ch(w6, w7, w0) + K32[++ctr] + m_wordBuffer[ctr];
	w5 += w1;
	w1 += Sum0Maj(w2, w3, w4);
	// t = 8 * i + 7
	w0 += Sum1Ch(w5, w6, w7) + K32[++ctr] + m_wordBuffer[ctr];
	w4 += w0;
	w0 += Sum0Maj(w1, w2, w3);

	w7 += Sum1Ch(w4, w5, w6) + K32[++ctr] + m_wordBuffer[ctr];
	w3 += w7;
	w7 += Sum0Maj(w0, w1, w2);
	w6 += Sum1Ch(w3, w4, w5) + K32[++ctr] + m_wordBuffer[ctr];
	w2 += w6;
	w6 += Sum0Maj(w7, w0, w1);
	w5 += Sum1Ch(w2, w3, w4) + K32[++ctr] + m_wordBuffer[ctr];
	w1 += w5;
	w5 += Sum0Maj(w6, w7, w0);
	w4 += Sum1Ch(w1, w2, w3) + K32[++ctr] + m_wordBuffer[ctr];
	w0 += w4;
	w4 += Sum0Maj(w5, w6, w7);
	w3 += Sum1Ch(w0, w1, w2) + K32[++ctr] + m_wordBuffer[ctr];
	w7 += w3;
	w3 += Sum0Maj(w4, w5, w6);
	w2 += Sum1Ch(w7, w0, w1) + K32[++ctr] + m_wordBuffer[ctr];
	w6 += w2;
	w2 += Sum0Maj(w3, w4, w5);
	w1 += Sum1Ch(w6, w7, w0) + K32[++ctr] + m_wordBuffer[ctr];
	w5 += w1;
	w1 += Sum0Maj(w2, w3, w4);
	w0 += Sum1Ch(w5, w6, w7) + K32[++ctr] + m_wordBuffer[ctr];
	w4 += w0;
	w0 += Sum0Maj(w1, w2, w3);

	w7 += Sum1Ch(w4, w5, w6) + K32[++ctr] + m_wordBuffer[ctr];
	w3 += w7;
	w7 += Sum0Maj(w0, w1, w2);
	w6 += Sum1Ch(w3, w4, w5) + K32[++ctr] + m_wordBuffer[ctr];
	w2 += w6;
	w6 += Sum0Maj(w7, w0, w1);
	w5 += Sum1Ch(w2, w3, w4) + K32[++ctr] + m_wordBuffer[ctr];
	w1 += w5;
	w5 += Sum0Maj(w6, w7, w0);
	w4 += Sum1Ch(w1, w2, w3) + K32[++ctr] + m_wordBuffer[ctr];
	w0 += w4;
	w4 += Sum0Maj(w5, w6, w7);
	w3 += Sum1Ch(w0, w1, w2) + K32[++ctr] + m_wordBuffer[ctr];
	w7 += w3;
	w3 += Sum0Maj(w4, w5, w6);
	w2 += Sum1Ch(w7, w0, w1) + K32[++ctr] + m_wordBuffer[ctr];
	w6 += w2;
	w2 += Sum0Maj(w3, w4, w5);
	w1 += Sum1Ch(w6, w7, w0) + K32[++ctr] + m_wordBuffer[ctr];
	w5 += w1;
	w1 += Sum0Maj(w2, w3, w4);
	w0 += Sum1Ch(w5, w6, w7) + K32[++ctr] + m_wordBuffer[ctr];
	w4 += w0;
	w0 += Sum0Maj(w1, w2, w3);

	w7 += Sum1Ch(w4, w5, w6) + K32[++ctr] + m_wordBuffer[ctr];
	w3 += w7;
	w7 += Sum0Maj(w0, w1, w2);
	w6 += Sum1Ch(w3, w4, w5) + K32[++ctr] + m_wordBuffer[ctr];
	w2 += w6;
	w6 += Sum0Maj(w7, w0, w1);
	w5 += Sum1Ch(w2, w3, w4) + K32[++ctr] + m_wordBuffer[ctr];
	w1 += w5;
	w5 += Sum0Maj(w6, w7, w0);
	w4 += Sum1Ch(w1, w2, w3) + K32[++ctr] + m_wordBuffer[ctr];
	w0 += w4;
	w4 += Sum0Maj(w5, w6, w7);
	w3 += Sum1Ch(w0, w1, w2) + K32[++ctr] + m_wordBuffer[ctr];
	w7 += w3;
	w3 += Sum0Maj(w4, w5, w6);
	w2 += Sum1Ch(w7, w0, w1) + K32[++ctr] + m_wordBuffer[ctr];
	w6 += w2;
	w2 += Sum0Maj(w3, w4, w5);
	w1 += Sum1Ch(w6, w7, w0) + K32[++ctr] + m_wordBuffer[ctr];
	w5 += w1;
	w1 += Sum0Maj(w2, w3, w4);
	w0 += Sum1Ch(w5, w6, w7) + K32[++ctr] + m_wordBuffer[ctr];
	w4 += w0;
	w0 += Sum0Maj(w1, w2, w3);

	w7 += Sum1Ch(w4, w5, w6) + K32[++ctr] + m_wordBuffer[ctr];
	w3 += w7;
	w7 += Sum0Maj(w0, w1, w2);
	w6 += Sum1Ch(w3, w4, w5) + K32[++ctr] + m_wordBuffer[ctr];
	w2 += w6;
	w6 += Sum0Maj(w7, w0, w1);
	w5 += Sum1Ch(w2, w3, w4) + K32[++ctr] + m_wordBuffer[ctr];
	w1 += w5;
	w5 += Sum0Maj(w6, w7, w0);
	w4 += Sum1Ch(w1, w2, w3) + K32[++ctr] + m_wordBuffer[ctr];
	w0 += w4;
	w4 += Sum0Maj(w5, w6, w7);
	w3 += Sum1Ch(w0, w1, w2) + K32[++ctr] + m_wordBuffer[ctr];
	w7 += w3;
	w3 += Sum0Maj(w4, w5, w6);
	w2 += Sum1Ch(w7, w0, w1) + K32[++ctr] + m_wordBuffer[ctr];
	w6 += w2;
	w2 += Sum0Maj(w3, w4, w5);
	w1 += Sum1Ch(w6, w7, w0) + K32[++ctr] + m_wordBuffer[ctr];
	w5 += w1;
	w1 += Sum0Maj(w2, w3, w4);
	w0 += Sum1Ch(w5, w6, w7) + K32[++ctr] + m_wordBuffer[ctr];
	w4 += w0;
	w0 += Sum0Maj(w1, w2, w3);

	w7 += Sum1Ch(w4, w5, w6) + K32[++ctr] + m_wordBuffer[ctr];
	w3 += w7;
	w7 += Sum0Maj(w0, w1, w2);
	w6 += Sum1Ch(w3, w4, w5) + K32[++ctr] + m_wordBuffer[ctr];
	w2 += w6;
	w6 += Sum0Maj(w7, w0, w1);
	w5 += Sum1Ch(w2, w3, w4) + K32[++ctr] + m_wordBuffer[ctr];
	w1 += w5;
	w5 += Sum0Maj(w6, w7, w0);
	w4 += Sum1Ch(w1, w2, w3) + K32[++ctr] + m_wordBuffer[ctr];
	w0 += w4;
	w4 += Sum0Maj(w5, w6, w7);
	w3 += Sum1Ch(w0, w1, w2) + K32[++ctr] + m_wordBuffer[ctr];
	w7 += w3;
	w3 += Sum0Maj(w4, w5, w6);
	w2 += Sum1Ch(w7, w0, w1) + K32[++ctr] + m_wordBuffer[ctr];
	w6 += w2;
	w2 += Sum0Maj(w3, w4, w5);
	w1 += Sum1Ch(w6, w7, w0) + K32[++ctr] + m_wordBuffer[ctr];
	w5 += w1;
	w1 += Sum0Maj(w2, w3, w4);
	w0 += Sum1Ch(w5, w6, w7) + K32[++ctr] + m_wordBuffer[ctr];
	w4 += w0;
	w0 += Sum0Maj(w1, w2, w3);

	w7 += Sum1Ch(w4, w5, w6) + K32[++ctr] + m_wordBuffer[ctr];
	w3 += w7;
	w7 += Sum0Maj(w0, w1, w2);
	w6 += Sum1Ch(w3, w4, w5) + K32[++ctr] + m_wordBuffer[ctr];
	w2 += w6;
	w6 += Sum0Maj(w7, w0, w1);
	w5 += Sum1Ch(w2, w3, w4) + K32[++ctr] + m_wordBuffer[ctr];
	w1 += w5;
	w5 += Sum0Maj(w6, w7, w0);
	w4 += Sum1Ch(w1, w2, w3) + K32[++ctr] + m_wordBuffer[ctr];
	w0 += w4;
	w4 += Sum0Maj(w5, w6, w7);
	w3 += Sum1Ch(w0, w1, w2) + K32[++ctr] + m_wordBuffer[ctr];
	w7 += w3;
	w3 += Sum0Maj(w4, w5, w6);
	w2 += Sum1Ch(w7, w0, w1) + K32[++ctr] + m_wordBuffer[ctr];
	w6 += w2;
	w2 += Sum0Maj(w3, w4, w5);
	w1 += Sum1Ch(w6, w7, w0) + K32[++ctr] + m_wordBuffer[ctr];
	w5 += w1;
	w1 += Sum0Maj(w2, w3, w4);
	w0 += Sum1Ch(w5, w6, w7) + K32[++ctr] + m_wordBuffer[ctr];
	w4 += w0;
	w0 += Sum0Maj(w1, w2, w3);

	w7 += Sum1Ch(w4, w5, w6) + K32[++ctr] + m_wordBuffer[ctr];
	w3 += w7;
	w7 += Sum0Maj(w0, w1, w2);
	w6 += Sum1Ch(w3, w4, w5) + K32[++ctr] + m_wordBuffer[ctr];
	w2 += w6;
	w6 += Sum0Maj(w7, w0, w1);
	w5 += Sum1Ch(w2, w3, w4) + K32[++ctr] + m_wordBuffer[ctr];
	w1 += w5;
	w5 += Sum0Maj(w6, w7, w0);
	w4 += Sum1Ch(w1, w2, w3) + K32[++ctr] + m_wordBuffer[ctr];
	w0 += w4;
	w4 += Sum0Maj(w5, w6, w7);
	w3 += Sum1Ch(w0, w1, w2) + K32[++ctr] + m_wordBuffer[ctr];
	w7 += w3;
	w3 += Sum0Maj(w4, w5, w6);
	w2 += Sum1Ch(w7, w0, w1) + K32[++ctr] + m_wordBuffer[ctr];
	w6 += w2;
	w2 += Sum0Maj(w3, w4, w5);
	w1 += Sum1Ch(w6, w7, w0) + K32[++ctr] + m_wordBuffer[ctr];
	w5 += w1;
	w1 += Sum0Maj(w2, w3, w4);
	w0 += Sum1Ch(w5, w6, w7) + K32[++ctr] + m_wordBuffer[ctr];
	w4 += w0;
	w0 += Sum0Maj(w1, w2, w3);

	H0 += w0;
	H1 += w1;
	H2 += w2;
	H3 += w3;
	H4 += w4;
	H5 += w5;
	H6 += w6;
	H7 += w7;

	// reset the offset and clear the word buffer
	m_wordOffset = 0;
	memset(m_wordBuffer.data(), 0, m_wordBuffer.size() * sizeof(uint));
}

void SHA256::ProcessLength(ulong BitLength)
{
	if (m_wordOffset > 14)
		ProcessBlock();

	m_wordBuffer[14] = (uint)((uint64_t)BitLength >> 32);
	m_wordBuffer[15] = (uint)((uint64_t)BitLength);
}

void SHA256::ProcessWord(const std::vector<byte> &Input, size_t Offset)
{
	m_wordBuffer[m_wordOffset] = CEX::Utility::IntUtils::BytesToBe32(Input, Offset);

	if (++m_wordOffset == 16)
		ProcessBlock();
}

NAMESPACE_DIGESTEND