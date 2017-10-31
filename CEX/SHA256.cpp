#include "SHA256.h"
#include "IntUtils.h"
#include "MemUtils.h"
#include "ParallelUtils.h"
#if defined(__AVX__)
#	include "Intrinsics.h"
#endif

NAMESPACE_DIGEST

using Utility::IntUtils;

const std::string SHA256::CLASS_NAME("SHA256");

//~~~Constructor~~~//

SHA256::SHA256(bool Parallel)
	:
	m_dgtState(Parallel ? DEF_PRLDEGREE : 1),
	m_isDestroyed(false),
	m_msgBuffer(Parallel ? DEF_PRLDEGREE * BLOCK_SIZE : BLOCK_SIZE),
	m_msgLength(0),
	m_parallelProfile(BLOCK_SIZE, false, STATE_PRECACHED, false, DEF_PRLDEGREE),
	m_treeDestroy(true),
	m_treeParams(Parallel ? SHA2Params(DIGEST_SIZE, static_cast<byte>(BLOCK_SIZE), DEF_PRLDEGREE) : SHA2Params(DIGEST_SIZE, 0, 0))
{
	// TODO: implement parallel alternate for single core cpu
	if (Parallel && !m_parallelProfile.IsParallel())
	{
		throw CryptoDigestException("SHA256::Ctor", "Cpu does not support parallel processing!");
	}

	if (m_parallelProfile.IsParallel())
	{
		m_parallelProfile.IsParallel() = Parallel;
	}

	Reset();
}

SHA256::SHA256(SHA2Params &Params)
	:
	m_dgtState(1),
	m_isDestroyed(false),
	m_msgBuffer(BLOCK_SIZE),
	m_msgLength(0),
	m_parallelProfile(BLOCK_SIZE, false, STATE_PRECACHED, false, m_treeParams.FanOut()),
	m_treeDestroy(false),
	m_treeParams(Params)
{
	if (m_treeParams.FanOut() > 1 && !m_parallelProfile.IsParallel())
	{
		throw CryptoDigestException("SHA256::Ctor", "Cpu does not support parallel processing!");
	}

	if (m_treeParams.FanOut() > 1 && m_parallelProfile.IsParallel())
	{
		m_dgtState.resize(m_treeParams.FanOut());
		m_msgBuffer.resize(m_treeParams.FanOut() * BLOCK_SIZE);
	}
	else if (m_parallelProfile.IsParallel())
	{
		m_parallelProfile.IsParallel() = false;
	}

	Reset();
}

SHA256::~SHA256()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_msgLength = 0;
		m_parallelProfile.Reset();

		if (m_treeDestroy)
		{
			m_treeParams.Reset();
			m_treeDestroy = false;
		}

		for (size_t i = 0; i < m_dgtState.size(); ++i)
		{
			m_dgtState[i].Reset();
		}

		IntUtils::ClearVector(m_msgBuffer);
		IntUtils::ClearVector(m_dgtState);
	}
}

//~~~Accessors~~~//

size_t SHA256::BlockSize() 
{ 
	return BLOCK_SIZE; 
}

size_t SHA256::DigestSize() 
{ 
	return DIGEST_SIZE;
}

const Digests SHA256::Enumeral() 
{
	return Digests::SHA256; 
}

const bool SHA256::IsParallel()
{ 
	return m_parallelProfile.IsParallel(); 
}

const std::string SHA256::Name()
{ 
	std::string txtName = "";

	if (m_parallelProfile.IsParallel())
	{
		txtName = CLASS_NAME + "-P" + IntUtils::ToString(m_parallelProfile.ParallelMaxDegree());
	}
	else
	{
		txtName = CLASS_NAME;
	}

	return txtName;
}

const size_t SHA256::ParallelBlockSize()
{ 
	return m_parallelProfile.ParallelBlockSize(); 
}

ParallelOptions &SHA256::ParallelProfile() 
{ 
	return m_parallelProfile; 
}

//~~~Public Functions~~~//

void SHA256::Compute(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Output.resize(DIGEST_SIZE);
	Update(Input, 0, Input.size());
	Finalize(Output, 0);
}

size_t SHA256::Finalize(std::vector<byte> &Output, const size_t OutOffset)
{
	CexAssert(Output.size() - OutOffset >= DIGEST_SIZE, "The Output buffer is too short!");

	if (m_parallelProfile.IsParallel())
	{
		// pad buffer with zeros
		if (m_msgLength < m_msgBuffer.size())
		{
			Utility::MemUtils::Clear(m_msgBuffer, m_msgLength, m_msgBuffer.size() - m_msgLength);
		}

		// process buffer
		if (m_msgLength != 0)
		{
			size_t blkCtr = 0;

			while (m_msgLength != 0)
			{
				const size_t MSGRMD = (m_msgLength >= BLOCK_SIZE) ? BLOCK_SIZE : m_msgLength;
				HashFinal(m_msgBuffer, blkCtr * BLOCK_SIZE, MSGRMD, m_dgtState[blkCtr]);
				m_msgLength -= MSGRMD;
				++blkCtr;
			}
		}

		// initialize root state
		SHA256State rootState;
		rootState.Reset();

		// add state blocks as contiguous message input
		for (size_t i = 0; i < m_dgtState.size(); ++i)
		{
			IntUtils::BeUL256ToBlock(m_dgtState[i].H, 0, m_msgBuffer, i * BLOCK_SIZE);
			m_msgLength += DIGEST_SIZE;
		}

		// compress full blocks
		size_t blkOff = 0;
		if (m_msgLength > BLOCK_SIZE)
		{
			const size_t BLKRMD = m_msgLength - (m_msgLength % BLOCK_SIZE);

			for (size_t i = 0; i < BLKRMD / BLOCK_SIZE; ++i)
			{
				Compress(m_msgBuffer, i * BLOCK_SIZE, rootState);
			}

			m_msgLength -= BLKRMD;
			blkOff = BLKRMD;
		}

		// finalize and store
		HashFinal(m_msgBuffer, blkOff, m_msgLength, rootState);
		IntUtils::BeUL256ToBlock(rootState.H, 0, Output, OutOffset);
	}
	else
	{
		// finalize and store
		HashFinal(m_msgBuffer, 0, m_msgLength, m_dgtState[0]);
		IntUtils::BeUL256ToBlock(m_dgtState[0].H, 0, Output, OutOffset);
	}

	Reset();

	return DIGEST_SIZE;
}

void SHA256::ParallelMaxDegree(size_t Degree)
{
	CexAssert(Degree != 0, "parallel degree can not be zero");
	CexAssert(Degree % 2 == 0, "parallel degree must be an even number");
	CexAssert(Degree <= m_parallelProfile.ProcessorCount(), "parallel degree can not exceed processor count");

	m_parallelProfile.SetMaxDegree(Degree);
	m_dgtState.clear();
	m_dgtState.resize(Degree);
	m_msgBuffer.clear();
	m_msgBuffer.resize(Degree * BLOCK_SIZE);

	Reset();
}

void SHA256::Reset()
{
	m_msgLength = 0;
	Utility::MemUtils::Clear(m_msgBuffer, 0, m_msgBuffer.size());

	for (size_t i = 0; i < m_dgtState.size(); ++i)
	{
		m_dgtState[i].Reset();

		if (m_parallelProfile.IsParallel())
		{
			m_treeParams.NodeOffset() = static_cast<uint>(i);
			Compress(m_treeParams.ToBytes(), 0, m_dgtState[i]);
		}
	}
}

void SHA256::Update(byte Input)
{
	std::vector<byte> inp(1, Input);
	Update(inp, 0, 1);
}

void SHA256::Update(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	CexAssert(Input.size() - InOffset >= Length, "The Output buffer is too short!");

	if (Length != 0)
	{
		if (m_parallelProfile.IsParallel())
		{
			if (m_msgLength != 0 && Length + m_msgLength >= m_msgBuffer.size())
			{
				// fill buffer
				const size_t RMDLEN = m_msgBuffer.size() - m_msgLength;
				if (RMDLEN != 0)
				{
					Utility::MemUtils::Copy(Input, InOffset, m_msgBuffer, m_msgLength, RMDLEN);
				}

				// empty the message buffer
				Utility::ParallelUtils::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Input, InOffset](size_t i)
				{
					Compress(m_msgBuffer, i * BLOCK_SIZE, m_dgtState[i]);
				});

				m_msgLength = 0;
				Length -= RMDLEN;
				InOffset += RMDLEN;
			}

			if (Length >= m_parallelProfile.ParallelBlockSize())
			{
				// calculate working set size
				const size_t PRCLEN = Length - (Length % m_parallelProfile.ParallelBlockSize());

				// process large blocks
				Utility::ParallelUtils::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Input, InOffset, PRCLEN](size_t i)
				{
					ProcessLeaf(Input, InOffset + (i * BLOCK_SIZE), m_dgtState[i], PRCLEN);
				});

				Length -= PRCLEN;
				InOffset += PRCLEN;
			}

			if (Length >= m_parallelProfile.ParallelMinimumSize())
			{
				const size_t PRMLEN = Length - (Length % m_parallelProfile.ParallelMinimumSize());

				Utility::ParallelUtils::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Input, InOffset, PRMLEN](size_t i)
				{
					ProcessLeaf(Input, InOffset + (i * BLOCK_SIZE), m_dgtState[i], PRMLEN);
				});

				Length -= PRMLEN;
				InOffset += PRMLEN;
			}
		}
		else
		{
			if (m_msgLength != 0 && (m_msgLength + Length >= BLOCK_SIZE))
			{
				const size_t RMDLEN = BLOCK_SIZE - m_msgLength;
				if (RMDLEN != 0)
				{
					Utility::MemUtils::Copy(Input, InOffset, m_msgBuffer, m_msgLength, RMDLEN);
				}

				Compress(m_msgBuffer, 0, m_dgtState[0]);
				m_msgLength = 0;
				InOffset += RMDLEN;
				Length -= RMDLEN;
			}

			// sequential loop through blocks
			while (Length > BLOCK_SIZE)
			{
				Compress(Input, InOffset, m_dgtState[0]);
				InOffset += BLOCK_SIZE;
				Length -= BLOCK_SIZE;
			}
		}

		// store unaligned bytes
		if (Length != 0)
		{
			Utility::MemUtils::Copy(Input, InOffset, m_msgBuffer, m_msgLength, Length);
			m_msgLength += Length;
		}
	}
}

//~~~Private Functions~~~//

uint SHA256::BigSigma0(uint W)
{
	return ((W >> 2) | (W << 30)) ^ ((W >> 13) | (W << 19)) ^ ((W >> 22) | (W << 10));
}

uint SHA256::BigSigma1(uint W)
{
	return ((W >> 6) | (W << 26)) ^ ((W >> 11) | (W << 21)) ^ ((W >> 25) | (W << 7));
}

uint SHA256::Ch(uint B, uint C, uint D)
{
	return (B & C) ^ (~B & D);
}

void SHA256::Compress(const std::vector<byte> &Input, size_t InOffset, SHA256State &State)
{
	if (m_parallelProfile.HasSHA2())
	{
		Compress64W(Input, InOffset, State);
	}
	else
	{
		Compress64(Input, InOffset, State);
	}
}

void SHA256::Compress64(const std::vector<byte> &Input, size_t InOffset, SHA256State &Output)
{
	uint A = Output.H[0];
	uint B = Output.H[1];
	uint C = Output.H[2];
	uint D = Output.H[3];
	uint E = Output.H[4];
	uint F = Output.H[5];
	uint G = Output.H[6];
	uint H = Output.H[7];
	uint W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14, W15;

	W0 = IntUtils::BeBytesTo32(Input, InOffset);
	Round(A, B, C, D, E, F, G, H, W0, 0x428A2F98);
	W1 = IntUtils::BeBytesTo32(Input, InOffset + 4);
	Round(H, A, B, C, D, E, F, G, W1, 0x71374491);
	W2 = IntUtils::BeBytesTo32(Input, InOffset + 8);
	Round(G, H, A, B, C, D, E, F, W2, 0xB5C0FBCF);
	W3 = IntUtils::BeBytesTo32(Input, InOffset + 12);
	Round(F, G, H, A, B, C, D, E, W3, 0xE9B5DBA5);
	W4 = IntUtils::BeBytesTo32(Input, InOffset + 16);
	Round(E, F, G, H, A, B, C, D, W4, 0x3956C25B);
	W5 = IntUtils::BeBytesTo32(Input, InOffset + 20);
	Round(D, E, F, G, H, A, B, C, W5, 0x59F111F1);
	W6 = IntUtils::BeBytesTo32(Input, InOffset + 24);
	Round(C, D, E, F, G, H, A, B, W6, 0x923F82A4);
	W7 = IntUtils::BeBytesTo32(Input, InOffset + 28);
	Round(B, C, D, E, F, G, H, A, W7, 0xAB1C5ED5);
	W8 = IntUtils::BeBytesTo32(Input, InOffset + 32);
	Round(A, B, C, D, E, F, G, H, W8, 0xD807AA98);
	W9 = IntUtils::BeBytesTo32(Input, InOffset + 36);
	Round(H, A, B, C, D, E, F, G, W9, 0x12835B01);
	W10 = IntUtils::BeBytesTo32(Input, InOffset + 40);
	Round(G, H, A, B, C, D, E, F, W10, 0x243185BE);
	W11 = IntUtils::BeBytesTo32(Input, InOffset + 44);
	Round(F, G, H, A, B, C, D, E, W11, 0x550C7DC3);
	W12 = IntUtils::BeBytesTo32(Input, InOffset + 48);
	Round(E, F, G, H, A, B, C, D, W12, 0x72BE5D74);
	W13 = IntUtils::BeBytesTo32(Input, InOffset + 52);
	Round(D, E, F, G, H, A, B, C, W13, 0x80DEB1FE);
	W14 = IntUtils::BeBytesTo32(Input, InOffset + 56);
	Round(C, D, E, F, G, H, A, B, W14, 0x9BDC06A7);
	W15 = IntUtils::BeBytesTo32(Input, InOffset + 60);
	Round(B, C, D, E, F, G, H, A, W15, 0xC19BF174);

	W0 += Sigma1(W14) + W9 + Sigma0(W1);
	Round(A, B, C, D, E, F, G, H, W0, 0xE49B69C1);
	W1 += Sigma1(W15) + W10 + Sigma0(W2);
	Round(H, A, B, C, D, E, F, G, W1, 0xEFBE4786);
	W2 += Sigma1(W0) + W11 + Sigma0(W3);
	Round(G, H, A, B, C, D, E, F, W2, 0x0FC19DC6);
	W3 += Sigma1(W1) + W12 + Sigma0(W4);
	Round(F, G, H, A, B, C, D, E, W3, 0x240CA1CC);
	W4 += Sigma1(W2) + W13 + Sigma0(W5);
	Round(E, F, G, H, A, B, C, D, W4, 0x2DE92C6F);
	W5 += Sigma1(W3) + W14 + Sigma0(W6);
	Round(D, E, F, G, H, A, B, C, W5, 0x4A7484AA);
	W6 += Sigma1(W4) + W15 + Sigma0(W7);
	Round(C, D, E, F, G, H, A, B, W6, 0x5CB0A9DC);
	W7 += Sigma1(W5) + W0 + Sigma0(W8);
	Round(B, C, D, E, F, G, H, A, W7, 0x76F988DA);
	W8 += Sigma1(W6) + W1 + Sigma0(W9);
	Round(A, B, C, D, E, F, G, H, W8, 0x983E5152);
	W9 += Sigma1(W7) + W2 + Sigma0(W10);
	Round(H, A, B, C, D, E, F, G, W9, 0xA831C66D);
	W10 += Sigma1(W8) + W3 + Sigma0(W11);
	Round(G, H, A, B, C, D, E, F, W10, 0xB00327C8);
	W11 += Sigma1(W9) + W4 + Sigma0(W12);
	Round(F, G, H, A, B, C, D, E, W11, 0xBF597FC7);
	W12 += Sigma1(W10) + W5 + Sigma0(W13);
	Round(E, F, G, H, A, B, C, D, W12, 0xC6E00BF3);
	W13 += Sigma1(W11) + W6 + Sigma0(W14);
	Round(D, E, F, G, H, A, B, C, W13, 0xD5A79147);
	W14 += Sigma1(W12) + W7 + Sigma0(W15);
	Round(C, D, E, F, G, H, A, B, W14, 0x06CA6351);
	W15 += Sigma1(W13) + W8 + Sigma0(W0);
	Round(B, C, D, E, F, G, H, A, W15, 0x14292967);

	W0 += Sigma1(W14) + W9 + Sigma0(W1);
	Round(A, B, C, D, E, F, G, H, W0, 0x27B70A85);
	W1 += Sigma1(W15) + W10 + Sigma0(W2);
	Round(H, A, B, C, D, E, F, G, W1, 0x2E1B2138);
	W2 += Sigma1(W0) + W11 + Sigma0(W3);
	Round(G, H, A, B, C, D, E, F, W2, 0x4D2C6DFC);
	W3 += Sigma1(W1) + W12 + Sigma0(W4);
	Round(F, G, H, A, B, C, D, E, W3, 0x53380D13);
	W4 += Sigma1(W2) + W13 + Sigma0(W5);
	Round(E, F, G, H, A, B, C, D, W4, 0x650A7354);
	W5 += Sigma1(W3) + W14 + Sigma0(W6);
	Round(D, E, F, G, H, A, B, C, W5, 0x766A0ABB);
	W6 += Sigma1(W4) + W15 + Sigma0(W7);
	Round(C, D, E, F, G, H, A, B, W6, 0x81C2C92E);
	W7 += Sigma1(W5) + W0 + Sigma0(W8);
	Round(B, C, D, E, F, G, H, A, W7, 0x92722C85);
	W8 += Sigma1(W6) + W1 + Sigma0(W9);
	Round(A, B, C, D, E, F, G, H, W8, 0xA2BFE8A1);
	W9 += Sigma1(W7) + W2 + Sigma0(W10);
	Round(H, A, B, C, D, E, F, G, W9, 0xA81A664B);
	W10 += Sigma1(W8) + W3 + Sigma0(W11);
	Round(G, H, A, B, C, D, E, F, W10, 0xC24B8B70);
	W11 += Sigma1(W9) + W4 + Sigma0(W12);
	Round(F, G, H, A, B, C, D, E, W11, 0xC76C51A3);
	W12 += Sigma1(W10) + W5 + Sigma0(W13);
	Round(E, F, G, H, A, B, C, D, W12, 0xD192E819);
	W13 += Sigma1(W11) + W6 + Sigma0(W14);
	Round(D, E, F, G, H, A, B, C, W13, 0xD6990624);
	W14 += Sigma1(W12) + W7 + Sigma0(W15);
	Round(C, D, E, F, G, H, A, B, W14, 0xF40E3585);
	W15 += Sigma1(W13) + W8 + Sigma0(W0);
	Round(B, C, D, E, F, G, H, A, W15, 0x106AA070);

	W0 += Sigma1(W14) + W9 + Sigma0(W1);
	Round(A, B, C, D, E, F, G, H, W0, 0x19A4C116);
	W1 += Sigma1(W15) + W10 + Sigma0(W2);
	Round(H, A, B, C, D, E, F, G, W1, 0x1E376C08);
	W2 += Sigma1(W0) + W11 + Sigma0(W3);
	Round(G, H, A, B, C, D, E, F, W2, 0x2748774C);
	W3 += Sigma1(W1) + W12 + Sigma0(W4);
	Round(F, G, H, A, B, C, D, E, W3, 0x34B0BCB5);
	W4 += Sigma1(W2) + W13 + Sigma0(W5);
	Round(E, F, G, H, A, B, C, D, W4, 0x391C0CB3);
	W5 += Sigma1(W3) + W14 + Sigma0(W6);
	Round(D, E, F, G, H, A, B, C, W5, 0x4ED8AA4A);
	W6 += Sigma1(W4) + W15 + Sigma0(W7);
	Round(C, D, E, F, G, H, A, B, W6, 0x5B9CCA4F);
	W7 += Sigma1(W5) + W0 + Sigma0(W8);
	Round(B, C, D, E, F, G, H, A, W7, 0x682E6FF3);
	W8 += Sigma1(W6) + W1 + Sigma0(W9);
	Round(A, B, C, D, E, F, G, H, W8, 0x748F82EE);
	W9 += Sigma1(W7) + W2 + Sigma0(W10);
	Round(H, A, B, C, D, E, F, G, W9, 0x78A5636F);
	W10 += Sigma1(W8) + W3 + Sigma0(W11);
	Round(G, H, A, B, C, D, E, F, W10, 0x84C87814);
	W11 += Sigma1(W9) + W4 + Sigma0(W12);
	Round(F, G, H, A, B, C, D, E, W11, 0x8CC70208);
	W12 += Sigma1(W10) + W5 + Sigma0(W13);
	Round(E, F, G, H, A, B, C, D, W12, 0x90BEFFFA);
	W13 += Sigma1(W11) + W6 + Sigma0(W14);
	Round(D, E, F, G, H, A, B, C, W13, 0xA4506CEB);
	W14 += Sigma1(W12) + W7 + Sigma0(W15);
	Round(C, D, E, F, G, H, A, B, W14, 0xBEF9A3F7);
	W15 += Sigma1(W13) + W8 + Sigma0(W0);
	Round(B, C, D, E, F, G, H, A, W15, 0xC67178F2);

	Output.H[0] += A;
	Output.H[1] += B;
	Output.H[2] += C;
	Output.H[3] += D;
	Output.H[4] += E;
	Output.H[5] += F;
	Output.H[6] += G;
	Output.H[7] += H;

	Output.T += BLOCK_SIZE;
}

void SHA256::Compress64W(const std::vector<byte> &Input, size_t InOffset, SHA256State &Output)
{
#if defined(__AVX__)
	__m128i S0, S1, T0, T1;
	__m128i MSG, TMP, MASK;
	__m128i M0, M1, M2, M3;

	// Load initial values
	TMP = _mm_loadu_si128(reinterpret_cast<__m128i*>(&Output.H));
	S1 = _mm_loadu_si128(reinterpret_cast<__m128i*>(&Output.H[4]));
	MASK = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);
	TMP = _mm_shuffle_epi32(TMP, 0xB1);  // CDAB
	S1 = _mm_shuffle_epi32(S1, 0x1B);    // EFGH
	S0 = _mm_alignr_epi8(TMP, S1, 8);    // ABEF
	S1 = _mm_blend_epi16(S1, TMP, 0xF0); // CDGH
			
	T0 = S0; // Save current state
	T1 = S1;

	// Rounds 0-3
	MSG = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset]));
	M0 = _mm_shuffle_epi8(MSG, MASK);
	MSG = _mm_add_epi32(M0, _mm_set_epi64x(0xE9B5DBA5B5C0FBCFULL, 0x71374491428A2F98ULL));
	S1 = _mm_sha256rnds2_epu32(S1, S0, MSG);
	MSG = _mm_shuffle_epi32(MSG, 0x0E);
	S0 = _mm_sha256rnds2_epu32(S0, S1, MSG);

	// Rounds 4-7
	M1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset + 16]));
	M1 = _mm_shuffle_epi8(M1, MASK);
	MSG = _mm_add_epi32(M1, _mm_set_epi64x(0xAB1C5ED5923F82A4ULL, 0x59F111F13956C25BULL));
	S1 = _mm_sha256rnds2_epu32(S1, S0, MSG);
	MSG = _mm_shuffle_epi32(MSG, 0x0E);
	S0 = _mm_sha256rnds2_epu32(S0, S1, MSG);
	M0 = _mm_sha256msg1_epu32(M0, M1);

	// Rounds 8-11
	M2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset + 32]));
	M2 = _mm_shuffle_epi8(M2, MASK);
	MSG = _mm_add_epi32(M2, _mm_set_epi64x(0x550C7DC3243185BEULL, 0x12835B01D807AA98ULL));
	S1 = _mm_sha256rnds2_epu32(S1, S0, MSG);
	MSG = _mm_shuffle_epi32(MSG, 0x0E);
	S0 = _mm_sha256rnds2_epu32(S0, S1, MSG);
	M1 = _mm_sha256msg1_epu32(M1, M2);

	// Rounds 12-15
	M3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset + 48]));
	M3 = _mm_shuffle_epi8(M3, MASK);
	MSG = _mm_add_epi32(M3, _mm_set_epi64x(0xC19BF1749BDC06A7ULL, 0x80DEB1FE72BE5D74ULL));
	S1 = _mm_sha256rnds2_epu32(S1, S0, MSG);
	TMP = _mm_alignr_epi8(M3, M2, 4);
	M0 = _mm_add_epi32(M0, TMP);
	M0 = _mm_sha256msg2_epu32(M0, M3);
	MSG = _mm_shuffle_epi32(MSG, 0x0E);
	S0 = _mm_sha256rnds2_epu32(S0, S1, MSG);
	M2 = _mm_sha256msg1_epu32(M2, M3);

	// Rounds 16-19
	MSG = _mm_add_epi32(M0, _mm_set_epi64x(0x240CA1CC0FC19DC6ULL, 0xEFBE4786E49B69C1ULL));
	S1 = _mm_sha256rnds2_epu32(S1, S0, MSG);
	TMP = _mm_alignr_epi8(M0, M3, 4);
	M1 = _mm_add_epi32(M1, TMP);
	M1 = _mm_sha256msg2_epu32(M1, M0);
	MSG = _mm_shuffle_epi32(MSG, 0x0E);
	S0 = _mm_sha256rnds2_epu32(S0, S1, MSG);
	M3 = _mm_sha256msg1_epu32(M3, M0);

	// Rounds 20-23
	MSG = _mm_add_epi32(M1, _mm_set_epi64x(0x76F988DA5CB0A9DCULL, 0x4A7484AA2DE92C6FULL));
	S1 = _mm_sha256rnds2_epu32(S1, S0, MSG);
	TMP = _mm_alignr_epi8(M1, M0, 4);
	M2 = _mm_add_epi32(M2, TMP);
	M2 = _mm_sha256msg2_epu32(M2, M1);
	MSG = _mm_shuffle_epi32(MSG, 0x0E);
	S0 = _mm_sha256rnds2_epu32(S0, S1, MSG);
	M0 = _mm_sha256msg1_epu32(M0, M1);

	// Rounds 24-27
	MSG = _mm_add_epi32(M2, _mm_set_epi64x(0xBF597FC7B00327C8ULL, 0xA831C66D983E5152ULL));
	S1 = _mm_sha256rnds2_epu32(S1, S0, MSG);
	TMP = _mm_alignr_epi8(M2, M1, 4);
	M3 = _mm_add_epi32(M3, TMP);
	M3 = _mm_sha256msg2_epu32(M3, M2);
	MSG = _mm_shuffle_epi32(MSG, 0x0E);
	S0 = _mm_sha256rnds2_epu32(S0, S1, MSG);
	M1 = _mm_sha256msg1_epu32(M1, M2);

	// Rounds 28-31
	MSG = _mm_add_epi32(M3, _mm_set_epi64x(0x1429296706CA6351ULL, 0xD5A79147C6E00BF3ULL));
	S1 = _mm_sha256rnds2_epu32(S1, S0, MSG);
	TMP = _mm_alignr_epi8(M3, M2, 4);
	M0 = _mm_add_epi32(M0, TMP);
	M0 = _mm_sha256msg2_epu32(M0, M3);
	MSG = _mm_shuffle_epi32(MSG, 0x0E);
	S0 = _mm_sha256rnds2_epu32(S0, S1, MSG);
	M2 = _mm_sha256msg1_epu32(M2, M3);

	// Rounds 32-35
	MSG = _mm_add_epi32(M0, _mm_set_epi64x(0x53380D134D2C6DFCULL, 0x2E1B213827B70A85ULL));
	S1 = _mm_sha256rnds2_epu32(S1, S0, MSG);
	TMP = _mm_alignr_epi8(M0, M3, 4);
	M1 = _mm_add_epi32(M1, TMP);
	M1 = _mm_sha256msg2_epu32(M1, M0);
	MSG = _mm_shuffle_epi32(MSG, 0x0E);
	S0 = _mm_sha256rnds2_epu32(S0, S1, MSG);
	M3 = _mm_sha256msg1_epu32(M3, M0);

	// Rounds 36-39
	MSG = _mm_add_epi32(M1, _mm_set_epi64x(0x92722C8581C2C92EULL, 0x766A0ABB650A7354ULL));
	S1 = _mm_sha256rnds2_epu32(S1, S0, MSG);
	TMP = _mm_alignr_epi8(M1, M0, 4);
	M2 = _mm_add_epi32(M2, TMP);
	M2 = _mm_sha256msg2_epu32(M2, M1);
	MSG = _mm_shuffle_epi32(MSG, 0x0E);
	S0 = _mm_sha256rnds2_epu32(S0, S1, MSG);
	M0 = _mm_sha256msg1_epu32(M0, M1);

	// Rounds 40-43
	MSG = _mm_add_epi32(M2, _mm_set_epi64x(0xC76C51A3C24B8B70ULL, 0xA81A664BA2BFE8A1ULL));
	S1 = _mm_sha256rnds2_epu32(S1, S0, MSG);
	TMP = _mm_alignr_epi8(M2, M1, 4);
	M3 = _mm_add_epi32(M3, TMP);
	M3 = _mm_sha256msg2_epu32(M3, M2);
	MSG = _mm_shuffle_epi32(MSG, 0x0E);
	S0 = _mm_sha256rnds2_epu32(S0, S1, MSG);
	M1 = _mm_sha256msg1_epu32(M1, M2);

	// Rounds 44-47
	MSG = _mm_add_epi32(M3, _mm_set_epi64x(0x106AA070F40E3585ULL, 0xD6990624D192E819ULL));
	S1 = _mm_sha256rnds2_epu32(S1, S0, MSG);
	TMP = _mm_alignr_epi8(M3, M2, 4);
	M0 = _mm_add_epi32(M0, TMP);
	M0 = _mm_sha256msg2_epu32(M0, M3);
	MSG = _mm_shuffle_epi32(MSG, 0x0E);
	S0 = _mm_sha256rnds2_epu32(S0, S1, MSG);
	M2 = _mm_sha256msg1_epu32(M2, M3);

	// Rounds 48-51
	MSG = _mm_add_epi32(M0, _mm_set_epi64x(0x34B0BCB52748774CULL, 0x1E376C0819A4C116ULL));
	S1 = _mm_sha256rnds2_epu32(S1, S0, MSG);
	TMP = _mm_alignr_epi8(M0, M3, 4);
	M1 = _mm_add_epi32(M1, TMP);
	M1 = _mm_sha256msg2_epu32(M1, M0);
	MSG = _mm_shuffle_epi32(MSG, 0x0E);
	S0 = _mm_sha256rnds2_epu32(S0, S1, MSG);
	M3 = _mm_sha256msg1_epu32(M3, M0);

	// Rounds 52-55
	MSG = _mm_add_epi32(M1, _mm_set_epi64x(0x682E6FF35B9CCA4FULL, 0x4ED8AA4A391C0CB3ULL));
	S1 = _mm_sha256rnds2_epu32(S1, S0, MSG);
	TMP = _mm_alignr_epi8(M1, M0, 4);
	M2 = _mm_add_epi32(M2, TMP);
	M2 = _mm_sha256msg2_epu32(M2, M1);
	MSG = _mm_shuffle_epi32(MSG, 0x0E);
	S0 = _mm_sha256rnds2_epu32(S0, S1, MSG);

	// Rounds 56-59
	MSG = _mm_add_epi32(M2, _mm_set_epi64x(0x8CC7020884C87814ULL, 0x78A5636F748F82EEULL));
	S1 = _mm_sha256rnds2_epu32(S1, S0, MSG);
	TMP = _mm_alignr_epi8(M2, M1, 4);
	M3 = _mm_add_epi32(M3, TMP);
	M3 = _mm_sha256msg2_epu32(M3, M2);
	MSG = _mm_shuffle_epi32(MSG, 0x0E);
	S0 = _mm_sha256rnds2_epu32(S0, S1, MSG);

	// Rounds 60-63
	MSG = _mm_add_epi32(M3, _mm_set_epi64x(0xC67178F2BEF9A3F7ULL, 0xA4506CEB90BEFFFAULL));
	S1 = _mm_sha256rnds2_epu32(S1, S0, MSG);
	MSG = _mm_shuffle_epi32(MSG, 0x0E);
	S0 = _mm_sha256rnds2_epu32(S0, S1, MSG);

	// Combine state 
	S0 = _mm_add_epi32(S0, T0);
	S1 = _mm_add_epi32(S1, T1);
	TMP = _mm_shuffle_epi32(S0, 0x1B);   // FEBA
	S1 = _mm_shuffle_epi32(S1, 0xB1);    // DCHG
	S0 = _mm_blend_epi16(TMP, S1, 0xF0); // DCBA
	S1 = _mm_alignr_epi8(S1, TMP, 8);    // ABEF

	// Save state
	_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output.H[0]), S0);
	_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output.H[4]), S1);
#else
	Compress64(Input, InOffset, Output);
#endif
}

void SHA256::HashFinal(std::vector<byte> &Input, size_t InOffset, size_t Length, SHA256State &State)
{
	State.T += Length;
	ulong bitLen = (State.T << 3);

	if (Length == BLOCK_SIZE)
	{
		Compress(Input, InOffset, State);
		Length = 0;
	}

	Input[InOffset + Length] = 128;
	++Length;

	// padding
	if (Length < BLOCK_SIZE)
	{
		Utility::MemUtils::Clear(Input, InOffset + Length, BLOCK_SIZE - Length);
	}

	if (Length > 56)
	{
		Compress(Input, InOffset, State);
		Utility::MemUtils::Clear(Input, 0, BLOCK_SIZE);
	}

	// finalize state with counter and last compression
	IntUtils::Be32ToBytes(static_cast<uint>(static_cast<ulong>(bitLen) >> 32), Input, InOffset + 56);
	IntUtils::Be32ToBytes(static_cast<uint>(static_cast<ulong>(bitLen)), Input, InOffset + 60);
	Compress(Input, InOffset, State);
}

uint SHA256::Maj(uint B, uint C, uint D)
{
	return (B & C) ^ (B & D) ^ (C & D);
}

void SHA256::ProcessLeaf(const std::vector<byte> &Input, size_t InOffset, SHA256State &State, ulong Length)
{
	do
	{
		Compress(Input, InOffset, State);
		InOffset += m_parallelProfile.ParallelMinimumSize();
		Length -= m_parallelProfile.ParallelMinimumSize();
	} 
	while (Length > 0);
}

void SHA256::Round(uint A, uint B, uint C, uint &D, uint E, uint F, uint G, uint &H, uint M, uint P)
{
	uint R0(H + BigSigma1(E) + Ch(E, F, G) + P + M);
	D += R0;
	H = R0 + (BigSigma0(A) + Maj(A, B, C));
}

uint SHA256::Sigma0(uint W)
{
	return ((W >> 7) | (W << 25)) ^ ((W >> 18) | (W << 14)) ^ (W >> 3);
}

uint SHA256::Sigma1(uint W)
{
	return ((W >> 17) | (W << 15)) ^ ((W >> 19) | (W << 13)) ^ (W >> 10);
}

NAMESPACE_DIGESTEND