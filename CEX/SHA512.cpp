#include "SHA512.h"
#include "IntUtils.h"
#include "MemUtils.h"
#include "ParallelUtils.h"

NAMESPACE_DIGEST

using Utility::IntUtils;

const std::string SHA512::CLASS_NAME("SHA512");

//~~~Constructor~~~//

SHA512::SHA512(bool Parallel)
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
		throw CryptoDigestException("SHA512::Ctor", "Cpu does not support parallel processing!");
	}

	if (m_parallelProfile.IsParallel())
	{
		m_parallelProfile.IsParallel() = Parallel;
	}

	Reset();
}

SHA512::SHA512(SHA2Params &Params)
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
		throw CryptoDigestException("SHA512::Ctor", "Cpu does not support parallel processing!");
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

SHA512::~SHA512()
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

		IntUtils::ClearVector(m_dgtState);
		IntUtils::ClearVector(m_msgBuffer);
	}
}

//~~~Accessors~~~//

size_t SHA512::BlockSize() 
{ 
	return BLOCK_SIZE; 
}

size_t SHA512::DigestSize() 
{ 
	return DIGEST_SIZE; 
}

const Digests SHA512::Enumeral()
{ 
	return Digests::SHA512; 
}

const bool SHA512::IsParallel() 
{ 
	return m_parallelProfile.IsParallel(); 
}

const std::string SHA512::Name() 
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

const size_t SHA512::ParallelBlockSize() 
{ 
	return m_parallelProfile.ParallelBlockSize(); 
}

ParallelOptions &SHA512::ParallelProfile()
{
	return m_parallelProfile; 
}

//~~~Public Functions~~~//

void SHA512::Compute(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Output.resize(DIGEST_SIZE);
	Update(Input, 0, Input.size());
	Finalize(Output, 0);
}

void SHA512::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_msgLength = 0;

		for (size_t i = 0; i < m_dgtState.size(); ++i)
		{
			m_dgtState[i].Reset();
		}

		IntUtils::ClearVector(m_dgtState);
		IntUtils::ClearVector(m_msgBuffer);
	}
}

size_t SHA512::Finalize(std::vector<byte> &Output, const size_t OutOffset)
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
		SHA512State rootState;
		rootState.Reset();

		// add state blocks as contiguous message input
		for (size_t i = 0; i < m_dgtState.size(); ++i)
		{
			IntUtils::BeULL512ToBlock(m_dgtState[i].H, 0, m_msgBuffer, i * BLOCK_SIZE);
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
		IntUtils::BeULL512ToBlock(rootState.H, 0, Output, OutOffset);
	}
	else
	{
		// finalize and store
		HashFinal(m_msgBuffer, 0, m_msgLength, m_dgtState[0]);
		IntUtils::BeULL512ToBlock(m_dgtState[0].H, 0, Output, OutOffset);
	}

	Reset();

	return DIGEST_SIZE;
}

void SHA512::ParallelMaxDegree(size_t Degree)
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

void SHA512::Reset()
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

void SHA512::Update(byte Input)
{
	std::vector<byte> inp(1, Input);
	Update(inp, 0, 1);
}

void SHA512::Update(const std::vector<byte> &Input, size_t InOffset, size_t Length)
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

ulong SHA512::BigSigma0(ulong W)
{
	return ((W << 36) | (W >> 28)) ^ ((W << 30) | (W >> 34)) ^ ((W << 25) | (W >> 39));
}

ulong SHA512::BigSigma1(ulong W)
{
	return ((W << 50) | (W >> 14)) ^ ((W << 46) | (W >> 18)) ^ ((W << 23) | (W >> 41));
}

ulong SHA512::Ch(ulong B, ulong C, ulong D)
{
	return (B & C) ^ (~B & D);
}

void SHA512::Compress(const std::vector<byte> &Input, size_t InOffset, SHA512State &State)
{
	ulong A = State.H[0];
	ulong B = State.H[1];
	ulong C = State.H[2];
	ulong D = State.H[3];
	ulong E = State.H[4];
	ulong F = State.H[5];
	ulong G = State.H[6];
	ulong H = State.H[7];
	ulong W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14, W15;

	W0 = IntUtils::BeBytesTo64(Input, InOffset);
	Round(A, B, C, D, E, F, G, H, W0, 0x428A2F98D728AE22);
	W1 = IntUtils::BeBytesTo64(Input, InOffset + 8);
	Round(H, A, B, C, D, E, F, G, W1, 0x7137449123EF65CD);
	W2 = IntUtils::BeBytesTo64(Input, InOffset + 16);
	Round(G, H, A, B, C, D, E, F, W2, 0xB5C0FBCFEC4D3B2F);
	W3 = IntUtils::BeBytesTo64(Input, InOffset + 24);
	Round(F, G, H, A, B, C, D, E, W3, 0xE9B5DBA58189DBBC);
	W4 = IntUtils::BeBytesTo64(Input, InOffset + 32);
	Round(E, F, G, H, A, B, C, D, W4, 0x3956C25BF348B538);
	W5 = IntUtils::BeBytesTo64(Input, InOffset + 40);
	Round(D, E, F, G, H, A, B, C, W5, 0x59F111F1B605D019);
	W6 = IntUtils::BeBytesTo64(Input, InOffset + 48);
	Round(C, D, E, F, G, H, A, B, W6, 0x923F82A4AF194F9B);
	W7 = IntUtils::BeBytesTo64(Input, InOffset + 56);
	Round(B, C, D, E, F, G, H, A, W7, 0xAB1C5ED5DA6D8118);
	W8 = IntUtils::BeBytesTo64(Input, InOffset + 64);
	Round(A, B, C, D, E, F, G, H, W8, 0xD807AA98A3030242);
	W9 = IntUtils::BeBytesTo64(Input, InOffset + 72);
	Round(H, A, B, C, D, E, F, G, W9, 0x12835B0145706FBE);
	W10 = IntUtils::BeBytesTo64(Input, InOffset + 80);
	Round(G, H, A, B, C, D, E, F, W10, 0x243185BE4EE4B28C);
	W11 = IntUtils::BeBytesTo64(Input, InOffset + 88);
	Round(F, G, H, A, B, C, D, E, W11, 0x550C7DC3D5FFB4E2);
	W12 = IntUtils::BeBytesTo64(Input, InOffset + 96);
	Round(E, F, G, H, A, B, C, D, W12, 0x72BE5D74F27B896F);
	W13 = IntUtils::BeBytesTo64(Input, InOffset + 104);
	Round(D, E, F, G, H, A, B, C, W13, 0x80DEB1FE3B1696B1);
	W14 = IntUtils::BeBytesTo64(Input, InOffset + 112);
	Round(C, D, E, F, G, H, A, B, W14, 0x9BDC06A725C71235);
	W15 = IntUtils::BeBytesTo64(Input, InOffset + 120);
	Round(B, C, D, E, F, G, H, A, W15, 0xC19BF174CF692694);

	W0 += Sigma1(W14) + W9 + Sigma0(W1);
	Round(A, B, C, D, E, F, G, H, W0, 0xE49B69C19EF14AD2);
	W1 += Sigma1(W15) + W10 + Sigma0(W2);
	Round(H, A, B, C, D, E, F, G, W1, 0xEFBE4786384F25E3);
	W2 += Sigma1(W0) + W11 + Sigma0(W3);
	Round(G, H, A, B, C, D, E, F, W2, 0x0FC19DC68B8CD5B5);
	W3 += Sigma1(W1) + W12 + Sigma0(W4);
	Round(F, G, H, A, B, C, D, E, W3, 0x240CA1CC77AC9C65);
	W4 += Sigma1(W2) + W13 + Sigma0(W5);
	Round(E, F, G, H, A, B, C, D, W4, 0x2DE92C6F592B0275);
	W5 += Sigma1(W3) + W14 + Sigma0(W6);
	Round(D, E, F, G, H, A, B, C, W5, 0x4A7484AA6EA6E483);
	W6 += Sigma1(W4) + W15 + Sigma0(W7);
	Round(C, D, E, F, G, H, A, B, W6, 0x5CB0A9DCBD41FBD4);
	W7 += Sigma1(W5) + W0 + Sigma0(W8);
	Round(B, C, D, E, F, G, H, A, W7, 0x76F988DA831153B5);
	W8 += Sigma1(W6) + W1 + Sigma0(W9);
	Round(A, B, C, D, E, F, G, H, W8, 0x983E5152EE66DFAB);
	W9 += Sigma1(W7) + W2 + Sigma0(W10);
	Round(H, A, B, C, D, E, F, G, W9, 0xA831C66D2DB43210);
	W10 += Sigma1(W8) + W3 + Sigma0(W11);
	Round(G, H, A, B, C, D, E, F, W10, 0xB00327C898FB213F);
	W11 += Sigma1(W9) + W4 + Sigma0(W12);
	Round(F, G, H, A, B, C, D, E, W11, 0xBF597FC7BEEF0EE4);
	W12 += Sigma1(W10) + W5 + Sigma0(W13);
	Round(E, F, G, H, A, B, C, D, W12, 0xC6E00BF33DA88FC2);
	W13 += Sigma1(W11) + W6 + Sigma0(W14);
	Round(D, E, F, G, H, A, B, C, W13, 0xD5A79147930AA725);
	W14 += Sigma1(W12) + W7 + Sigma0(W15);
	Round(C, D, E, F, G, H, A, B, W14, 0x06CA6351E003826F);
	W15 += Sigma1(W13) + W8 + Sigma0(W0);
	Round(B, C, D, E, F, G, H, A, W15, 0x142929670A0E6E70);

	W0 += Sigma1(W14) + W9 + Sigma0(W1);
	Round(A, B, C, D, E, F, G, H, W0, 0x27B70A8546D22FFC);
	W1 += Sigma1(W15) + W10 + Sigma0(W2);
	Round(H, A, B, C, D, E, F, G, W1, 0x2E1B21385C26C926);
	W2 += Sigma1(W0) + W11 + Sigma0(W3);
	Round(G, H, A, B, C, D, E, F, W2, 0x4D2C6DFC5AC42AED);
	W3 += Sigma1(W1) + W12 + Sigma0(W4);
	Round(F, G, H, A, B, C, D, E, W3, 0x53380D139D95B3DF);
	W4 += Sigma1(W2) + W13 + Sigma0(W5);
	Round(E, F, G, H, A, B, C, D, W4, 0x650A73548BAF63DE);
	W5 += Sigma1(W3) + W14 + Sigma0(W6);
	Round(D, E, F, G, H, A, B, C, W5, 0x766A0ABB3C77B2A8);
	W6 += Sigma1(W4) + W15 + Sigma0(W7);
	Round(C, D, E, F, G, H, A, B, W6, 0x81C2C92E47EDAEE6);
	W7 += Sigma1(W5) + W0 + Sigma0(W8);
	Round(B, C, D, E, F, G, H, A, W7, 0x92722C851482353B);
	W8 += Sigma1(W6) + W1 + Sigma0(W9);
	Round(A, B, C, D, E, F, G, H, W8, 0xA2BFE8A14CF10364);
	W9 += Sigma1(W7) + W2 + Sigma0(W10);
	Round(H, A, B, C, D, E, F, G, W9, 0xA81A664BBC423001);
	W10 += Sigma1(W8) + W3 + Sigma0(W11);
	Round(G, H, A, B, C, D, E, F, W10, 0xC24B8B70D0F89791);
	W11 += Sigma1(W9) + W4 + Sigma0(W12);
	Round(F, G, H, A, B, C, D, E, W11, 0xC76C51A30654BE30);
	W12 += Sigma1(W10) + W5 + Sigma0(W13);
	Round(E, F, G, H, A, B, C, D, W12, 0xD192E819D6EF5218);
	W13 += Sigma1(W11) + W6 + Sigma0(W14);
	Round(D, E, F, G, H, A, B, C, W13, 0xD69906245565A910);
	W14 += Sigma1(W12) + W7 + Sigma0(W15);
	Round(C, D, E, F, G, H, A, B, W14, 0xF40E35855771202A);
	W15 += Sigma1(W13) + W8 + Sigma0(W0);
	Round(B, C, D, E, F, G, H, A, W15, 0x106AA07032BBD1B8);

	W0 += Sigma1(W14) + W9 + Sigma0(W1);
	Round(A, B, C, D, E, F, G, H, W0, 0x19A4C116B8D2D0C8);
	W1 += Sigma1(W15) + W10 + Sigma0(W2);
	Round(H, A, B, C, D, E, F, G, W1, 0x1E376C085141AB53);
	W2 += Sigma1(W0) + W11 + Sigma0(W3);
	Round(G, H, A, B, C, D, E, F, W2, 0x2748774CDF8EEB99);
	W3 += Sigma1(W1) + W12 + Sigma0(W4);
	Round(F, G, H, A, B, C, D, E, W3, 0x34B0BCB5E19B48A8);
	W4 += Sigma1(W2) + W13 + Sigma0(W5);
	Round(E, F, G, H, A, B, C, D, W4, 0x391C0CB3C5C95A63);
	W5 += Sigma1(W3) + W14 + Sigma0(W6);
	Round(D, E, F, G, H, A, B, C, W5, 0x4ED8AA4AE3418ACB);
	W6 += Sigma1(W4) + W15 + Sigma0(W7);
	Round(C, D, E, F, G, H, A, B, W6, 0x5B9CCA4F7763E373);
	W7 += Sigma1(W5) + W0 + Sigma0(W8);
	Round(B, C, D, E, F, G, H, A, W7, 0x682E6FF3D6B2B8A3);
	W8 += Sigma1(W6) + W1 + Sigma0(W9);
	Round(A, B, C, D, E, F, G, H, W8, 0x748F82EE5DEFB2FC);
	W9 += Sigma1(W7) + W2 + Sigma0(W10);
	Round(H, A, B, C, D, E, F, G, W9, 0x78A5636F43172F60);
	W10 += Sigma1(W8) + W3 + Sigma0(W11);
	Round(G, H, A, B, C, D, E, F, W10, 0x84C87814A1F0AB72);
	W11 += Sigma1(W9) + W4 + Sigma0(W12);
	Round(F, G, H, A, B, C, D, E, W11, 0x8CC702081A6439EC);
	W12 += Sigma1(W10) + W5 + Sigma0(W13);
	Round(E, F, G, H, A, B, C, D, W12, 0x90BEFFFA23631E28);
	W13 += Sigma1(W11) + W6 + Sigma0(W14);
	Round(D, E, F, G, H, A, B, C, W13, 0xA4506CEBDE82BDE9);
	W14 += Sigma1(W12) + W7 + Sigma0(W15);
	Round(C, D, E, F, G, H, A, B, W14, 0xBEF9A3F7B2C67915);
	W15 += Sigma1(W13) + W8 + Sigma0(W0);
	Round(B, C, D, E, F, G, H, A, W15, 0xC67178F2E372532B);

	W0 += Sigma1(W14) + W9 + Sigma0(W1);
	Round(A, B, C, D, E, F, G, H, W0, 0xCA273ECEEA26619C);
	W1 += Sigma1(W15) + W10 + Sigma0(W2);
	Round(H, A, B, C, D, E, F, G, W1, 0xD186B8C721C0C207);
	W2 += Sigma1(W0) + W11 + Sigma0(W3);
	Round(G, H, A, B, C, D, E, F, W2, 0xEADA7DD6CDE0EB1E);
	W3 += Sigma1(W1) + W12 + Sigma0(W4);
	Round(F, G, H, A, B, C, D, E, W3, 0xF57D4F7FEE6ED178);
	W4 += Sigma1(W2) + W13 + Sigma0(W5);
	Round(E, F, G, H, A, B, C, D, W4, 0x06F067AA72176FBA);
	W5 += Sigma1(W3) + W14 + Sigma0(W6);
	Round(D, E, F, G, H, A, B, C, W5, 0x0A637DC5A2C898A6);
	W6 += Sigma1(W4) + W15 + Sigma0(W7);
	Round(C, D, E, F, G, H, A, B, W6, 0x113F9804BEF90DAE);
	W7 += Sigma1(W5) + W0 + Sigma0(W8);
	Round(B, C, D, E, F, G, H, A, W7, 0x1B710B35131C471B);
	W8 += Sigma1(W6) + W1 + Sigma0(W9);
	Round(A, B, C, D, E, F, G, H, W8, 0x28DB77F523047D84);
	W9 += Sigma1(W7) + W2 + Sigma0(W10);
	Round(H, A, B, C, D, E, F, G, W9, 0x32CAAB7B40C72493);
	W10 += Sigma1(W8) + W3 + Sigma0(W11);
	Round(G, H, A, B, C, D, E, F, W10, 0x3C9EBE0A15C9BEBC);
	W11 += Sigma1(W9) + W4 + Sigma0(W12);
	Round(F, G, H, A, B, C, D, E, W11, 0x431D67C49C100D4C);
	W12 += Sigma1(W10) + W5 + Sigma0(W13);
	Round(E, F, G, H, A, B, C, D, W12, 0x4CC5D4BECB3E42B6);
	W13 += Sigma1(W11) + W6 + Sigma0(W14);
	Round(D, E, F, G, H, A, B, C, W13, 0x597F299CFC657E2A);
	W14 += Sigma1(W12) + W7 + Sigma0(W15);
	Round(C, D, E, F, G, H, A, B, W14, 0x5FCB6FAB3AD6FAEC);
	W15 += Sigma1(W13) + W8 + Sigma0(W0);
	Round(B, C, D, E, F, G, H, A, W15, 0x6C44198C4A475817);

	State.H[0] += A;
	State.H[1] += B;
	State.H[2] += C;
	State.H[3] += D;
	State.H[4] += E;
	State.H[5] += F;
	State.H[6] += G;
	State.H[7] += H;

	State.Increase(BLOCK_SIZE);
}

void SHA512::HashFinal(std::vector<byte> &Input, size_t InOffset, size_t Length, SHA512State &State)
{
	State.Increase(Length);
	ulong bitLen = (State.T[0] << 3);

	if (Length == BLOCK_SIZE)
	{
		Compress(Input, InOffset, State);
		Length = 0;
	}

	Input[InOffset + Length] = 128;
	++Length;

	// padding
	if (Length < BLOCK_SIZE)
		Utility::MemUtils::Clear(Input, InOffset + Length, BLOCK_SIZE - Length);

	if (Length > 112)
	{
		Compress(Input, InOffset, State);
		Utility::MemUtils::Clear(Input, InOffset, BLOCK_SIZE);
	}

	// finalize state with counter and last compression
	IntUtils::Be64ToBytes(State.T[1], Input, InOffset + 112);
	IntUtils::Be64ToBytes(bitLen, Input, InOffset + 120);
	Compress(Input, InOffset, State);
}

ulong SHA512::Maj(ulong B, ulong C, ulong D)
{
	return (B & C) ^ (B & D) ^ (C & D);
}

void SHA512::ProcessLeaf(const std::vector<byte> &Input, size_t InOffset, SHA512State &State, ulong Length)
{
	do
	{
		Compress(Input, InOffset, State);
		InOffset += m_parallelProfile.ParallelMinimumSize();
		Length -= m_parallelProfile.ParallelMinimumSize();
	} 
	while (Length > 0);
}

void SHA512::Round(ulong A, ulong B, ulong C, ulong &D, ulong E, ulong F, ulong G, ulong &H, ulong M, ulong P)
{
	ulong R0 = H + BigSigma1(E) + Ch(E, F, G) + P + M;
	D += R0;
	H = R0 + BigSigma0(A) + Maj(A, B, C);
}

ulong SHA512::Sigma0(ulong W)
{
	return ((W << 63) | (W >> 1)) ^ ((W << 56) | (W >> 8)) ^ (W >> 7);
}

ulong SHA512::Sigma1(ulong W)
{
	return ((W << 45) | (W >> 19)) ^ ((W << 3) | (W >> 61)) ^ (W >> 6);
}

NAMESPACE_DIGESTEND