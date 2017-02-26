#include "ISAAC.h"
#include "IntUtils.h"
#include "CSPRsg.h"

NAMESPACE_DRBG

//~~~Public Methods~~~//

void ISAAC::Destroy()
{
	if (!m_isDestroyed)
	{
		m_accululator = 0;
		m_cycCounter = 0;
		m_rndCount = 0;
		m_rslCounter = 0;
		Utility::IntUtils::ClearVector(m_rndResult);
		Utility::IntUtils::ClearVector(m_wrkBuffer);
		m_isDestroyed = true;
	}
}

size_t ISAAC::Generate(std::vector<byte> &Output)
{
	return Generate(Output, 0, Output.size());
}

size_t ISAAC::Generate(std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	size_t blkCtr = 0;
	size_t blkSze = UINT_SIZE;
	uint X;

	while (blkCtr < Length)
	{
		X = Generate();

		if (Length - blkCtr < blkSze)
			blkSze = Length - blkCtr;

		memcpy(&Output[OutOffset + blkCtr], &X, blkSze);
		blkCtr += blkSze;
	}

	return Length;
}

void ISAAC::Initialize(const RngParams &GenParam)
{
	if (GenParam.Nonce().size() != 0)
	{
		if (GenParam.Info().size() != 0)
			Initialize(GenParam.Key(), GenParam.Nonce(), GenParam.Info());
		else
			Initialize(GenParam.Key(), GenParam.Nonce());
	}
	else
	{
		Initialize(GenParam.Key());
	}
}

void ISAAC::Initialize(const std::vector<byte> &Key)
{
#if defined(CPPEXCEPTIONS_ENABLED)
	if (Key.size() < UINT_SIZE || Key.size() > MAXKEY_SIZE)
		throw CryptoGeneratorException("ISAAC:Initialize", "The seed array length must be between 1 and 256 int32 values!");
#endif

	size_t len = Key.size() > MAXKEY_SIZE ? MAXKEY_SIZE : Key.size();
	memcpy(&m_rndResult[0], &Key[0], len);
	Process(true);
}

void ISAAC::Initialize(const std::vector<byte> &Key, const std::vector<byte> &Nonce)
{
	std::vector<byte> seed(Key.size() + Nonce.size());
	memcpy(&seed[0], &Key[0], Key.size());
	memcpy(&seed[Key.size()], &Nonce[0], Nonce.size());

	Initialize(seed);
}

void ISAAC::Initialize(const std::vector<byte> &Key, const std::vector<byte> &Nonce, const std::vector<byte> &Info)
{
	std::vector<byte> seed(Key.size() + Nonce.size());
	memcpy(&seed[0], &Key[0], Key.size());
	memcpy(&seed[Key.size()], &Nonce[0], Nonce.size());
	memcpy(&seed[Key.size() + Nonce.size()], &Info[0], Info.size());

	Initialize(seed);
}

void ISAAC::Reset()
{
	Transform();
}

void ISAAC::Update(const std::vector<byte> &Seed)
{
	Initialize(Seed);
}

//~~~Private Methods~~~//

uint ISAAC::Generate()
{
	if (0 == m_rslCounter--)
	{
		Transform();
		m_rslCounter = STATE_SIZE - 1;
	}

	return m_rndResult[m_rslCounter];
}

void ISAAC::Mix(uint &A, uint &B, uint &C, uint &D, uint &E, uint &F, uint &G, uint &H)
{
	A ^= B << 11;
	D += A;
	B += C;
	B ^= C >> 2;
	E += B;
	C += D;
	C ^= D << 8;
	F += C;
	D += E;
	D ^= E >> 16;
	G += D;
	E += F;
	E ^= F << 10;
	H += E;
	F += G;
	F ^= G >> 4;
	A += F;
	G += H;
	G ^= H << 8;
	B += G;
	H += A;
	H ^= A >> 9;
	C += H;
	A += B;
}

void ISAAC::Process(bool MixState)
{
	uint ctr = 0;
	uint A, B, C, D, E, F, G, H;
	A = B = C = D = E = F = G = H = GOLDEN_RATIO;

	Mix(A, B, C, D, E, F, G, H);
	Mix(A, B, C, D, E, F, G, H);
	Mix(A, B, C, D, E, F, G, H);
	Mix(A, B, C, D, E, F, G, H);

	while (ctr != STATE_SIZE)
	{
		if (MixState)
		{
			A += m_rndResult[ctr];
			B += m_rndResult[ctr + 1];
			C += m_rndResult[ctr + 2];
			D += m_rndResult[ctr + 3];
			E += m_rndResult[ctr + 4];
			F += m_rndResult[ctr + 5];
			G += m_rndResult[ctr + 6];
			H += m_rndResult[ctr + 7];
		}

		Mix(A, B, C, D, E, F, G, H);

		m_wrkBuffer[ctr] = A;
		m_wrkBuffer[ctr + 1] = B;
		m_wrkBuffer[ctr + 2] = C;
		m_wrkBuffer[ctr + 3] = D;
		m_wrkBuffer[ctr + 4] = E;
		m_wrkBuffer[ctr + 5] = F;
		m_wrkBuffer[ctr + 6] = G;
		m_wrkBuffer[ctr + 7] = H;
		ctr += 8;
	}

	if (MixState)
	{
		// second pass makes all of seed affect all of mem
		ctr = 0;
		while (ctr != STATE_SIZE)
		{
			A += m_wrkBuffer[ctr];
			B += m_wrkBuffer[ctr + 1];
			C += m_wrkBuffer[ctr + 2];
			D += m_wrkBuffer[ctr + 3];
			E += m_wrkBuffer[ctr + 4];
			F += m_wrkBuffer[ctr + 5];
			G += m_wrkBuffer[ctr + 6];
			H += m_wrkBuffer[ctr + 7];

			Mix(A, B, C, D, E, F, G, H);

			m_wrkBuffer[ctr] = A;
			m_wrkBuffer[ctr + 1] = B;
			m_wrkBuffer[ctr + 2] = C;
			m_wrkBuffer[ctr + 3] = D;
			m_wrkBuffer[ctr + 4] = E;
			m_wrkBuffer[ctr + 5] = F;
			m_wrkBuffer[ctr + 6] = G;
			m_wrkBuffer[ctr + 7] = H;
			ctr += 8;
		}
	}

	Transform();
}

void ISAAC::Transform()
{
	const size_t PRCSZE = STATE_SIZE / 2;
	size_t i = 0;
	size_t j = PRCSZE - 1;
	uint X, Y;
	m_lstResult += ++m_cycCounter;

	while (i != PRCSZE)
	{
		X = m_wrkBuffer[i];
		m_accululator ^= m_accululator << 13;
		m_accululator += m_wrkBuffer[++j];
		m_wrkBuffer[i] = Y = m_wrkBuffer[(X & SHIFT_MASK) >> 2] + m_accululator + m_lstResult;
		m_rndResult[i] = m_lstResult = m_wrkBuffer[((Y >> ULNG_SIZE) & SHIFT_MASK) >> 2] + X;

		X = m_wrkBuffer[++i];
		m_accululator ^= m_accululator >> 6;
		m_accululator += m_wrkBuffer[++j];
		m_wrkBuffer[i] = Y = m_wrkBuffer[(X & SHIFT_MASK) >> 2] + m_accululator + m_lstResult;
		m_rndResult[i] = m_lstResult = m_wrkBuffer[((Y >> ULNG_SIZE) & SHIFT_MASK) >> 2] + X;

		X = m_wrkBuffer[++i];
		m_accululator ^= m_accululator << 2;
		m_accululator += m_wrkBuffer[++j];
		m_wrkBuffer[i] = Y = m_wrkBuffer[(X & SHIFT_MASK) >> 2] + m_accululator + m_lstResult;
		m_rndResult[i] = m_lstResult = m_wrkBuffer[((Y >> ULNG_SIZE) & SHIFT_MASK) >> 2] + X;

		X = m_wrkBuffer[++i];
		m_accululator ^= m_accululator >> 16;
		m_accululator += m_wrkBuffer[++j];
		m_wrkBuffer[i] = Y = m_wrkBuffer[(X & SHIFT_MASK) >> 2] + m_accululator + m_lstResult;
		m_rndResult[i] = m_lstResult = m_wrkBuffer[((Y >> ULNG_SIZE) & SHIFT_MASK) >> 2] + X;
		++i;
	}

	j = 0;
	while (j != PRCSZE)
	{
		X = m_wrkBuffer[i];
		m_accululator ^= m_accululator << 13;
		m_accululator += m_wrkBuffer[j];
		m_wrkBuffer[i] = Y = m_wrkBuffer[(X & SHIFT_MASK) >> 2] + m_accululator + m_lstResult;
		m_rndResult[i] = m_lstResult = m_wrkBuffer[((Y >> ULNG_SIZE) & SHIFT_MASK) >> 2] + X;

		X = m_wrkBuffer[++i];
		m_accululator ^= m_accululator >> 6;
		m_accululator += m_wrkBuffer[++j];
		m_wrkBuffer[i] = Y = m_wrkBuffer[(X & SHIFT_MASK) >> 2] + m_accululator + m_lstResult;
		m_rndResult[i] = m_lstResult = m_wrkBuffer[((Y >> ULNG_SIZE) & SHIFT_MASK) >> 2] + X;

		X = m_wrkBuffer[++i];
		m_accululator ^= m_accululator << 2;
		m_accululator += m_wrkBuffer[++j];
		m_wrkBuffer[i] = Y = m_wrkBuffer[(X & SHIFT_MASK) >> 2] + m_accululator + m_lstResult;
		m_rndResult[i] = m_lstResult = m_wrkBuffer[((Y >> ULNG_SIZE) & SHIFT_MASK) >> 2] + X;

		X = m_wrkBuffer[++i];
		m_accululator ^= m_accululator >> 16;
		m_accululator += m_wrkBuffer[++j];
		m_wrkBuffer[i] = Y = m_wrkBuffer[(X & SHIFT_MASK) >> 2] + m_accululator + m_lstResult;
		m_rndResult[i] = m_lstResult = m_wrkBuffer[((Y >> ULNG_SIZE) & SHIFT_MASK) >> 2] + X;
		++i;
		++j;
	}

	m_rslCounter = STATE_SIZE;
}

NAMESPACE_DRBGEND
