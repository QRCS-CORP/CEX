#include "ISCRsg.h"
#include "IntUtils.h"
#include "CSPRsg.h"

NAMESPACE_SEED

//** Public Methods **//

void ISCRsg::Destroy()
{
	if (!m_isDestroyed)
	{
		m_accululator = 0;
		m_cycCounter = 0;
		m_rndCount = 0;
		m_rslCounter = 0;
		CEX::Utility::IntUtils::ClearVector(m_rndResult);
		CEX::Utility::IntUtils::ClearVector(m_wrkBuffer);
		m_isDestroyed = true;
	}
}

void ISCRsg::GetBytes(std::vector<byte> &Output)
{
	size_t offset = 0;
	int X;
	size_t len = SIZE32;

	while (offset < Output.size())
	{
		X = Next();

		if (Output.size() - offset < len)
			len = Output.size() - offset;

		memcpy(&Output[offset], &X, len);
		offset += len;
	}
}

std::vector<byte> ISCRsg::GetBytes(size_t Size)
{
	std::vector<byte> data(Size);
	GetBytes(data);
	return data;
}

int ISCRsg::Next()
{
	if (0 == m_rslCounter--)
	{
		Generate();
		m_rslCounter = MSIZE - 1;
	}
	return m_rndResult[m_rslCounter];
}

void ISCRsg::Reset()
{
	Generate();
}

//** Protected Methods **//

void ISCRsg::Generate()
{
	const int SSZ = MSIZE / 2;
	int i = 0;
	int j = SSZ - 1;
	int X, Y;
	m_lstResult += ++m_cycCounter;

	while (i != SSZ)
	{
		X = m_wrkBuffer[i];
		m_accululator ^= m_accululator << 13;
		m_accululator += m_wrkBuffer[++j];
		m_wrkBuffer[i] = Y = m_wrkBuffer[(X & MASK) >> 2] + m_accululator + m_lstResult;
		m_rndResult[i] = m_lstResult = m_wrkBuffer[((Y >> SIZE64) & MASK) >> 2] + X;

		X = m_wrkBuffer[++i];
		m_accululator ^= (int)((uint)m_accululator >> 6);
		m_accululator += m_wrkBuffer[++j];
		m_wrkBuffer[i] = Y = m_wrkBuffer[(X & MASK) >> 2] + m_accululator + m_lstResult;
		m_rndResult[i] = m_lstResult = m_wrkBuffer[((Y >> SIZE64) & MASK) >> 2] + X;

		X = m_wrkBuffer[++i];
		m_accululator ^= m_accululator << 2;
		m_accululator += m_wrkBuffer[++j];
		m_wrkBuffer[i] = Y = m_wrkBuffer[(X & MASK) >> 2] + m_accululator + m_lstResult;
		m_rndResult[i] = m_lstResult = m_wrkBuffer[((Y >> SIZE64) & MASK) >> 2] + X;

		X = m_wrkBuffer[++i];
		m_accululator ^= (int)((uint)m_accululator >> 16);
		m_accululator += m_wrkBuffer[++j];
		m_wrkBuffer[i] = Y = m_wrkBuffer[(X & MASK) >> 2] + m_accululator + m_lstResult;
		m_rndResult[i] = m_lstResult = m_wrkBuffer[((Y >> SIZE64) & MASK) >> 2] + X;
		++i;
	}

	j = 0;
	while (j != SSZ)
	{
		X = m_wrkBuffer[i];
		m_accululator ^= m_accululator << 13;
		m_accululator += m_wrkBuffer[j];
		m_wrkBuffer[i] = Y = m_wrkBuffer[(X & MASK) >> 2] + m_accululator + m_lstResult;
		m_rndResult[i] = m_lstResult = m_wrkBuffer[((Y >> SIZE64) & MASK) >> 2] + X;

		X = m_wrkBuffer[++i];
		m_accululator ^= (int)((uint)m_accululator >> 6);
		m_accululator += m_wrkBuffer[++j];
		m_wrkBuffer[i] = Y = m_wrkBuffer[(X & MASK) >> 2] + m_accululator + m_lstResult;
		m_rndResult[i] = m_lstResult = m_wrkBuffer[((Y >> SIZE64) & MASK) >> 2] + X;

		X = m_wrkBuffer[++i];
		m_accululator ^= m_accululator << 2;
		m_accululator += m_wrkBuffer[++j];
		m_wrkBuffer[i] = Y = m_wrkBuffer[(X & MASK) >> 2] + m_accululator + m_lstResult;
		m_rndResult[i] = m_lstResult = m_wrkBuffer[((Y >> SIZE64) & MASK) >> 2] + X;

		X = m_wrkBuffer[++i];
		m_accululator ^= (int)((uint)m_accululator >> 16);
		m_accululator += m_wrkBuffer[++j];
		m_wrkBuffer[i] = Y = m_wrkBuffer[(X & MASK) >> 2] + m_accululator + m_lstResult;
		m_rndResult[i] = m_lstResult = m_wrkBuffer[((Y >> SIZE64) & MASK) >> 2] + X;
		++i;
		++j;
	}

	m_rslCounter = MSIZE;
}

void ISCRsg::Initialize(bool MixState)
{
	int ctr = 0;
	int A, B, C, D, E, F, G, H;
	A = B = C = D = E = F = G = H = GDNR;

	Mix(A, B, C, D, E, F, G, H);
	Mix(A, B, C, D, E, F, G, H);
	Mix(A, B, C, D, E, F, G, H);
	Mix(A, B, C, D, E, F, G, H);

	while (ctr != MSIZE)
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
		while (ctr != MSIZE)
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

	Generate();
}

void ISCRsg::GetSeed(size_t Size)
{
	CSPRsg rnd;
	std::vector<byte> seed(Size);
	seed = rnd.GetBytes(Size);
	memcpy(&m_rndResult[0], &seed[0], Size);
}

NAMESPACE_SEEDEND
