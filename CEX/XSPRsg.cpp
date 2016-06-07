#include "XSPRsg.h"
#include "CSPRsg.h"
#include "IntUtils.h"

NAMESPACE_SEED

//** Public Methods **//

void XSPRsg::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isShift1024 = false;
		m_stateOffset = 0;
		CEX::Utility::IntUtils::ClearVector(m_stateSeed);
		CEX::Utility::IntUtils::ClearVector(m_wrkBuffer);
		m_isDestroyed = true;
	}
}

void XSPRsg::GetBytes(std::vector<byte> &Output)
{
	Generate(Output, Output.size());
}

void XSPRsg::Jump()
{
	if (m_isShift1024)
		Jump1024();
	else
		Jump128();
}

std::vector<byte> XSPRsg::GetBytes(size_t Size)
{
	std::vector<byte> data(Size);
	GetBytes(data);
	return data;
}

void XSPRsg::Generate(std::vector<byte> &Output, size_t Size)
{
	size_t offset = 0;
	ulong X;
	size_t ulen = sizeof(ulong);

	while (offset < Size)
	{
		if (m_isShift1024)
			X = Shift1024();
		else
			X = Shift128();

		if (Size - offset < ulen)
			ulen = Size - offset;

		memcpy(&Output[offset], &X, ulen);
		offset += ulen;
	}
}

int XSPRsg::Next()
{
	ulong X;
	if (m_isShift1024)
		X = Shift1024();
	else
		X = Shift128();

	int ret(0);
	memcpy(&ret, &X, sizeof(ret));

	return ret;
}

void XSPRsg::Reset()
{
	memset(&m_wrkBuffer[0], 0, sizeof m_wrkBuffer);
	memcpy(&m_wrkBuffer[0], &m_stateSeed[0], m_stateSeed.size() * sizeof(ulong));
}

ulong XSPRsg::Split(ulong X)
{
	ulong Z = (X += Z1);
	Z = (Z ^ (Z >> 30)) * Z2;
	Z = (Z ^ (Z >> 27)) * Z3;

	return Z ^ (Z >> 31);
}

//** Protected Methods **//

void XSPRsg::Jump128()
{
	ulong s0 = 0;
	ulong s1 = 0;

	for (size_t i = 0; i < JMP128.size(); i++)
	{
		for (size_t b = 0; b < 64; b++)
		{
			if (JMP128[i] & 1ULL << b)
			{
				s0 ^= m_wrkBuffer[0];
				s1 ^= m_wrkBuffer[1];
			}

			Shift128();
		}
	}

	m_wrkBuffer[0] = s0;
	m_wrkBuffer[1] = s1;
}

void XSPRsg::Jump1024()
{
	std::vector<ulong> T(16, 0);

	for (size_t i = 0; i < JMP1024.size(); i++)
	{
		for (size_t b = 0; b < 64; b++)
		{
			if (JMP1024[i] & 1ULL << b)
			{
				for (int j = 0; j < 16; j++)
					T[j] ^= m_wrkBuffer[(j + m_stateOffset) & 15];
			}

			Shift1024();
		}
	}

	memcpy(&m_wrkBuffer[0], &T[0], sizeof T);
}

ulong XSPRsg::Shift128()
{
	ulong X = m_wrkBuffer[0];
	const ulong Y = m_wrkBuffer[1];

	m_wrkBuffer[0] = Y;
	X ^= X << 23; // a
	m_wrkBuffer[1] = X ^ Y ^ (X >> 18) ^ (Y >> 5); // b, c

	return m_wrkBuffer[1] + Y; // +
}

ulong XSPRsg::Shift1024()
{
	const ulong X = m_wrkBuffer[m_stateOffset];
	ulong Y = m_wrkBuffer[m_stateOffset = (m_stateOffset + 1) & 15];

	Y ^= Y << 31; // a
	m_wrkBuffer[m_stateOffset] = Y ^ X ^ (Y >> 11) ^ (X >> 30); // b,c

	return m_wrkBuffer[m_stateOffset] * Z4;
}

void XSPRsg::GetSeed(size_t Size)
{
	CSPRsg rnd;
	std::vector<byte> seed(Size);
	seed = rnd.GetBytes(Size);
	memcpy(&m_stateSeed[0], &seed[0], Size);
}

NAMESPACE_SEEDEND