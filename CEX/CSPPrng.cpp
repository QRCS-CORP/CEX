#include "CSPPrng.h"
#include "IntUtils.h"

NAMESPACE_PRNG

using CEX::Utility::IntUtils;

void CSPPrng::Destroy()
{
	if (!m_isDestroyed)
	{
		if (m_rngCrypto != 0)
		{
			m_rngCrypto->Destroy();
			try
			{
				delete m_rngCrypto;
			}
			catch (...) {}
		}

		m_isDestroyed = true;
	}
}

std::vector<byte> CSPPrng::GetBytes(size_t Size)
{
	std::vector<byte> data(Size);
	m_rngCrypto->GetBytes(data);

	return data;
}

void CSPPrng::GetBytes(std::vector<byte> &Output)
{
	m_rngCrypto->GetBytes(Output);
}

uint CSPPrng::Next()
{
	return IntUtils::ToInt32(GetBytes(4));
}

uint CSPPrng::Next(uint Maximum)
{
	std::vector<byte> rand;
	uint num(0);

	do
	{
		rand = GetByteRange(Maximum);
		memcpy(&num, &rand[0], rand.size());
	} 
	while (num > Maximum);

	return num;
}

uint CSPPrng::Next(uint Minimum, uint Maximum)
{
	uint num = 0;
	while ((num = Next(Maximum)) < Minimum) {}
	return num;
}

ulong CSPPrng::NextLong()
{
	return IntUtils::ToInt64(GetBytes(8));
}

ulong CSPPrng::NextLong(ulong Maximum)
{
	std::vector<byte> rand;
	ulong num(0);

	do
	{
		rand = GetByteRange(Maximum);
		memcpy(&num, &rand[0], rand.size());
	} 
	while (num > Maximum);

	return num;
}

ulong CSPPrng::NextLong(ulong Minimum, ulong Maximum)
{
	ulong num = 0;
	while ((num = NextLong(Maximum)) < Minimum) {}
	return num;
}

void CSPPrng::Reset()
{
	if (m_rngCrypto != 0)
	{
		m_rngCrypto->Destroy();
		delete m_rngCrypto;
	}

	m_rngCrypto = new CEX::Seed::CSPRsg;
}

//~~~Protected Methods~~~//

std::vector<byte> CSPPrng::GetByteRange(ulong Maximum)
{
	std::vector<byte> data;

	if (Maximum < 256)
		data = GetBytes(1);
	else if (Maximum < 65536)
		data = GetBytes(2);
	else if (Maximum < 16777216)
		data = GetBytes(3);
	else if (Maximum < 4294967296)
		data = GetBytes(4);
	else if (Maximum < 1099511627776)
		data = GetBytes(5);
	else if (Maximum < 281474976710656)
		data = GetBytes(6);
	else if (Maximum < 72057594037927936)
		data = GetBytes(7);
	else
		data = GetBytes(8);

	return GetBits(data, Maximum);
}

std::vector<byte> CSPPrng::GetBits(std::vector<byte> Data, ulong Maximum)
{
	ulong val = 0;
	memcpy(&val, &Data[0], Data.size());
	ulong bits = Data.size() * 8;

	while (val > Maximum && bits != 0)
	{
		val >>= 1;
		bits--;
	}

	std::vector<byte> ret(Data.size());
	memcpy(&ret[0], &val, Data.size());

	return ret;
}

NAMESPACE_PRNGEND
