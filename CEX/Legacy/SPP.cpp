#include "SPP.h"
#include "CSPR.h"
#include "IntUtils.h"

NAMESPACE_PRNG

using Provider::CSPR;
using Utility::IntUtils;

//~~~Public Methods~~~//

void SPP::Destroy()
{
	if (!m_isDestroyed)
	{
		m_bufferIndex = 0;
		m_bufferSize = 0;
		m_rndCount = 0;
		m_keySize = 0;

		IntUtils::ClearVector(m_byteBuffer);
		IntUtils::ClearVector(m_stateSeed);

		if (m_seedGenerator != 0)
			delete m_seedGenerator;
		if (m_rngGenerator != 0)
			delete m_rngGenerator;

		m_isDestroyed = true;
	}
}

std::vector<byte> SPP::GetBytes(size_t Size)
{
	std::vector<byte> data(Size);
	GetBytes(data);
	return data;
}

void SPP::GetBytes(std::vector<byte> &Output)
{
	if (Output.size() == 0)
		throw CryptoRandomException("CMP:GetBytes", "Buffer size must be at least 1 byte!");

	if (m_byteBuffer.size() - m_bufferIndex < Output.size())
	{
		size_t bufSize = m_byteBuffer.size() - m_bufferIndex;
		// copy remaining bytes
		if (bufSize != 0)
			memcpy(&Output[0], &m_byteBuffer[m_bufferIndex], bufSize);

		size_t rem = Output.size() - bufSize;

		while (rem > 0)
		{
			// fill buffer
			m_rngGenerator->Generate(m_byteBuffer);

			if (rem > m_byteBuffer.size())
			{
				memcpy(&Output[bufSize], &m_byteBuffer[0], m_byteBuffer.size());
				bufSize += m_byteBuffer.size();
				rem -= m_byteBuffer.size();
			}
			else
			{
				memcpy(&Output[bufSize], &m_byteBuffer[0], rem);
				m_bufferIndex = rem;
				rem = 0;
			}
		}
	}
	else
	{
		memcpy(&Output[0], &m_byteBuffer[m_bufferIndex], Output.size());
		m_bufferIndex += Output.size();
	}
}

uint SPP::Next()
{
	return IntUtils::ToInt32(GetBytes(4));
}

uint SPP::Next(uint Maximum)
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

uint SPP::Next(uint Minimum, uint Maximum)
{
	uint num = 0;
	while ((num = Next(Maximum)) < Minimum) {}
	return num;
}

ulong SPP::NextLong()
{
	return IntUtils::ToInt64(GetBytes(8));
}

ulong SPP::NextLong(ulong Maximum)
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

ulong SPP::NextLong(ulong Minimum, ulong Maximum)
{
	ulong num = 0;
	while ((num = NextLong(Maximum)) < Minimum) {}
	return num;
}

void SPP::Reset()
{
	if (m_rngGenerator != 0)
		delete m_rngGenerator;
	if (m_seedGenerator != 0)
		delete m_seedGenerator;

	m_seedGenerator = GetSeedGenerator(m_seedType);
	m_rngGenerator = new SBG(m_rndCount);

	if (m_seedGenerator != 0)
	{
		std::vector<byte> seed(m_keySize);
		m_seedGenerator->GetBytes(seed);
		m_rngGenerator->Initialize(seed);
	}
	else
	{
		m_rngGenerator->Initialize(m_stateSeed);
	}

	m_rngGenerator->Generate(m_byteBuffer);
	m_bufferIndex = 0;
}

//~~~Private~~~//

std::vector<byte> SPP::GetBits(std::vector<byte> &Data, ulong Maximum)
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

std::vector<byte> SPP::GetByteRange(ulong Maximum)
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

IProvider* SPP::GetSeedGenerator(Providers SeedEngine)
{
	switch (SeedEngine) //ToDo: ProviderFromName
	{
		/*case Enumeration::Providers::XSG:
		return new Provider::XSG();*/ //ToDo?
	default:
		return new CSPR();
	}
}

NAMESPACE_PRNGEND