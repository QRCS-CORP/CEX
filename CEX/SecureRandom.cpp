#include "SecureRandom.h"
#include "ArrayUtils.h"
#include "BitConverter.h"
#include "ProviderFromName.h"

NAMESPACE_PRNG

using IO::BitConverter;

//~~~Public Methods~~~//

void SecureRandom::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_bufferIndex = 0;
		m_bufferSize = 0;
		m_seedType = Providers::None;

		try
		{
			Utility::ArrayUtils::ClearVector(m_byteBuffer);

			if (m_rngGenerator != 0)
				delete m_rngGenerator;
		}
		catch(std::exception& ex)
		{
			throw CryptoRandomException("SecureRandom:Destroy", "Not all objects were destroyed!", std::string(ex.what()));
		}
	}
}

std::vector<byte> SecureRandom::GetBytes(size_t Size)
{
	std::vector<byte> data(Size);
	GetBytes(data);
	return data;
}

void SecureRandom::GetBytes(std::vector<byte> &Output)
{
	if (Output.size() == 0)
		throw CryptoRandomException("SecureRandom:GetBytes", "Buffer size must be at least 1 byte!");

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
			m_rngGenerator->GetBytes(m_byteBuffer);

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

char SecureRandom::NextChar()
{
	int sze = sizeof(char);
	return BitConverter::ToChar(GetBytes(sze), 0);
}

unsigned char SecureRandom::NextUChar()
{
	int sze = sizeof(unsigned char);
	return BitConverter::ToUChar(GetBytes(sze), 0);
}

double SecureRandom::NextDouble()
{
	int sze = sizeof(double);
	return BitConverter::ToDouble(GetBytes(sze), 0);
}

short SecureRandom::NextInt16()
{
	return BitConverter::ToInt16(GetBytes(2), 0);
}

short SecureRandom::NextInt16(short Maximum)
{
	std::vector<byte> rand;
	short num(0);

	do
	{
		rand = GetByteRange(Maximum);
		memcpy(&num, &rand[0], rand.size());
	} 
	while (num > Maximum);

	return num;
}

short SecureRandom::NextInt16(short Minimum, short Maximum)
{
	short num = 0;
	while ((num = NextInt16(Maximum)) < Minimum) {}
	return num;
}

ushort SecureRandom::NextUInt16()
{
	return BitConverter::ToUInt16(GetBytes(2), 0);
}

ushort SecureRandom::NextUInt16(ushort Maximum)
{
	std::vector<byte> rand;
	ushort num(0);

	do
	{
		rand = GetByteRange(Maximum);
		memcpy(&num, &rand[0], rand.size());
	} 
	while (num > Maximum);

	return num;
}

ushort SecureRandom::NextUInt16(ushort Minimum, ushort Maximum)
{
	ushort num = 0;
	while ((num = NextUInt16(Maximum)) < Minimum) {}
	return num;
}

int SecureRandom::Next()
{
	return BitConverter::ToInt32(GetBytes(4), 0);
}

int SecureRandom::NextInt32()
{
	return BitConverter::ToInt32(GetBytes(4), 0);
}

int SecureRandom::NextInt32(int Maximum)
{
	std::vector<byte> rand;
	int num(0);

	do
	{
		rand = GetByteRange(Maximum);
		memcpy(&num, &rand[0], rand.size());
	} 
	while (num > Maximum);

	return num;
}

int SecureRandom::NextInt32(int Minimum, int Maximum)
{
	int num = 0;
	while ((num = NextInt32(Maximum)) < Minimum) {}
	return num;
}

uint SecureRandom::NextUInt32()
{
	return BitConverter::ToUInt32(GetBytes(4), 0);
}

uint SecureRandom::NextUInt32(uint Maximum)
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

uint SecureRandom::NextUInt32(uint Minimum, uint Maximum)
{
	uint num = 0;
	while ((num = NextUInt32(Maximum)) < Minimum) {}
	return num;
}

long SecureRandom::NextLong()
{
	return BitConverter::ToInt64(GetBytes(8), 0);
}

long SecureRandom::NextInt64()
{
	return BitConverter::ToInt64(GetBytes(8), 0);
}

long SecureRandom::NextInt64(long Maximum)
{
	std::vector<byte> rand;
	long num(0);

	do
	{
		rand = GetByteRange(Maximum);
		memcpy(&num, &rand[0], rand.size());
	} 
	while (num > Maximum);

	return num;
}

long SecureRandom::NextInt64(long Minimum, long Maximum)
{
	long num = 0;
	while ((num = NextInt64(Maximum)) < Minimum) {}
	return num;
}

ulong SecureRandom::NextUInt64()
{
	return BitConverter::ToUInt64(GetBytes(8), 0);
}

ulong SecureRandom::NextUInt64(ulong Maximum)
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

ulong SecureRandom::NextUInt64(ulong Minimum, ulong Maximum)
{
	ulong num = 0;
	while ((num = NextUInt64(Maximum)) < Minimum) {}
	return num;
}

void SecureRandom::Reset()
{
	if (m_rngGenerator != 0)
		delete m_rngGenerator;

	try
	{
		m_rngGenerator = Helper::ProviderFromName::GetInstance(m_seedType);
	}
	catch(std::exception& ex)
	{
		throw CryptoRandomException("SecureRandom:Reset", "Random seed generator could not be acquired!", std::string(ex.what()));
	}

	m_rngGenerator->GetBytes(m_byteBuffer);
	m_bufferIndex = 0;
}

//~~~Private Methods~~~//

std::vector<byte> SecureRandom::GetByteRange(ulong Maximum)
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

std::vector<byte> SecureRandom::GetBits(std::vector<byte> &Data, ulong Maximum)
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