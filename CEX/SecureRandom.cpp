#include "SecureRandom.h"
#include "BitConverter.h"
#include "IntUtils.h"
#include "MemUtils.h"
#include "ProviderFromName.h"

NAMESPACE_PRNG

//~~~Constructor~~~//

SecureRandom::SecureRandom(Providers ProviderType, size_t BufferSize)
	:
	m_bufferIndex(0),
	m_bufferSize(BufferSize),
	m_byteBuffer(BufferSize),
	m_isDestroyed(false),
	m_pvdType(ProviderType)
{
	if (BufferSize < 64)
		throw CryptoRandomException("SecureRandom:Ctor", "Buffer size must be at least 64 bytes!");

	Reset();
}

SecureRandom::~SecureRandom()
{
	Destroy();
}

//~~~Public Functions~~~//

void SecureRandom::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_bufferIndex = 0;
		m_bufferSize = 0;
		m_pvdType = Providers::None;

		try
		{
			Utility::IntUtils::ClearVector(m_byteBuffer);

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
			Utility::MemUtils::Copy<byte>(m_byteBuffer, m_bufferIndex, Output, 0, bufSize);

		size_t rem = Output.size() - bufSize;

		while (rem > 0)
		{
			// fill buffer
			m_rngGenerator->GetBytes(m_byteBuffer);

			if (rem > m_byteBuffer.size())
			{
				Utility::MemUtils::Copy<byte>(m_byteBuffer, 0, Output, bufSize, m_byteBuffer.size());
				bufSize += m_byteBuffer.size();
				rem -= m_byteBuffer.size();
			}
			else
			{
				Utility::MemUtils::Copy<byte>(m_byteBuffer, 0, Output, bufSize, rem);
				m_bufferIndex = rem;
				rem = 0;
			}
		}
	}
	else
	{
		Utility::MemUtils::Copy<byte>(m_byteBuffer, m_bufferIndex, Output, 0, Output.size());
		m_bufferIndex += Output.size();
	}
}

char SecureRandom::NextChar()
{
	return IO::BitConverter::ToChar(GetBytes(sizeof(char)), 0);
}

unsigned char SecureRandom::NextUChar()
{
	return IO::BitConverter::ToUChar(GetBytes(sizeof(unsigned char)), 0);
}

double SecureRandom::NextDouble()
{
	int sze = sizeof(double);
	return IO::BitConverter::ToDouble(GetBytes(sizeof(double)), 0);
}

short SecureRandom::NextInt16()
{
	return static_cast<short>(Utility::IntUtils::LeBytesTo16(GetBytes(2), 0));
}

short SecureRandom::NextInt16(short Maximum)
{
	std::vector<byte> rand;
	short num(0);

	do
	{
		rand = GetByteRange(Maximum);
		num = static_cast<short>(Utility::IntUtils::LeBytesTo16(rand, 0));
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
	return Utility::IntUtils::LeBytesTo16(GetBytes(2), 0);
}

ushort SecureRandom::NextUInt16(ushort Maximum)
{
	std::vector<byte> rand;
	ushort num(0);

	do
	{
		rand = GetByteRange(Maximum);
		num = Utility::IntUtils::LeBytesTo16(rand, 0);
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
	return static_cast<int>(Utility::IntUtils::LeBytesTo32(GetBytes(4), 0));
}

int SecureRandom::NextInt32()
{
	return static_cast<int>(Utility::IntUtils::LeBytesTo32(GetBytes(4), 0));
}

int SecureRandom::NextInt32(int Maximum)
{
	std::vector<byte> rand;
	int num(0);

	do
	{
		rand = GetByteRange(Maximum);
		num = static_cast<int>(Utility::IntUtils::LeBytesTo32(rand, 0));
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
	return Utility::IntUtils::LeBytesTo32(GetBytes(4), 0);
}

uint SecureRandom::NextUInt32(uint Maximum)
{
	std::vector<byte> rand;
	uint num(0);

	do
	{
		rand = GetByteRange(Maximum);
		num = Utility::IntUtils::LeBytesTo32(rand, 0);
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
	return static_cast<long>(Utility::IntUtils::LeBytesTo64(GetBytes(8), 0));
}

long SecureRandom::NextInt64()
{
	return static_cast<long>(Utility::IntUtils::LeBytesTo64(GetBytes(8), 0));
}

long SecureRandom::NextInt64(long Maximum)
{
	std::vector<byte> rand;
	long num(0);

	do
	{
		rand = GetByteRange(Maximum);
		num = static_cast<long>(Utility::IntUtils::LeBytesTo64(rand, 0));
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
	return Utility::IntUtils::LeBytesTo64(GetBytes(8), 0);
}

ulong SecureRandom::NextUInt64(ulong Maximum)
{
	std::vector<byte> rand;
	ulong num(0);

	do
	{
		rand = GetByteRange(Maximum);
		num = Utility::IntUtils::LeBytesTo64(rand, 0);
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
	m_rngGenerator = Helper::ProviderFromName::GetInstance(m_pvdType);
	m_rngGenerator->GetBytes(m_byteBuffer);
	m_bufferIndex = 0;
}

//~~~Private Functions~~~//

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
	Utility::MemUtils::Copy<byte, ulong>(Data, 0, val, Data.size());
	ulong bits = Data.size() * 8;

	while (val > Maximum && bits != 0)
	{
		val >>= 1;
		bits--;
	}
	std::vector<byte> ret(sizeof(ulong));
	Utility::MemUtils::Copy<ulong, byte>(val, ret, 0, sizeof(ulong));

	return ret;
}

NAMESPACE_PRNGEND