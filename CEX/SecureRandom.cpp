#include "SecureRandom.h"
#include "BitConverter.h"
#include "IntUtils.h"
#include "ProviderFromName.h"
#include "PrngFromName.h"

NAMESPACE_PRNG

//~~~Constructor~~~//

SecureRandom::SecureRandom(Prngs EngineType, Providers ProviderType, Digests DigestType)
	:
	m_bufferIndex(0),
	m_bufferSize(BUFFER_SIZE),
	m_rndBuffer(BUFFER_SIZE),
	m_digestType(DigestType),
	m_isDestroyed(false),
	m_prngEngineType(EngineType),
	m_providerType(ProviderType)
{
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
		m_digestType = Digests::None;
		m_prngEngineType = Prngs::None;
		m_providerType = Providers::None;

		try
		{
			Utility::IntUtils::ClearVector(m_rndBuffer);

			if (m_prngEngine != 0)
				delete m_prngEngine;
		}
		catch(std::exception& ex)
		{
			throw CryptoRandomException("SecureRandom:Destroy", "Not all objects were destroyed!", std::string(ex.what()));
		}
	}
}

void SecureRandom::Fill(std::vector<ushort> &Output, size_t Offset, size_t Elements)
{
	CEXASSERT(Output.size() - Offset <= Elements, "the output array is too short");

	size_t bufLen = Elements * sizeof(ushort);
	std::vector<byte> buf(bufLen);
	GetBytes(buf);
	Utility::MemUtils::Copy(buf, 0, Output, Offset, bufLen);
}

void SecureRandom::Fill(std::vector<uint> &Output, size_t Offset, size_t Elements)
{
	CEXASSERT(Output.size() - Offset <= Elements, "the output array is too short");

	size_t bufLen = Elements * sizeof(uint);
	std::vector<byte> buf(bufLen);
	GetBytes(buf);
	Utility::MemUtils::Copy(buf, 0, Output, Offset, bufLen);
}

void SecureRandom::Fill(std::vector<ulong> &Output, size_t Offset, size_t Elements)
{
	CEXASSERT(Output.size() - Offset <= Elements, "the output array is too short");

	size_t bufLen = Elements * sizeof(ulong);
	std::vector<byte> buf(bufLen);
	GetBytes(buf);
	Utility::MemUtils::Copy(buf, 0, Output, Offset, bufLen);
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

	if (m_rndBuffer.size() - m_bufferIndex < Output.size())
	{
		size_t bufSize = m_rndBuffer.size() - m_bufferIndex;
		// copy remaining bytes
		if (bufSize != 0)
			Utility::MemUtils::Copy<byte>(m_rndBuffer, m_bufferIndex, Output, 0, bufSize);

		size_t rmd = Output.size() - bufSize;

		while (rmd > 0)
		{
			// fill buffer
			m_prngEngine->GetBytes(m_rndBuffer);

			if (rmd > m_rndBuffer.size())
			{
				Utility::MemUtils::Copy<byte>(m_rndBuffer, 0, Output, bufSize, m_rndBuffer.size());
				bufSize += m_rndBuffer.size();
				rmd -= m_rndBuffer.size();
			}
			else
			{
				Utility::MemUtils::Copy<byte>(m_rndBuffer, 0, Output, bufSize, rmd);
				m_bufferIndex = rmd;
				rmd = 0;
			}
		}
	}
	else
	{
		Utility::MemUtils::Copy<byte>(m_rndBuffer, m_bufferIndex, Output, 0, Output.size());
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

short SecureRandom::NextInt16(short Maximum, short Minimum)
{
	CEXASSERT(Maximum > Minimum, "maximum must be more than minimum");

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
	CEXASSERT(Maximum != 0, "maximum can not be zero");

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

ushort SecureRandom::NextUInt16(ushort Maximum, ushort Minimum)
{
	CEXASSERT(Maximum > Minimum, "maximum must be more than minimum");

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

int SecureRandom::NextInt32(int Maximum, int Minimum)
{
	CEXASSERT(Maximum > Minimum, "maximum must be more than minimum");

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
	CEXASSERT(Maximum != 0, "maximum can not be zero");

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

uint SecureRandom::NextUInt32(uint Maximum, uint Minimum)
{
	CEXASSERT(Maximum > Minimum, "maximum must be more than minimum");

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

long SecureRandom::NextInt64(long Maximum, long Minimum)
{
	CEXASSERT(Maximum > Minimum, "maximum must be more than minimum");

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
	CEXASSERT(Maximum != 0, "maximum can not be zero");

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

ulong SecureRandom::NextUInt64(ulong Maximum, ulong Minimum)
{
	CEXASSERT(Maximum > Minimum, "maximum must be more than minimum");

	ulong num = 0;
	while ((num = NextUInt64(Maximum)) < Minimum) {}
	return num;
}

void SecureRandom::Reset()
{
	if (m_digestType == Digests::None && m_prngEngineType != Prngs::BCR)
		m_digestType = Digests::SHA256;

	m_prngEngine = Helper::PrngFromName::GetInstance(m_prngEngineType, m_providerType, m_digestType);
	m_prngEngine->GetBytes(m_rndBuffer);
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