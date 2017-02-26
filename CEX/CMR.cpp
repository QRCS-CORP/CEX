#include "CMR.h"
#include "ArrayUtils.h"
#include "IntUtils.h"
#include "ProviderFromName.h"

NAMESPACE_PRNG

//~~~Constructor~~~//

CMR::CMR(BlockCiphers CipherType, Providers ProviderType, size_t BufferSize)
	:
	m_bufferIndex(0),
	m_bufferSize(BufferSize),
	m_byteBuffer(BufferSize),
	m_engineType(CipherType),
	m_isDestroyed(false),
	m_pvdType(ProviderType)
{
	if (BufferSize < BUFFER_MIN)
		throw CryptoRandomException("CMR:Ctor", "Buffer size must be at least 64 bytes!");

	Reset();
}

CMR::CMR(std::vector<byte> &Seed, BlockCiphers CipherType, size_t BufferSize)
	:
	m_bufferIndex(0),
	m_bufferSize(BufferSize),
	m_byteBuffer(BufferSize),
	m_engineType(CipherType),
	m_isDestroyed(false),
	m_stateSeed(Seed)
{
	if (BufferSize < BUFFER_MIN)
		throw CryptoRandomException("CMR:Ctor", "Buffer size must be at least 64 bytes!");
	if (Seed.size() == 0)
		throw CryptoRandomException("CMR:Ctor", "Seed can not be null or empty!");

	Reset();
}

CMR::~CMR()
{
	Destroy();
}

//~~~Public Functions~~~//

void CMR::Destroy()
{
	if (!m_isDestroyed)
	{
		m_engineType = BlockCiphers::None;
		m_pvdType = Providers::None;
		m_bufferIndex = 0;
		m_bufferSize = 0;

		Utility::ArrayUtils::ClearVector(m_stateSeed);
		Utility::ArrayUtils::ClearVector(m_byteBuffer);

		if (m_rngGenerator != 0)
			delete m_rngGenerator;

		m_isDestroyed = true;
	}
}

std::vector<byte> CMR::GetBytes(size_t Size)
{
	std::vector<byte> data(Size);
	GetBytes(data);
	return data;
}

void CMR::GetBytes(std::vector<byte> &Output)
{
	if (Output.size() == 0)
		throw CryptoRandomException("CMR:GetBytes", "Buffer size must be at least 1 byte!");

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

uint CMR::Next()
{
	return Utility::IntUtils::ToInt32(GetBytes(4));
}

uint CMR::Next(uint Maximum)
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

uint CMR::Next(uint Minimum, uint Maximum)
{
	uint num = 0;
	while ((num = Next(Maximum)) < Minimum) {}
	return num;
}

ulong CMR::NextLong()
{
	return Utility::IntUtils::ToInt64(GetBytes(8));
}

ulong CMR::NextLong(ulong Maximum)
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

ulong CMR::NextLong(ulong Minimum, ulong Maximum)
{
	ulong num = 0;
	while ((num = NextLong(Maximum)) < Minimum) {}
	return num;
}

void CMR::Reset()
{
	if (m_rngGenerator != 0)
		delete m_rngGenerator;

	m_rngGenerator = new Drbg::CMG(m_engineType, Enumeration::Digests::SHA256, m_pvdType);

	if (m_stateSeed.size() != 0)
	{
		m_rngGenerator->Initialize(m_stateSeed);
	}
	else
	{
		std::vector<byte> seed(m_rngGenerator->LegalKeySizes()[1].KeySize());
		Provider::IProvider* seedGen = Helper::ProviderFromName::GetInstance(m_pvdType);
		seedGen->GetBytes(seed);
		delete seedGen;
		m_rngGenerator->Initialize(seed);
	}

	m_rngGenerator->Generate(m_byteBuffer);
	m_bufferIndex = 0;
}

std::vector<byte> CMR::GetBits(std::vector<byte> &Data, ulong Maximum)
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

std::vector<byte> CMR::GetByteRange(ulong Maximum)
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

NAMESPACE_PRNGEND