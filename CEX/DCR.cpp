#include "DCR.h"
#include "ArrayUtils.h"
#include "IntUtils.h"
#include "ProviderFromName.h"

NAMESPACE_PRNG

//~~~Constructor~~~//

DCR::DCR(Digests DigestEngine, Providers SeedEngine, size_t BufferSize)
	:
	m_bufferIndex(0),
	m_bufferSize(BufferSize),
	m_digestType(DigestEngine),
	m_isDestroyed(false),
	m_pvdType(SeedEngine),
	m_rngBuffer(BufferSize)
{
	if (BufferSize < BUFFER_MIN)
		throw CryptoRandomException("DCR:Ctor", "BufferSize must be at least 64 bytes!");

	Reset();
}

DCR::DCR(std::vector<byte> Seed, Digests DigestEngine, size_t BufferSize)
	:
	m_bufferIndex(0),
	m_bufferSize(BufferSize),
	m_digestType(DigestEngine),
	m_isDestroyed(false),
	m_rngBuffer(BufferSize)
{
	if (Seed.size() == 0)
		throw CryptoRandomException("DCR:Ctor", "Seed can not be null!");
	if (GetMinimumSeedSize(DigestEngine) < Seed.size())
		throw CryptoRandomException("DCR:Ctor", "The state seed is too small! must be at least digest block size + 8 bytes");
	if (BufferSize < BUFFER_MIN)
		throw CryptoRandomException("DCR:Ctor", "BufferSize must be at least 128 bytes!");

	m_pvdType = Providers::CSP;
	Reset();
}

DCR::~DCR()
{
	Destroy();
}

//~~~Public Functions~~~//

void DCR::Destroy()
{
	if (!m_isDestroyed)
	{
		m_bufferIndex = 0;
		m_bufferSize = 0;

		Utility::ArrayUtils::ClearVector(m_rngBuffer);
		Utility::ArrayUtils::ClearVector(m_stateSeed);

		if (m_rngGenerator != 0)
			delete m_rngGenerator;

		m_isDestroyed = true;
	}
}

std::vector<byte> DCR::GetBytes(size_t Size)
{
	std::vector<byte> data(Size);
	GetBytes(data);
	return data;
}

void DCR::GetBytes(std::vector<byte> &Output)
{
	if (Output.size() == 0)
		throw CryptoRandomException("CMR:GetBytes", "Buffer size must be at least 1 byte!");

	if (m_rngBuffer.size() - m_bufferIndex < Output.size())
	{
		size_t bufSize = m_rngBuffer.size() - m_bufferIndex;
		// copy remaining bytes
		if (bufSize != 0)
			memcpy(&Output[0], &m_rngBuffer[m_bufferIndex], bufSize);

		size_t rem = Output.size() - bufSize;

		while (rem > 0)
		{
			// fill buffer
			m_rngGenerator->Generate(m_rngBuffer);

			if (rem > m_rngBuffer.size())
			{
				memcpy(&Output[bufSize], &m_rngBuffer[0], m_rngBuffer.size());
				bufSize += m_rngBuffer.size();
				rem -= m_rngBuffer.size();
			}
			else
			{
				memcpy(&Output[bufSize], &m_rngBuffer[0], rem);
				m_bufferIndex = rem;
				rem = 0;
			}
		}
	}
	else
	{
		memcpy(&Output[0], &m_rngBuffer[m_bufferIndex], Output.size());
		m_bufferIndex += Output.size();
	}
}

uint DCR::Next()
{
	return Utility::IntUtils::ToInt32(GetBytes(4));
}

uint DCR::Next(uint Maximum)
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

uint DCR::Next(uint Minimum, uint Maximum)
{
	uint num = 0;
	while ((num = Next(Maximum)) < Minimum) {}
	return num;
}

ulong DCR::NextLong()
{
	return Utility::IntUtils::ToInt64(GetBytes(8));
}

ulong DCR::NextLong(ulong Maximum)
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

ulong DCR::NextLong(ulong Minimum, ulong Maximum)
{
	ulong num = 0;
	while ((num = NextLong(Maximum)) < Minimum) {}
	return num;
}

void DCR::Reset()
{
	if (m_rngGenerator != 0)
		delete m_rngGenerator;

	m_rngGenerator = new Drbg::DCG(m_digestType);

	if (m_stateSeed.size() != 0)
	{
		m_rngGenerator->Initialize(m_stateSeed);
	}
	else
	{
		Provider::IProvider* seedGen = Helper::ProviderFromName::GetInstance(m_pvdType);
		std::vector<byte> seed(m_rngGenerator->LegalKeySizes()[1].KeySize());
		seedGen->GetBytes(seed);
		delete seedGen;
		m_rngGenerator->Initialize(seed);
	}

	m_rngGenerator->Generate(m_rngBuffer);
	m_bufferIndex = 0;
}

//~~~Private Functions~~~//

std::vector<byte> DCR::GetBits(std::vector<byte> &Data, ulong Maximum)
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

std::vector<byte> DCR::GetByteRange(ulong Maximum)
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

uint DCR::GetMinimumSeedSize(Digests RngEngine)
{
	int ctrLen = 8;

	switch (RngEngine)
	{
	case Digests::Blake256:
			return ctrLen + 32;
		case Digests::Blake512:
			return ctrLen + 64;
		case Digests::Keccak256:
			return ctrLen + 136;
		case Digests::Keccak512:
			return ctrLen + 72;
		case Digests::SHA256:
			return ctrLen + 64;
		case Digests::SHA512:
			return ctrLen + 128;
		case Digests::Skein1024:
			return ctrLen + 128;
		case Digests::Skein256:
			return ctrLen + 32;
		case Digests::Skein512:
			return ctrLen + 64;
		default:
			return ctrLen + 128;
	}
}

NAMESPACE_PRNGEND
