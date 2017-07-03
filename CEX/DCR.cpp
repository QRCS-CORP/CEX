#include "DCR.h"
#include "IntUtils.h"
#include "ProviderFromName.h"

NAMESPACE_PRNG

const std::string DCR::CLASS_NAME("DCR");

//~~~Properties~~~//

const Prngs DCR::Enumeral()
{
	return Prngs::DCR;
}

const std::string DCR::Name()
{
	return CLASS_NAME + "-" + m_rngGenerator->Name();
}

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
	if (GetMinimumSeedSize(DigestEngine) > Seed.size())
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

		Utility::IntUtils::ClearVector(m_rngBuffer);
		Utility::IntUtils::ClearVector(m_rndSeed);

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
		throw CryptoRandomException("BCR:GetBytes", "Buffer size must be at least 1 byte!");

	if (m_rngBuffer.size() - m_bufferIndex < Output.size())
	{
		size_t bufSize = m_rngBuffer.size() - m_bufferIndex;
		// copy remaining bytes
		if (bufSize != 0)
			Utility::MemUtils::Copy<byte>(m_rngBuffer, m_bufferIndex, Output, 0, bufSize);

		size_t rmd = Output.size() - bufSize;

		while (rmd > 0)
		{
			// fill buffer
			m_rngGenerator->Generate(m_rngBuffer);

			if (rmd > m_rngBuffer.size())
			{
				Utility::MemUtils::Copy<byte>(m_rngBuffer, 0, Output, bufSize, m_rngBuffer.size());
				bufSize += m_rngBuffer.size();
				rmd -= m_rngBuffer.size();
			}
			else
			{
				Utility::MemUtils::Copy<byte>(m_rngBuffer, 0, Output, bufSize, rmd);
				m_bufferIndex = rmd;
				rmd = 0;
			}
		}
	}
	else
	{
		Utility::MemUtils::Copy<byte>(m_rngBuffer, m_bufferIndex, Output, 0, Output.size());
		m_bufferIndex += Output.size();
	}
}

ushort DCR::NextUShort()
{
	return Utility::IntUtils::LeBytesTo16(GetBytes(2), 0);
}

ushort DCR::NextUShort(ushort Maximum)
{
	CEXASSERT(Maximum != 0, "maximum can not be zero");

	std::vector<byte> rand;
	uint num(0);

	do
	{
		rand = GetByteRange(Maximum);
		num = Utility::IntUtils::LeBytesTo16(rand, 0);
	} 
	while (num > Maximum);

	return num;
}

ushort DCR::NextUShort(ushort Maximum, ushort Minimum)
{
	CEXASSERT(Maximum != 0, "maximum can not be zero");
	CEXASSERT(Maximum > Minimum, "minimum can not be more than maximum");

	uint num = 0;
	while ((num = NextUShort(Maximum)) < Minimum) {}
	return num;
}

uint DCR::Next()
{
	return Utility::IntUtils::LeBytesTo32(GetBytes(4), 0);
}

uint DCR::Next(uint Maximum)
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

uint DCR::Next(uint Maximum, uint Minimum)
{
	CEXASSERT(Maximum != 0, "maximum can not be zero");
	CEXASSERT(Maximum > Minimum, "minimum can not be more than maximum");

	uint num = 0;
	while ((num = Next(Maximum)) < Minimum) {}
	return num;
}

ulong DCR::NextULong()
{
	return Utility::IntUtils::LeBytesTo64(GetBytes(8), 0);
}

ulong DCR::NextULong(ulong Maximum)
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

ulong DCR::NextULong(ulong Maximum, ulong Minimum)
{
	CEXASSERT(Maximum != 0, "maximum can not be zero");
	CEXASSERT(Maximum > Minimum, "minimum can not be more than maximum");

	ulong num = 0;
	while ((num = NextULong(Maximum)) < Minimum) {}
	return num;
}

void DCR::Reset()
{
	m_rngGenerator = new Drbg::DCG(m_digestType);

	if (m_rndSeed.size() != 0)
	{
		m_rngGenerator->Initialize(m_rndSeed);
	}
	else
	{
		Provider::IProvider* seedGen = Helper::ProviderFromName::GetInstance(m_pvdType == Providers::None ? Providers::CSP : m_pvdType);
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
