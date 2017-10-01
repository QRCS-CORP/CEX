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
		m_isDestroyed = true;
		m_bufferIndex = 0;
		m_bufferSize = 0;

		Utility::IntUtils::ClearVector(m_rngBuffer);
		Utility::IntUtils::ClearVector(m_rndSeed);

		if (m_rngGenerator != 0)
			delete m_rngGenerator;
	}
}

void DCR::Fill(std::vector<ushort> &Output, size_t Offset, size_t Elements)
{
	CEXASSERT(Output.size() - Offset <= Elements, "the output array is too short");

	size_t bufLen = Elements * sizeof(ushort);
	std::vector<byte> buf(bufLen);
	GetBytes(buf);
	Utility::MemUtils::Copy(buf, 0, Output, Offset, bufLen);
}

void DCR::Fill(std::vector<uint> &Output, size_t Offset, size_t Elements)
{
	CEXASSERT(Output.size() - Offset <= Elements, "the output array is too short");

	size_t bufLen = Elements * sizeof(uint);
	std::vector<byte> buf(bufLen);
	GetBytes(buf);
	Utility::MemUtils::Copy(buf, 0, Output, Offset, bufLen);
}

void DCR::Fill(std::vector<ulong> &Output, size_t Offset, size_t Elements)
{
	CEXASSERT(Output.size() - Offset <= Elements, "the output array is too short");

	size_t bufLen = Elements * sizeof(ulong);
	std::vector<byte> buf(bufLen);
	GetBytes(buf);
	Utility::MemUtils::Copy(buf, 0, Output, Offset, bufLen);
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
			Utility::MemUtils::Copy(m_rngBuffer, m_bufferIndex, Output, 0, bufSize);

		size_t rmd = Output.size() - bufSize;

		while (rmd > 0)
		{
			// fill buffer
			m_rngGenerator->Generate(m_rngBuffer);

			if (rmd > m_rngBuffer.size())
			{
				Utility::MemUtils::Copy(m_rngBuffer, 0, Output, bufSize, m_rngBuffer.size());
				bufSize += m_rngBuffer.size();
				rmd -= m_rngBuffer.size();
			}
			else
			{
				Utility::MemUtils::Copy(m_rngBuffer, 0, Output, bufSize, rmd);
				m_bufferIndex = rmd;
				rmd = 0;
			}
		}
	}
	else
	{
		Utility::MemUtils::Copy(m_rngBuffer, m_bufferIndex, Output, 0, Output.size());
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

	ushort num;

	do
	{
		num = (ushort)GetRanged(Maximum, sizeof(ushort));
	} while (num > Maximum);

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

	uint num;

	do
	{
		num = (uint)GetRanged(Maximum, sizeof(uint));
	} while (num > Maximum);

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

	ulong num;

	do
	{
		num = GetRanged(Maximum, sizeof(ulong));
	} while (num > Maximum);

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

ulong DCR::GetRanged(ulong Maximum, size_t Length)
{
	std::vector<byte> rand;

	if (Maximum < 256)
		rand = GetBytes(1);
	else if (Maximum < 65536)
		rand = GetBytes(2);
	else if (Maximum < 16777216)
		rand = GetBytes(3);
	else if (Maximum < 4294967296)
		rand = GetBytes(4);
	else if (Maximum < 1099511627776)
		rand = GetBytes(5);
	else if (Maximum < 281474976710656)
		rand = GetBytes(6);
	else if (Maximum < 72057594037927936)
		rand = GetBytes(7);
	else
		rand = GetBytes(8);

	ulong val = 0;
	Utility::MemUtils::CopyToValue(rand, 0, val, rand.size());

	ulong bits = Length * 8;
	while (val > Maximum && bits != 0)
	{
		val >>= 1;
		bits--;
	}

	return val;
}

uint DCR::GetMinimumSeedSize(Digests RngEngine)
{
	const uint CTRLEN = 8;

	switch (RngEngine)
	{
		case Digests::Blake256:
			return CTRLEN + 32;
		case Digests::Blake512:
			return CTRLEN + 64;
		case Digests::Keccak256:
			return CTRLEN + 136;
		case Digests::Keccak512:
		case Digests::Keccak1024:
			return CTRLEN + 72;
		case Digests::SHA256:
			return CTRLEN + 64;
		case Digests::SHA512:
			return CTRLEN + 128;
		case Digests::Skein1024:
			return CTRLEN + 128;
		case Digests::Skein256:
			return CTRLEN + 32;
		case Digests::Skein512:
			return CTRLEN + 64;
		default:
			return CTRLEN + 128;
	}
}

NAMESPACE_PRNGEND
