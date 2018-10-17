#include "HCR.h"
#include "IntUtils.h"
#include "ProviderFromName.h"

NAMESPACE_PRNG

using Enumeration::SHA2Digests;

const std::string HCR::CLASS_NAME("HCR");

//~~~Accessors~~~//

const Prngs HCR::Enumeral()
{
	return Prngs::HCR;
}

const std::string HCR::Name()
{
	return CLASS_NAME + "-" + m_rngGenerator->Name();
}

//~~~Constructor~~~//

HCR::HCR(SHA2Digests DigestType, Providers ProviderType, size_t BufferSize)
	:
	m_bufferIndex(0),
	m_bufferSize(BufferSize >= MIN_BUFLEN ? BufferSize : MIN_BUFLEN),
	m_digestType(DigestType != SHA2Digests::None ? DigestType :
		throw CryptoRandomException("HCR:Ctor", "Digest type can not be none!")),
	m_isDestroyed(false),
	m_pvdType(ProviderType),
	m_rndSeed(0),
	m_rngBuffer(BufferSize),
	m_rngGenerator(new Drbg::HCG(static_cast<SHA2Digests>(DigestType)))
{
	Reset();
}

HCR::HCR(std::vector<byte> Seed, SHA2Digests DigestType, size_t BufferSize)
	:
	m_bufferIndex(0),
	m_bufferSize(BufferSize >= MIN_BUFLEN ? BufferSize : MIN_BUFLEN),
	m_digestType(DigestType != SHA2Digests::None ? DigestType :
		throw CryptoRandomException("HCR:Ctor", "Digest type can not be none!")),
	m_isDestroyed(false),
	m_pvdType(Providers::ACP),
	m_rndSeed(Seed.size() >= GetMinimumSeedSize(DigestType) ? Seed :
		throw CryptoRandomException("HCR:Ctor", "The seed is too small!")),
	m_rngBuffer(BufferSize),
	m_rngGenerator(new Drbg::HCG(DigestType))
{
	Reset();
}

HCR::~HCR()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_bufferIndex = 0;
		m_bufferSize = 0;
		m_digestType = SHA2Digests::None;
		m_pvdType = Providers::None;

		Utility::IntUtils::ClearVector(m_rndSeed);
		Utility::IntUtils::ClearVector(m_rngBuffer);

		if (m_rngGenerator != nullptr)
		{
			m_rngGenerator.reset(nullptr);
		}
	}
}

//~~~Public Functions~~~//

std::vector<byte> HCR::Generate(size_t Length)
{
	std::vector<byte> rnd(Length);
	Generate(rnd);

	return rnd;
}

void HCR::Generate(std::vector<byte> &Output, size_t Offset, size_t Length)
{
	CexAssert(Offset + Length <= Output.size(), "the array is too small to fulfill this request");

	std::vector<byte> rnd = Generate(Length);
	Utility::MemUtils::Copy(rnd, 0, Output, Offset, Length);
}

void HCR::Generate(std::vector<byte> &Output)
{
	CexAssert(Output.size() != 0, "buffer size must be at least 1 in length");

	if (m_rngBuffer.size() - m_bufferIndex < Output.size())
	{
		size_t bufSize = m_rngBuffer.size() - m_bufferIndex;

		// copy remaining bytes
		if (bufSize != 0)
		{
			Utility::MemUtils::Copy(m_rngBuffer, m_bufferIndex, Output, 0, bufSize);
		}

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

ushort HCR::NextUInt16()
{
	ushort x = 0;
	Utility::MemUtils::CopyToValue(Generate(sizeof(ushort)), 0, x, sizeof(ushort));

	return x;
}

uint HCR::NextUInt32()
{
	uint x = 0;
	Utility::MemUtils::CopyToValue(Generate(sizeof(uint)), 0, x, sizeof(uint));

	return x;
}

ulong HCR::NextUInt64()
{
	ulong x = 0;
	Utility::MemUtils::CopyToValue(Generate(sizeof(ulong)), 0, x, sizeof(ulong));

	return x;
}

void HCR::Reset()
{
	if (m_rndSeed.size() != 0)
	{
		m_rngGenerator->Initialize(m_rndSeed);
	}
	else
	{
		Provider::IProvider* seedGen = Helper::ProviderFromName::GetInstance(m_pvdType == Providers::None ? Providers::CSP : m_pvdType);
		std::vector<byte> seed(m_rngGenerator->LegalKeySizes()[1].KeySize());
		seedGen->Generate(seed);
		delete seedGen;
		m_rngGenerator->Initialize(seed);
	}

	m_rngGenerator->Generate(m_rngBuffer);
	m_bufferIndex = 0;
}

uint HCR::GetMinimumSeedSize(SHA2Digests RngEngine)
{
	uint seedSize = 0;

	switch (RngEngine)
	{
		case SHA2Digests::SHA256:
		{
			seedSize = 64;
			break;
		}
		case SHA2Digests::SHA512:
		{
			seedSize = 128;
			break;
		}
		default:
		{
			seedSize = 128;
		}
	}

	return seedSize;
}

NAMESPACE_PRNGEND
