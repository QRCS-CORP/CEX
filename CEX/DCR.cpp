#include "DCR.h"
#include "IntUtils.h"
#include "ProviderFromName.h"

NAMESPACE_PRNG

const std::string DCR::CLASS_NAME("DCR");

//~~~Constructor~~~//

DCR::DCR(Digests DigestEngine, Providers SeedEngine, size_t BufferSize)
	:
	m_bufferIndex(0),
	m_bufferSize(BufferSize >= MIN_BUFSZE ? BufferSize :
		throw CryptoRandomException("DCR:Ctor", "BufferSize must be at least 64 bytes!")),
	m_digestType(DigestEngine != Digests::None ? DigestEngine :
		throw CryptoRandomException("DCR:Ctor", "Digest type can not be none!")),
	m_isDestroyed(false),
	m_pvdType(SeedEngine),
	m_rndSeed(0),
	m_rngBuffer(BufferSize),
	m_rngGenerator(new Drbg::DCG(DigestEngine))
{
	Reset();
}

DCR::DCR(std::vector<byte> Seed, Digests DigestEngine, size_t BufferSize)
	:
	m_bufferIndex(0),
	m_bufferSize(BufferSize >= MIN_BUFSZE ? BufferSize :
		throw CryptoRandomException("DCR:Ctor", "BufferSize must be at least 64 bytes!")),
	m_digestType(DigestEngine != Digests::None ? DigestEngine : 
		throw CryptoRandomException("DCR:Ctor", "Digest type can not be none!")),
	m_isDestroyed(false),
	m_pvdType(Providers::ACP),
	m_rngBuffer(BufferSize),
	m_rngGenerator(new Drbg::DCG(DigestEngine)),
	m_rndSeed(Seed.size() >= GetMinimumSeedSize(DigestEngine) ? Seed :
		throw CryptoRandomException("DCR:Ctor", "The seed is too small!"))
{
	Reset();
}

DCR::~DCR()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_bufferIndex = 0;
		m_bufferSize = 0;
		m_digestType = Digests::None;
		m_pvdType = Providers::None;

		Utility::IntUtils::ClearVector(m_rndSeed);
		Utility::IntUtils::ClearVector(m_rngBuffer);

		if (m_rngGenerator != nullptr)
		{
			m_rngGenerator.reset(nullptr);
		}
	}
}

//~~~Accessors~~~//

const Prngs DCR::Enumeral()
{
	return Prngs::DCR;
}

const std::string DCR::Name()
{
	return CLASS_NAME + "-" + m_rngGenerator->Name();
}

//~~~Public Functions~~~//

void DCR::Fill(std::vector<ushort> &Output, size_t Offset, size_t Elements)
{
	CexAssert(Output.size() - Offset <= Elements, "the output array is too short");

	const size_t BUFLEN = Elements * sizeof(ushort);
	std::vector<byte> buf(BUFLEN);
	GetBytes(buf);
	Utility::MemUtils::Copy(buf, 0, Output, Offset, BUFLEN);
}

void DCR::Fill(std::vector<uint> &Output, size_t Offset, size_t Elements)
{
	CexAssert(Output.size() - Offset <= Elements, "the output array is too short");

	const size_t BUFLEN = Elements * sizeof(uint);
	std::vector<byte> buf(BUFLEN);
	GetBytes(buf);
	Utility::MemUtils::Copy(buf, 0, Output, Offset, BUFLEN);
}

void DCR::Fill(std::vector<ulong> &Output, size_t Offset, size_t Elements)
{
	CexAssert(Output.size() - Offset <= Elements, "the output array is too short");

	const size_t BUFLEN = Elements * sizeof(ulong);
	std::vector<byte> buf(BUFLEN);
	GetBytes(buf);
	Utility::MemUtils::Copy(buf, 0, Output, Offset, BUFLEN);
}

std::vector<byte> DCR::GetBytes(size_t Size)
{
	std::vector<byte> buf(Size);
	GetBytes(buf);

	return buf;
}

void DCR::GetBytes(std::vector<byte> &Output)
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

ushort DCR::NextUInt16()
{
	ushort x = 0;
	Utility::MemUtils::CopyToValue(GetBytes(sizeof(ushort)), 0, x, sizeof(ushort));

	return x;
}

uint DCR::NextUInt32()
{
	uint x = 0;
	Utility::MemUtils::CopyToValue(GetBytes(sizeof(uint)), 0, x, sizeof(uint));

	return x;
}

ulong DCR::NextUInt64()
{
	ulong x = 0;
	Utility::MemUtils::CopyToValue(GetBytes(sizeof(ulong)), 0, x, sizeof(ulong));

	return x;
}

void DCR::Reset()
{
	if (m_rndSeed.size() != 0)
	{
		m_rngGenerator->Initialize(m_rndSeed);
	}
	else
	{
		Provider::IProvider* seedGen = Helper::ProviderFromName::GetInstance(m_pvdType == Providers::None ? Providers::ACP : m_pvdType);
		std::vector<byte> seed(m_rngGenerator->LegalKeySizes()[1].KeySize());
		seedGen->GetBytes(seed);
		delete seedGen;
		m_rngGenerator->Initialize(seed);
	}

	m_rngGenerator->Generate(m_rngBuffer);
	m_bufferIndex = 0;
}

uint DCR::GetMinimumSeedSize(Digests RngEngine)
{
	const uint CTRLEN = 8;
	uint seedSize = 0;

	switch (RngEngine)
	{
		case Digests::Keccak256:
		{
			seedSize = CTRLEN + 136;
			break;
		}
		case Digests::Keccak512:
		case Digests::Keccak1024:
		{
			seedSize = CTRLEN + 72;
			break;
		}
		case Digests::Blake256:
		case Digests::SHA256:
		case Digests::Skein512:
		{
			seedSize = CTRLEN + 64;
			break;
		}
		case Digests::Blake512:
		case Digests::SHA512:
		case Digests::Skein1024:
		{
			seedSize = CTRLEN + 128;
			break;
		}
		case Digests::Skein256:
		{
			seedSize = CTRLEN + 32;
			break;
		}
		default:
		{
			seedSize = CTRLEN + 128;
		}
	}

	return seedSize;
}

NAMESPACE_PRNGEND
