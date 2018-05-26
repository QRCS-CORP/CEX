#include "HCR.h"
#include "IntUtils.h"
#include "ProviderFromName.h"

NAMESPACE_PRNG

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

HCR::HCR(Digests DigestEngine, Providers SeedEngine, size_t BufferSize)
	:
	m_bufferIndex(0),
	m_bufferSize(BufferSize >= MIN_BUFLEN ? BufferSize : MIN_BUFLEN),
	m_digestType(DigestEngine != Digests::None ? DigestEngine :
		throw CryptoRandomException("HCR:Ctor", "Digest type can not be none!")),
	m_isDestroyed(false),
	m_pvdType(SeedEngine),
	m_rndSeed(0),
	m_rngBuffer(BufferSize),
	m_rngGenerator(new Drbg::HCG(m_digestType))
{
	Reset();
}

HCR::HCR(std::vector<byte> Seed, Digests DigestEngine, size_t BufferSize)
	:
	m_bufferIndex(0),
	m_bufferSize(BufferSize >= MIN_BUFLEN ? BufferSize : MIN_BUFLEN),
	m_digestType(DigestEngine != Digests::None ? DigestEngine :
		throw CryptoRandomException("HCR:Ctor", "Digest type can not be none!")),
	m_isDestroyed(false),
	m_pvdType(Providers::ACP),
	m_rndSeed(Seed.size() >= GetMinimumSeedSize(DigestEngine) ? Seed :
		throw CryptoRandomException("HCR:Ctor", "The seed is too small!")),
	m_rngBuffer(BufferSize),
	m_rngGenerator(new Drbg::HCG(m_digestType))
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

//~~~Public Functions~~~//

void HCR::Fill(std::vector<int16_t> &Output, size_t Offset, size_t Elements)
{
	CexAssert(Output.size() - Offset <= Elements, "the output array is too short");

	size_t bufLen = Elements * sizeof(int16_t);
	std::vector<byte> buf(bufLen);
	GetBytes(buf);
	Utility::MemUtils::Copy(buf, 0, Output, Offset, bufLen);
}

void HCR::Fill(std::vector<ushort> &Output, size_t Offset, size_t Elements)
{
	CexAssert(Output.size() - Offset <= Elements, "the output array is too short");

	size_t bufLen = Elements * sizeof(ushort);
	std::vector<byte> buf(bufLen);
	GetBytes(buf);
	Utility::MemUtils::Copy(buf, 0, Output, Offset, bufLen);
}

void HCR::Fill(std::vector<int32_t> &Output, size_t Offset, size_t Elements)
{
	CexAssert(Output.size() - Offset <= Elements, "the output array is too short");

	size_t bufLen = Elements * sizeof(int32_t);
	std::vector<byte> buf(bufLen);
	GetBytes(buf);
	Utility::MemUtils::Copy(buf, 0, Output, Offset, bufLen);
}

void HCR::Fill(std::vector<uint> &Output, size_t Offset, size_t Elements)
{
	CexAssert(Output.size() - Offset <= Elements, "the output array is too short");

	size_t bufLen = Elements * sizeof(uint);
	std::vector<byte> buf(bufLen);
	GetBytes(buf);
	Utility::MemUtils::Copy(buf, 0, Output, Offset, bufLen);
}

void HCR::Fill(std::vector<int64_t> &Output, size_t Offset, size_t Elements)
{
	CexAssert(Output.size() - Offset <= Elements, "the output array is too short");

	size_t bufLen = Elements * sizeof(int64_t);
	std::vector<byte> buf(bufLen);
	GetBytes(buf);
	Utility::MemUtils::Copy(buf, 0, Output, Offset, bufLen);
}

void HCR::Fill(std::vector<ulong> &Output, size_t Offset, size_t Elements)
{
	CexAssert(Output.size() - Offset <= Elements, "the output array is too short");

	size_t bufLen = Elements * sizeof(ulong);
	std::vector<byte> buf(bufLen);
	GetBytes(buf);
	Utility::MemUtils::Copy(buf, 0, Output, Offset, bufLen);
}

std::vector<byte> HCR::GetBytes(size_t Length)
{
	std::vector<byte> rnd(Length);
	GetBytes(rnd);

	return rnd;
}

void HCR::GetBytes(std::vector<byte> &Output, size_t Offset, size_t Length)
{
	CexAssert(Offset + Length <= Output.size(), "the array is too small to fulfill this request");

	std::vector<byte> rnd = GetBytes(Length);
	Utility::MemUtils::Copy(rnd, 0, Output, Offset, Length);
}

void HCR::GetBytes(std::vector<byte> &Output)
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
	Utility::MemUtils::CopyToValue(GetBytes(sizeof(ushort)), 0, x, sizeof(ushort));

	return x;
}

uint HCR::NextUInt32()
{
	uint x = 0;
	Utility::MemUtils::CopyToValue(GetBytes(sizeof(uint)), 0, x, sizeof(uint));

	return x;
}

ulong HCR::NextUInt64()
{
	ulong x = 0;
	Utility::MemUtils::CopyToValue(GetBytes(sizeof(ulong)), 0, x, sizeof(ulong));

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
		seedGen->GetBytes(seed);
		delete seedGen;
		m_rngGenerator->Initialize(seed);
	}

	m_rngGenerator->Generate(m_rngBuffer);
	m_bufferIndex = 0;
}

uint HCR::GetMinimumSeedSize(Digests RngEngine)
{
	uint seedSize = 0;

	switch (RngEngine)
	{
		case Digests::Keccak256:
		{
			seedSize = 136;
			break;
		}
		case Digests::Keccak512:
		case Digests::Keccak1024:
		{
			seedSize = 72;
			break;
		}
		case Digests::Blake256:
		case Digests::SHA256:
		case Digests::Skein512:
		{
			seedSize = 64;
			break;
		}
		case Digests::Blake512:
		case Digests::SHA512:
		case Digests::Skein1024:
		{
			seedSize = 128;
			break;
		}
		case Digests::Skein256:
		{
			seedSize = 32;
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
