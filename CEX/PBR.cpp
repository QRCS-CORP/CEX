#include "PBR.h"
#include "DigestFromName.h"
#include "IntUtils.h"

NAMESPACE_PRNG

const std::string PBR::CLASS_NAME("PBR");

//~~~Constructor~~~//

PBR::PBR(std::vector<byte> &Seed, int Iterations, Digests DigestEngine, size_t BufferSize)
	:
	m_bufferIndex(0),
	m_bufferSize(BufferSize >= MIN_BUFSZE ? BufferSize :
		throw CryptoRandomException("PBR:Ctor", "BufferSize must be at least 64 bytes!")),
	m_digestIterations(Iterations != 0 ? Iterations : 
		throw CryptoRandomException("PBR:Ctor", "Iterations can not be zero; at least 1 iteration is required!")),
	m_digestType(DigestEngine != Digests::None ? DigestEngine :
		throw CryptoRandomException("PBR:Ctor", "Digest type can not be none!")),
	m_isDestroyed(false),
	m_rndSeed(Seed.size() >= GetMinimumSeedSize(DigestEngine) ? Seed :
		throw CryptoRandomException("PBR:Ctor", "The seed is too small!")),
	m_rngBuffer(BufferSize),
	m_rngGenerator(new Kdf::PBKDF2(m_digestType, m_digestIterations))
{
	Reset();
}

PBR::~PBR()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_bufferIndex = 0;
		m_bufferSize = 0;
		m_digestIterations = 0;
		m_digestType = Digests::None;

		Utility::IntUtils::ClearVector(m_rndSeed);
		Utility::IntUtils::ClearVector(m_rngBuffer);

		if (m_rngGenerator != nullptr)
		{
			m_rngGenerator.reset(nullptr);
		}
	}
}

//~~~Accessors~~~//

const Prngs PBR::Enumeral()
{
	return Prngs::PBR;
}

const std::string PBR::Name()
{
	return CLASS_NAME + "-" + m_rngGenerator->Name();
}

//~~~Public Functions~~~//

void PBR::Fill(std::vector<ushort> &Output, size_t Offset, size_t Elements)
{
	CexAssert(Output.size() - Offset <= Elements, "the output array is too short");

	size_t bufLen = Elements * sizeof(ushort);
	std::vector<byte> buf(bufLen);
	GetBytes(buf);
	Utility::MemUtils::Copy(buf, 0, Output, Offset, bufLen);
}

void PBR::Fill(std::vector<uint> &Output, size_t Offset, size_t Elements)
{
	CexAssert(Output.size() - Offset <= Elements, "the output array is too short");

	size_t bufLen = Elements * sizeof(uint);
	std::vector<byte> buf(bufLen);
	GetBytes(buf);
	Utility::MemUtils::Copy(buf, 0, Output, Offset, bufLen);
}

void PBR::Fill(std::vector<ulong> &Output, size_t Offset, size_t Elements)
{
	CexAssert(Output.size() - Offset <= Elements, "the output array is too short");

	size_t bufLen = Elements * sizeof(ulong);
	std::vector<byte> buf(bufLen);
	GetBytes(buf);
	Utility::MemUtils::Copy(buf, 0, Output, Offset, bufLen);
}

std::vector<byte> PBR::GetBytes(size_t Length)
{
	std::vector<byte> rnd(Length);
	GetBytes(rnd);

	return rnd;
}

void PBR::GetBytes(std::vector<byte> &Output, size_t Offset, size_t Length)
{
	CexAssert(Offset + Length <= Output.size(), "the array is too small to fulfill this request");

	std::vector<byte> rnd = GetBytes(Length);
	Utility::MemUtils::Copy(rnd, 0, Output, Offset, Length);
}

void PBR::GetBytes(std::vector<byte> &Output)
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

		size_t rem = Output.size() - bufSize;

		while (rem != 0)
		{
			// fill buffer
			m_rngGenerator->Generate(m_rngBuffer);

			if (rem > m_rngBuffer.size())
			{
				Utility::MemUtils::Copy(m_rngBuffer, 0, Output, bufSize, m_rngBuffer.size());
				bufSize += m_rngBuffer.size();
				rem -= m_rngBuffer.size();
			}
			else
			{
				Utility::MemUtils::Copy(m_rngBuffer, 0, Output, bufSize, rem);
				m_bufferIndex = rem;
				rem = 0;
			}
		}
	}
	else
	{
		Utility::MemUtils::Copy(m_rngBuffer, m_bufferIndex, Output, 0, Output.size());
		m_bufferIndex += Output.size();
	}
}

ushort PBR::NextUInt16()
{
	ushort x = 0;
	Utility::MemUtils::CopyToValue(GetBytes(sizeof(ushort)), 0, x, sizeof(ushort));

	return x;
}

uint PBR::NextUInt32()
{
	uint x = 0;
	Utility::MemUtils::CopyToValue(GetBytes(sizeof(uint)), 0, x, sizeof(uint));

	return x;
}

ulong PBR::NextUInt64()
{
	ulong x = 0;
	Utility::MemUtils::CopyToValue(GetBytes(sizeof(ulong)), 0, x, sizeof(ulong));

	return x;
}

void PBR::Reset()
{
	m_rngGenerator->Initialize(m_rndSeed);
	m_rngGenerator->Generate(m_rngBuffer);
	m_bufferIndex = 0;
}

uint PBR::GetMinimumSeedSize(Digests RngEngine)
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