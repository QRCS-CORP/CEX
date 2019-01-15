#include "PBR.h"
#include "DigestFromName.h"
#include "IntegerTools.h"
#include "SHA2Digests.h"

NAMESPACE_PRNG

using Utility::MemoryTools;

const std::string PBR::CLASS_NAME("PBR");

//~~~Constructor~~~//

PBR::PBR(std::vector<byte> &Seed, int Iterations, Digests DigestType, size_t BufferSize)
	:
	m_bufferIndex(0),
	m_bufferSize(BufferSize >= MIN_BUFLEN ? BufferSize :
		throw CryptoRandomException(CLASS_NAME, std::string("Constructor"), std::string("Buffer is too small!"), ErrorCodes::IllegalOperation)),
	m_digestIterations(Iterations != 0 ? Iterations : 
		throw CryptoRandomException(CLASS_NAME, std::string("Constructor"), std::string("Iterations can not be zero!"), ErrorCodes::IllegalOperation)),
	m_digestType(DigestType != Digests::None ? DigestType :
		throw CryptoRandomException(CLASS_NAME, std::string("Constructor"), std::string("Digest type can not be none!"), ErrorCodes::IllegalOperation)),
	m_isDestroyed(false),
	m_rndSeed(Seed.size() >= GetMinimumSeedSize(DigestType) ? Seed :
		throw CryptoRandomException(CLASS_NAME, std::string("Constructor"), std::string("Seed size is too small!"), ErrorCodes::InvalidKey)),
	m_rngBuffer(BufferSize),
	m_rngGenerator(new Kdf::PBKDF2(static_cast<Enumeration::SHA2Digests>(DigestType), m_digestIterations))
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

		Utility::IntegerTools::Clear(m_rndSeed);
		Utility::IntegerTools::Clear(m_rngBuffer);

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

std::vector<byte> PBR::Generate(size_t Length)
{
	std::vector<byte> rnd(Length);
	Generate(rnd);

	return rnd;
}

void PBR::Generate(std::vector<byte> &Output, size_t Offset, size_t Length)
{
	CexAssert(Offset + Length <= Output.size(), "the array is too small to fulfill this request");

	std::vector<byte> rnd = Generate(Length);
	MemoryTools::Copy(rnd, 0, Output, Offset, Length);
}

void PBR::Generate(std::vector<byte> &Output)
{
	CexAssert(Output.size() != 0, "buffer size must be at least 1 in length");

	if (m_rngBuffer.size() - m_bufferIndex < Output.size())
	{
		size_t bufSize = m_rngBuffer.size() - m_bufferIndex;

		// copy remaining bytes
		if (bufSize != 0)
		{
			MemoryTools::Copy(m_rngBuffer, m_bufferIndex, Output, 0, bufSize);
		}

		size_t rem = Output.size() - bufSize;

		while (rem != 0)
		{
			// fill buffer
			m_rngGenerator->Generate(m_rngBuffer);

			if (rem > m_rngBuffer.size())
			{
				MemoryTools::Copy(m_rngBuffer, 0, Output, bufSize, m_rngBuffer.size());
				bufSize += m_rngBuffer.size();
				rem -= m_rngBuffer.size();
			}
			else
			{
				MemoryTools::Copy(m_rngBuffer, 0, Output, bufSize, rem);
				m_bufferIndex = rem;
				rem = 0;
			}
		}
	}
	else
	{
		MemoryTools::Copy(m_rngBuffer, m_bufferIndex, Output, 0, Output.size());
		m_bufferIndex += Output.size();
	}
}

ushort PBR::NextUInt16()
{
	ushort x = 0;
	MemoryTools::CopyToValue(Generate(sizeof(ushort)), 0, x, sizeof(ushort));

	return x;
}

uint PBR::NextUInt32()
{
	uint x = 0;
	MemoryTools::CopyToValue(Generate(sizeof(uint)), 0, x, sizeof(uint));

	return x;
}

ulong PBR::NextUInt64()
{
	ulong x = 0;
	MemoryTools::CopyToValue(Generate(sizeof(ulong)), 0, x, sizeof(ulong));

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
