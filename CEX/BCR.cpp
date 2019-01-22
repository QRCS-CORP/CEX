#include "BCR.h"
#include "IntegerTools.h"
#include "ProviderFromName.h"
#include "SymmetricKey.h"

NAMESPACE_PRNG

using Utility::MemoryTools;

const std::string BCR::CLASS_NAME("BCR");

//~~~Constructor~~~//

BCR::BCR(BlockCiphers CipherType, Providers ProviderType, bool Parallel)
	:
	m_bufferIndex(0),
	m_rngGeneratorType(CipherType != BlockCiphers::None ? CipherType :
		throw CryptoRandomException(CLASS_NAME, std::string("Constructor"), std::string("Cipher type can not be none!"), ErrorCodes::IllegalOperation)),
	m_isDestroyed(false),
	m_isParallel(Parallel),
	m_pvdType(ProviderType == Providers::None ? Providers::ACP : ProviderType),
	m_rndSeed(0),
	m_rngBuffer(0),
	m_rngGenerator(new Drbg::BCG(CipherType, Enumeration::BlockCipherExtensions::HKDF256, m_pvdType))
{
	Reset();
}

BCR::BCR(std::vector<byte> &Seed, BlockCiphers CipherType, bool Parallel)
	:
	m_bufferIndex(0),
	m_rngGeneratorType(CipherType != BlockCiphers::None ? CipherType :
		throw CryptoRandomException(CLASS_NAME, std::string("Constructor"), std::string("Cipher type can not be none!"), ErrorCodes::IllegalOperation)),
	m_isDestroyed(false),
	m_isParallel(Parallel),
	m_pvdType(Providers::ACP),
	m_rndSeed(Seed.size() < 32 ? Seed :
		throw CryptoRandomException(CLASS_NAME, std::string("Constructor"), std::string("Seed size is too small!"), ErrorCodes::InvalidKey)),
	m_rngBuffer(0),
	m_rngGenerator(new Drbg::BCG(CipherType, Enumeration::BlockCipherExtensions::HKDF256, Providers::ACP))
{
	Reset();
}

BCR::~BCR()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_rngGeneratorType = BlockCiphers::None;
		m_pvdType = Providers::None;
		m_bufferIndex = 0;
		m_isParallel = false;

		Utility::IntegerTools::Clear(m_rndSeed);
		Utility::IntegerTools::Clear(m_rngBuffer);

		if (m_rngGenerator != nullptr)
		{
			m_rngGenerator.reset(nullptr);
		}
	}
}

//~~~Accessors~~~//

const Prngs BCR::Enumeral() 
{ 
	return Prngs::BCR; 
}

const std::string BCR::Name() 
{ 
	return CLASS_NAME + "-" + m_rngGenerator->Name();
}

//~~~Public Functions~~~//

std::vector<byte> BCR::Generate(size_t Length)
{
	std::vector<byte> rnd(Length);
	Generate(rnd);

	return rnd;
}

void BCR::Generate(std::vector<byte> &Output, size_t Offset, size_t Length)
{
	CEXASSERT(Offset + Length <= Output.size(), "The array is too small to fulfill this request");

	std::vector<byte> rnd = Generate(Length);
	MemoryTools::Copy(rnd, 0, Output, Offset, Length);
}

void BCR::Generate(std::vector<byte> &Output)
{
	CEXASSERT(Output.size() != 0, "Buffer size must be at least 1 byte in length");

	if (m_rngBuffer.size() - m_bufferIndex < Output.size())
	{
		size_t bufSize = m_rngBuffer.size() - m_bufferIndex;

		// copy remaining bytes
		if (bufSize != 0)
		{
			MemoryTools::Copy(m_rngBuffer, m_bufferIndex, Output, 0, bufSize);
		}

		size_t rmd = Output.size() - bufSize;

		while (rmd > 0)
		{
			// fill buffer
			m_rngGenerator->Generate(m_rngBuffer);

			if (rmd > m_rngBuffer.size())
			{
				MemoryTools::Copy(m_rngBuffer, 0, Output, bufSize, m_rngBuffer.size());
				bufSize += m_rngBuffer.size();
				rmd -= m_rngBuffer.size();
			}
			else
			{
				MemoryTools::Copy(m_rngBuffer, 0, Output, bufSize, rmd);
				m_bufferIndex = rmd;
				rmd = 0;
			}
		}
	}
	else
	{
		MemoryTools::Copy(m_rngBuffer, m_bufferIndex, Output, 0, Output.size());
		m_bufferIndex += Output.size();
	}
}

ushort BCR::NextUInt16()
{
	ushort x = 0;
	MemoryTools::CopyToValue(Generate(sizeof(ushort)), 0, x, sizeof(ushort));

	return x;
}

uint BCR::NextUInt32()
{
	uint x = 0;
	MemoryTools::CopyToValue(Generate(sizeof(uint)), 0, x, sizeof(uint));

	return x;
}

ulong BCR::NextUInt64()
{
	ulong x = 0;
	MemoryTools::CopyToValue(Generate(sizeof(ulong)), 0, x, sizeof(ulong));

	return x;
}

void BCR::Reset()
{
	if (m_isParallel)
	{
		m_isParallel = m_rngGenerator->IsParallel();
	}

	m_rngGenerator->ParallelProfile().IsParallel() = m_isParallel;

	if (m_rndSeed.size() != 0)
	{
		m_rngGenerator->Initialize(m_rndSeed);
	}
	else
	{
		std::vector<byte> seed(m_rngGenerator->LegalKeySizes()[1].KeySize());
		std::vector<byte> nonce(m_rngGenerator->LegalKeySizes()[1].NonceSize());
		Provider::IProvider* seedGen = Helper::ProviderFromName::GetInstance(m_pvdType == Providers::None ? Providers::CSP : m_pvdType);
		seedGen->Generate(seed);
		seedGen->Generate(nonce);
		delete seedGen;
		Cipher::SymmetricKey kp(seed, nonce);
		m_rngGenerator->Initialize(kp);
	}

	m_rngBuffer.resize(m_isParallel ? m_rngGenerator->ParallelBlockSize() : BUFFER_DEF);
	m_rngGenerator->Generate(m_rngBuffer);
	m_bufferIndex = 0;
}

NAMESPACE_PRNGEND
