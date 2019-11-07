#include "HCR.h"
#include "HCG.h"
#include "MemoryTools.h"
#include "ProviderFromName.h"
#include "SymmetricKey.h"

NAMESPACE_PRNG

using Drbg::HCG;
using Utility::MemoryTools;
using Enumeration::PrngConvert;
using Enumeration::ProviderConvert;
using Enumeration::SHA2DigestConvert;
using Enumeration::SHA2Digests;

//~~~Constructor~~~//

HCR::HCR(SHA2Digests DigestType, Providers ProviderType)
	:
	PrngBase(Prngs::HCR, PrngConvert::ToName(Prngs::HCR) + std::string("-") + SHA2DigestConvert::ToName(DigestType) + std::string("-") + ProviderConvert::ToName(ProviderType)),
	m_digestType(DigestType != SHA2Digests::None ? DigestType :
		throw CryptoRandomException(PrngConvert::ToName(Prngs::HCR), std::string("Constructor"), std::string("Digest type can not be none!"), ErrorCodes::IllegalOperation)),
	m_pvdType(ProviderType != Providers::None ? ProviderType :
		throw CryptoRandomException(PrngConvert::ToName(Prngs::HCR), std::string("Constructor"), std::string("Provider type can not be none!"), ErrorCodes::InvalidParam)),
	m_rndBuffer(BUFFER_SIZE),
	m_rndIndex(BUFFER_SIZE),
	m_rngGenerator(new HCG(static_cast<SHA2Digests>(DigestType)))
{
	Reset();
}

HCR::~HCR()
{
	m_digestType = SHA2Digests::None;
	m_pvdType = Providers::None;
	m_rndIndex = 0;
	SecureClear(m_rndBuffer);

	if (m_rngGenerator != nullptr)
	{
		m_rngGenerator.reset(nullptr);
	}
}

//~~~Accessors~~~//

//~~~Public Functions~~~//

void HCR::Generate(std::vector<byte> &Output)
{
	GetRandom(Output, 0, Output.size(), m_rngGenerator);
}

void HCR::Generate(std::vector<byte> &Output, size_t Offset, size_t Length)
{
	if ((Output.size() - Offset) < Length)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The output buffer is too small!"), ErrorCodes::InvalidSize);
	}

	GetRandom(Output, Offset, Length, m_rngGenerator);
}

void HCR::Generate(SecureVector<byte> &Output)
{

	GetRandom(Output, 0, Output.size(), m_rngGenerator);
}

void HCR::Generate(SecureVector<byte> &Output, size_t Offset, size_t Length)
{
	if ((Output.size() - Offset) < Length)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The output buffer is too small!"), ErrorCodes::InvalidSize);
	}

	GetRandom(Output, Offset, Length, m_rngGenerator);
}

void HCR::Reset()
{
	Provider::IProvider* pvd = Helper::ProviderFromName::GetInstance(m_pvdType == Providers::None ? Providers::CSP : m_pvdType);

	if (!pvd->IsAvailable())
	{
		throw CryptoRandomException(Name(), std::string("Reset"), std::string("The random provider can not be instantiated!"), ErrorCodes::NoAccess);
	}

	Cipher::SymmetricKeySize ks = m_rngGenerator->LegalKeySizes()[1];
	std::vector<byte> key(ks.KeySize());
	pvd->Generate(key);
	delete pvd;

	Cipher::SymmetricKey kp(key);
	m_rngGenerator->Initialize(kp);
	MemoryTools::Clear(key, 0, key.size());
}

//~~~Private Functions~~~//

void HCR::GetRandom(std::vector<byte> &Output, size_t Offset, size_t Length, std::unique_ptr<IDrbg> &Generator)
{
	const size_t BUFLEN = m_rndBuffer.size() - m_rndIndex;

	if (Length != 0)
	{
		if (Length > BUFLEN)
		{
			if (BUFLEN > 0)
			{
				SecureExtract(m_rndBuffer, m_rndIndex, Output, Offset, BUFLEN);
			}

			while (Length >= m_rndBuffer.size())
			{
				Generator->Generate(m_rndBuffer, 0, m_rndBuffer.size());
				SecureExtract(m_rndBuffer, 0, Output, Offset, m_rndBuffer.size());
				Length -= m_rndBuffer.size();
				Offset += m_rndBuffer.size();
			}

			Generator->Generate(m_rndBuffer, 0, m_rndBuffer.size());
			SecureExtract(m_rndBuffer, 0, Output, Offset, Length);
			m_rndIndex = Length;
		}
		else
		{
			SecureExtract(m_rndBuffer, m_rndIndex, Output, Offset, Length);
			m_rndIndex += Length;
		}
	}

	Generator->Generate(Output, Offset, Length);
}

void HCR::GetRandom(SecureVector<byte> &Output, size_t Offset, size_t Length, std::unique_ptr<IDrbg> &Generator)
{
	const size_t BUFLEN = m_rndBuffer.size() - m_rndIndex;

	if (Length != 0)
	{
		if (Length > BUFLEN)
		{
			if (BUFLEN > 0)
			{
				SecureCopy(m_rndBuffer, m_rndIndex, Output, Offset, BUFLEN);
			}

			while (Length >= m_rndBuffer.size())
			{
				Generator->Generate(m_rndBuffer, 0, m_rndBuffer.size());
				SecureCopy(m_rndBuffer, 0, Output, Offset, m_rndBuffer.size());
				Length -= m_rndBuffer.size();
				Offset += m_rndBuffer.size();
			}

			Generator->Generate(m_rndBuffer, 0, m_rndBuffer.size());
			SecureCopy(m_rndBuffer, 0, Output, Offset, Length);
			m_rndIndex = Length;
		}
		else
		{
			SecureCopy(m_rndBuffer, m_rndIndex, Output, Offset, Length);
			m_rndIndex += Length;
		}
	}
}

NAMESPACE_PRNGEND
