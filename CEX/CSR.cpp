#include "CSR.h"
#include "CSG.h"
#include "MemoryTools.h"
#include "ProviderFromName.h"
#include "SymmetricKey.h"

NAMESPACE_PRNG

using Drbg::CSG;
using Utility::MemoryTools;
using Enumeration::PrngConvert;
using Enumeration::ProviderConvert;
using Enumeration::ShakeModeConvert;

//~~~Constructor~~~//

CSR::CSR(ShakeModes ShakeModeType, Providers ProviderType)
	:
	PrngBase(Prngs::CSR, PrngConvert::ToName(Prngs::CSR) + std::string("-") + ShakeModeConvert::ToName(ShakeModeType) + std::string("-") + ProviderConvert::ToName(ProviderType)),
	m_pvdType(ProviderType != Providers::None ? ProviderType :
		throw CryptoRandomException(PrngConvert::ToName(Prngs::CSR), std::string("Constructor"), std::string("Provider type can not be none!"), ErrorCodes::InvalidParam)),
	m_rndBuffer(BUFFER_SIZE),
	m_rndIndex(BUFFER_SIZE),
	m_rngGenerator(new CSG(ShakeModeType, ProviderType)),
	m_shakeModeType(ShakeModeType != ShakeModes::None ? ShakeModeType :
		throw CryptoRandomException(PrngConvert::ToName(Prngs::CSR), std::string("Constructor"), std::string("Shake mode type can not be none!"), ErrorCodes::IllegalOperation))
{
	Reset();
}

CSR::~CSR()
{
	m_pvdType = Providers::None;
	m_shakeModeType = ShakeModes::None;
	m_rndIndex = 0;
	Clear(m_rndBuffer);

	if (m_rngGenerator != nullptr)
	{
		m_rngGenerator.reset(nullptr);
	}
}

//~~~Public Functions~~~//

void CSR::Generate(std::vector<byte> &Output)
{
	GetRandom(Output, 0, Output.size(), m_rngGenerator);
}

void CSR::Generate(std::vector<byte> &Output, size_t Offset, size_t Length)
{
	if ((Output.size() - Offset) < Length)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The output buffer is too small!"), ErrorCodes::InvalidSize);
	}

	GetRandom(Output, Offset, Length, m_rngGenerator);
}

void CSR::Generate(SecureVector<byte> &Output)
{

	GetRandom(Output, 0, Output.size(), m_rngGenerator);
}

void CSR::Generate(SecureVector<byte> &Output, size_t Offset, size_t Length)
{
	if ((Output.size() - Offset) < Length)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The output buffer is too small!"), ErrorCodes::InvalidSize);
	}

	GetRandom(Output, Offset, Length, m_rngGenerator);
}

void CSR::Reset()
{
	Provider::IProvider* pvd = Helper::ProviderFromName::GetInstance(m_pvdType);

	if (!pvd->IsAvailable())
	{
		throw CryptoRandomException(Name(), std::string("Reset"), std::string("The random provider can not be instantiated!"), ErrorCodes::NoAccess);
	}

	Cipher::SymmetricKeySize ks = m_rngGenerator->LegalKeySizes()[1];
	std::vector<byte> key(ks.KeySize());
	std::vector<byte> cust(ks.NonceSize());
	pvd->Generate(key);
	pvd->Generate(cust);
	delete pvd;

	Cipher::SymmetricKey kp(key, cust);
	m_rngGenerator->Initialize(kp);
	MemoryTools::Clear(key, 0, key.size());
	MemoryTools::Clear(cust, 0, cust.size());
}

//~~~Private Functions~~~//

void CSR::GetRandom(std::vector<byte> &Output, size_t Offset, size_t Length, std::unique_ptr<IDrbg> &Generator)
{
	const size_t BUFLEN = m_rndBuffer.size() - m_rndIndex;

	if (Length != 0)
	{
		if (Length > BUFLEN)
		{
			if (BUFLEN > 0)
			{
				Extract(m_rndBuffer, m_rndIndex, Output, Offset, BUFLEN);
			}

			while (Length >= m_rndBuffer.size())
			{
				Generator->Generate(m_rndBuffer, 0, m_rndBuffer.size());
				Extract(m_rndBuffer, 0, Output, Offset, m_rndBuffer.size());
				Length -= m_rndBuffer.size();
				Offset += m_rndBuffer.size();
			}

			Generator->Generate(m_rndBuffer, 0, m_rndBuffer.size());
			Extract(m_rndBuffer, 0, Output, Offset, Length);
			m_rndIndex = Length;
		}
		else
		{
			Extract(m_rndBuffer, m_rndIndex, Output, Offset, Length);
			m_rndIndex += Length;
		}
	}

	Generator->Generate(Output, Offset, Length);
}

void CSR::GetRandom(SecureVector<byte> &Output, size_t Offset, size_t Length, std::unique_ptr<IDrbg> &Generator)
{
	const size_t BUFLEN = m_rndBuffer.size() - m_rndIndex;

	if (Length != 0)
	{
		if (Length > BUFLEN)
		{
			if (BUFLEN > 0)
			{
				Copy(m_rndBuffer, m_rndIndex, Output, Offset, BUFLEN);
			}

			while (Length >= m_rndBuffer.size())
			{
				Generator->Generate(m_rndBuffer, 0, m_rndBuffer.size());
				Copy(m_rndBuffer, 0, Output, Offset, m_rndBuffer.size());
				Length -= m_rndBuffer.size();
				Offset += m_rndBuffer.size();
			}

			Generator->Generate(m_rndBuffer, 0, m_rndBuffer.size());
			Copy(m_rndBuffer, 0, Output, Offset, Length);
			m_rndIndex = Length;
		}
		else
		{
			Copy(m_rndBuffer, m_rndIndex, Output, Offset, Length);
			m_rndIndex += Length;
		}
	}
}

NAMESPACE_PRNGEND
