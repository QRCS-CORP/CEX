#include "HCR.h"
#include "HCG.h"
#include "MemoryTools.h"
#include "ProviderFromName.h"
#include "SymmetricKey.h"

NAMESPACE_PRNG

using Drbg::HCG;
using Tools::MemoryTools;
using Enumeration::PrngConvert;
using Enumeration::ProviderConvert;
using Enumeration::SHA2DigestConvert;
using Enumeration::SHA2Digests;

class HCR::HcrState
{
public:

	SecureVector<byte> Buffer;
	size_t Position;
	SHA2Digests DigestType;
	Providers ProviderType;

	HcrState(SHA2Digests DigestType, Providers ProviderType)
		:
		Buffer(BUFFER_SIZE),
		Position(0),
		DigestType(DigestType),
		ProviderType(ProviderType)
	{
	}

	~HcrState()
	{
		Reset();
	}

	void Reset()
	{
		MemoryTools::Clear(Buffer, 0, Buffer.size());
		Position = 0;
		DigestType = SHA2Digests::None;
		ProviderType = Providers::None;
	}
};

//~~~Constructor~~~//

HCR::HCR(SHA2Digests DigestType, Providers ProviderType)
	:
	PrngBase(Prngs::HCR, PrngConvert::ToName(Prngs::HCR) + std::string("-") + SHA2DigestConvert::ToName(DigestType) + std::string("-") + ProviderConvert::ToName(ProviderType)),
	m_hcrState(DigestType != SHA2Digests::None && ProviderType != Providers::None ? 
		new HcrState(DigestType, ProviderType) : 
		throw CryptoRandomException(PrngConvert::ToName(Prngs::HCR), std::string("Constructor"), std::string("Digest and Provider types can not be none!"), ErrorCodes::IllegalOperation)),
	m_rngGenerator(new HCG(static_cast<SHA2Digests>(DigestType)))
{
	Reset();
}

HCR::~HCR()
{
	if (m_rngGenerator != nullptr)
	{
		m_rngGenerator.reset(nullptr);
	}

	if (m_hcrState != nullptr)
	{
		m_hcrState.reset(nullptr);
	}
}

//~~~Accessors~~~//

//~~~Public Functions~~~//

void HCR::Generate(std::vector<byte> &Output)
{
	SecureVector<byte> tmp(Output.size());

	Generate(tmp, 0, Output.size(), m_rngGenerator);
	SecureMove(tmp, 0, Output, 0, tmp.size());
}

void HCR::Generate(std::vector<byte> &Output, size_t Offset, size_t Length)
{
	if ((Output.size() - Offset) < Length)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The output buffer is too small!"), ErrorCodes::InvalidSize);
	}

	SecureVector<byte> tmp(Length);

	Generate(tmp, 0, Output.size(), m_rngGenerator);
	SecureMove(tmp, 0, Output, Offset, tmp.size());
}

void HCR::Generate(SecureVector<byte> &Output)
{
	Generate(Output, 0, Output.size(), m_rngGenerator);
}

void HCR::Generate(SecureVector<byte> &Output, size_t Offset, size_t Length)
{
	if ((Output.size() - Offset) < Length)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The output buffer is too small!"), ErrorCodes::InvalidSize);
	}

	Generate(Output, Offset, Length, m_rngGenerator);
}

void HCR::Reset()
{
	// initialize the random provider
	Provider::IProvider* pvd = Helper::ProviderFromName::GetInstance(m_hcrState->ProviderType == Providers::None ? 
		Providers::CSP : 
		m_hcrState->ProviderType);

	if (!pvd->IsAvailable())
	{
		throw CryptoRandomException(Name(), std::string("Reset"), std::string("The random provider can not be instantiated!"), ErrorCodes::NoAccess);
	}

	// use the provider to generate the key
	Cipher::SymmetricKeySize ks = m_rngGenerator->LegalKeySizes()[1];
	std::vector<byte> key(ks.KeySize());
	pvd->Generate(key);
	delete pvd;

	// initialize the drbg
	Cipher::SymmetricKey kp(key);
	m_rngGenerator->Initialize(kp);
	MemoryTools::Clear(key, 0, key.size());

	// fill the buffer
	m_rngGenerator->Generate(m_hcrState->Buffer, 0, m_hcrState->Buffer.size());
}

//~~~Private Functions~~~//

void HCR::Generate(SecureVector<byte> &Output, size_t Offset, size_t Length, std::unique_ptr<IDrbg> &Generator)
{
	const size_t BUFLEN = m_hcrState->Buffer.size() - m_hcrState->Position;

	if (Length != 0)
	{
		if (Length > BUFLEN)
		{
			if (BUFLEN > 0)
			{
				SecureMove(m_hcrState->Buffer, m_hcrState->Position, Output, Offset, BUFLEN);
			}

			while (Length >= m_hcrState->Buffer.size())
			{
				Generator->Generate(m_hcrState->Buffer, 0, m_hcrState->Buffer.size());
				SecureMove(m_hcrState->Buffer, 0, Output, Offset, m_hcrState->Buffer.size());
				Length -= m_hcrState->Buffer.size();
				Offset += m_hcrState->Buffer.size();
			}

			Generator->Generate(m_hcrState->Buffer, 0, m_hcrState->Buffer.size());
			SecureMove(m_hcrState->Buffer, 0, Output, Offset, Length);
			m_hcrState->Position = Length;
		}
		else
		{
			SecureMove(m_hcrState->Buffer, m_hcrState->Position, Output, Offset, Length);
			m_hcrState->Position += Length;
		}
	}
}

NAMESPACE_PRNGEND
