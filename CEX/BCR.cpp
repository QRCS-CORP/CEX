#include "BCR.h"
#include "BCG.h"
#include "MemoryTools.h"
#include "ProviderFromName.h"
#include "SymmetricKey.h"

NAMESPACE_PRNG

using Drbg::BCG;
using Enumeration::BlockCipherConvert;
using Tools::MemoryTools;
using Enumeration::PrngConvert;
using Enumeration::ProviderConvert;

class BCR::BcrState
{
public:

	SecureVector<uint8_t> Buffer;
	size_t Position = 0;
	Providers ProviderType;

	BcrState(Providers ProviderType)
		:
		Buffer(BUFFER_SIZE),
		ProviderType(ProviderType)
	{
	}

	~BcrState()
	{
		Reset();
	}

	void Reset()
	{
		MemoryTools::Clear(Buffer, 0, Buffer.size());
		Position = 0;
		ProviderType = Providers::None;
	}
};

//~~~Constructor~~~//

BCR::BCR(Providers ProviderType)
	:
	PrngBase(Prngs::BCR, PrngConvert::ToName(Prngs::BCR) + std::string("-") + std::string("-") + ProviderConvert::ToName(ProviderType)),
	m_bcrState(ProviderType != Providers::None ? 
		new BcrState(ProviderType) :
		throw CryptoRandomException(PrngConvert::ToName(Prngs::BCR), std::string("Constructor"), std::string("Provider type can not be none!"), ErrorCodes::InvalidParam)),
	m_rngGenerator(new BCG(ProviderType))
{
	Reset();
}

BCR::~BCR()
{
	if (m_rngGenerator != nullptr)
	{
		m_rngGenerator.reset(nullptr);
	}

	if (m_bcrState != nullptr)
	{
		m_bcrState.reset(nullptr);
	}
}

//~~~Accessors~~~//

//~~~Public Functions~~~//

void BCR::Generate(std::vector<uint8_t> &Output)
{
	SecureVector<uint8_t> tmp(Output.size());

	Generate(tmp, 0, Output.size(), m_rngGenerator);
	SecureMove(tmp, 0, Output, 0, Output.size());
}

void BCR::Generate(std::vector<uint8_t> &Output, size_t Offset, size_t Length)
{
	if ((Output.size() - Offset) < Length)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The output buffer is too small!"), ErrorCodes::InvalidSize);
	}

	SecureVector<uint8_t> tmp(Length);

	Generate(tmp, 0, Length, m_rngGenerator);
	SecureMove(tmp, 0, Output, Offset, Length);
}

void BCR::Generate(SecureVector<uint8_t> &Output)
{
	Generate(Output, 0, Output.size(), m_rngGenerator);
}

void BCR::Generate(SecureVector<uint8_t> &Output, size_t Offset, size_t Length)
{
	if ((Output.size() - Offset) < Length)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The output buffer is too small!"), ErrorCodes::InvalidSize);
	}

	Generate(Output, Offset, Length, m_rngGenerator);
}

void BCR::Reset()
{
	Cipher::SymmetricKeySize ks = m_rngGenerator->LegalKeySizes()[1];
	std::vector<uint8_t> key(ks.KeySize());
	std::vector<uint8_t> nonce(ks.IVSize());

	// initialize the random provider
	Provider::IProvider* pvd = Helper::ProviderFromName::GetInstance(m_bcrState->ProviderType);

	if (!pvd->IsAvailable())
	{
		throw CryptoRandomException(Name(), std::string("Reset"), std::string("The random provider can not be instantiated!"), ErrorCodes::NoAccess);
	}

	// use the provider to generate the key
	pvd->Generate(key);
	pvd->Generate(nonce);
	delete pvd;

	// initialize the drbg
	Cipher::SymmetricKey kp(key, nonce);
	m_rngGenerator->Initialize(kp);
	MemoryTools::Clear(key, 0, key.size());
	MemoryTools::Clear(nonce, 0, nonce.size());

	// fill the buffer
	m_rngGenerator->Generate(m_bcrState->Buffer, 0, m_bcrState->Buffer.size());
}

//~~~Private Functions~~~//

void BCR::Generate(SecureVector<uint8_t> &Output, size_t Offset, size_t Length, std::unique_ptr<IDrbg> &Generator)
{
	const size_t BUFLEN = m_bcrState->Buffer.size() - m_bcrState->Position;

	if (Length != 0)
	{
		if (Length > BUFLEN)
		{
			if (BUFLEN > 0)
			{
				SecureMove(m_bcrState->Buffer, m_bcrState->Position, Output, Offset, BUFLEN);
			}

			while (Length >= m_bcrState->Buffer.size())
			{
				Generator->Generate(m_bcrState->Buffer, 0, m_bcrState->Buffer.size());
				SecureMove(m_bcrState->Buffer, 0, Output, Offset, m_bcrState->Buffer.size());
				Length -= m_bcrState->Buffer.size();
				Offset += m_bcrState->Buffer.size();
			}

			Generator->Generate(m_bcrState->Buffer, 0, m_bcrState->Buffer.size());
			SecureMove(m_bcrState->Buffer, 0, Output, Offset, Length);
			m_bcrState->Position = Length;
		}
		else
		{
			SecureMove(m_bcrState->Buffer, m_bcrState->Position, Output, Offset, Length);
			m_bcrState->Position += Length;
		}
	}
}

NAMESPACE_PRNGEND
