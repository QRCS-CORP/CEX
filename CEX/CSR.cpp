#include "CSR.h"
#include "CSG.h"
#include "MemoryTools.h"
#include "ProviderFromName.h"
#include "SymmetricKey.h"

NAMESPACE_PRNG

using Drbg::CSG;
using Tools::MemoryTools;
using Enumeration::PrngConvert;
using Enumeration::ProviderConvert;
using Enumeration::ShakeModeConvert;

class CSR::CsrState
{
public:

	SecureVector<byte> Buffer;
	size_t Position;
	Providers ProviderType;
	ShakeModes ShakeType;

	CsrState(ShakeModes ShakeType, Providers ProviderType)
		:
		Buffer(BUFFER_SIZE),
		Position(0),
		ProviderType(ProviderType),
		ShakeType(ShakeType)
	{
	}

	~CsrState()
	{
		Reset();
	}

	void Reset()
	{
		MemoryTools::Clear(Buffer, 0, Buffer.size());
		Position = 0;
		ProviderType = Providers::None;
		ShakeType = ShakeModes::None;
	}
};

//~~~Constructor~~~//

CSR::CSR(ShakeModes ShakeType, Providers ProviderType)
	:
	PrngBase(Prngs::CSR, PrngConvert::ToName(Prngs::CSR) + std::string("-") + ShakeModeConvert::ToName(ShakeType) + std::string("-") + ProviderConvert::ToName(ProviderType)),
	m_csrState(ProviderType != Providers::None && ShakeType != ShakeModes::None ?
		new CsrState(ShakeType, ProviderType) : 
		throw CryptoRandomException(PrngConvert::ToName(Prngs::CSR), std::string("Constructor"), std::string("Shake mode and Provider type can not be none!"), ErrorCodes::InvalidParam)),
	m_rngGenerator(new CSG(ShakeType, ProviderType))
{
	Reset();
}

CSR::~CSR()
{
	if (m_rngGenerator != nullptr)
	{
		m_rngGenerator.reset(nullptr);
	}

	if (m_csrState != nullptr)
	{
		m_csrState.reset(nullptr);
	}
}

//~~~Public Functions~~~//

void CSR::Generate(std::vector<byte> &Output)
{
	SecureVector<byte> tmp(Output.size());

	Generate(tmp, 0, Output.size(), m_rngGenerator);
	SecureMove(tmp, 0, Output, 0, tmp.size());
}

void CSR::Generate(std::vector<byte> &Output, size_t Offset, size_t Length)
{
	if ((Output.size() - Offset) < Length)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The output buffer is too small!"), ErrorCodes::InvalidSize);
	}

	SecureVector<byte> tmp(Length);

	Generate(tmp, 0, Output.size(), m_rngGenerator);
	SecureMove(tmp, 0, Output, Offset, tmp.size());
}

void CSR::Generate(SecureVector<byte> &Output)
{
	Generate(Output, 0, Output.size(), m_rngGenerator);
}

void CSR::Generate(SecureVector<byte> &Output, size_t Offset, size_t Length)
{
	if ((Output.size() - Offset) < Length)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The output buffer is too small!"), ErrorCodes::InvalidSize);
	}

	Generate(Output, Offset, Length, m_rngGenerator);
}

void CSR::Reset()
{
	// initialize the random provider
	Provider::IProvider* pvd = Helper::ProviderFromName::GetInstance(m_csrState->ProviderType);

	if (!pvd->IsAvailable())
	{
		throw CryptoRandomException(Name(), std::string("Reset"), std::string("The random provider can not be instantiated!"), ErrorCodes::NoAccess);
	}

	// use the provider to generate the key
	Cipher::SymmetricKeySize ks = m_rngGenerator->LegalKeySizes()[1];
	std::vector<byte> key(ks.KeySize());
	std::vector<byte> cust(ks.IVSize());
	pvd->Generate(key);
	pvd->Generate(cust);
	delete pvd;

	// initialize the drbg
	Cipher::SymmetricKey kp(key, cust);
	m_rngGenerator->Initialize(kp);
	MemoryTools::Clear(key, 0, key.size());
	MemoryTools::Clear(cust, 0, cust.size());

	// fill the buffer
	m_rngGenerator->Generate(m_csrState->Buffer, 0, m_csrState->Buffer.size());
}

//~~~Private Functions~~~//

void CSR::Generate(SecureVector<byte> &Output, size_t Offset, size_t Length, std::unique_ptr<IDrbg> &Generator)
{
	const size_t BUFLEN = m_csrState->Buffer.size() - m_csrState->Position;

	if (Length != 0)
	{
		if (Length > BUFLEN)
		{
			if (BUFLEN > 0)
			{
				SecureMove(m_csrState->Buffer, m_csrState->Position, Output, Offset, BUFLEN);
			}

			while (Length >= m_csrState->Buffer.size())
			{
				Generator->Generate(m_csrState->Buffer, 0, m_csrState->Buffer.size());
				SecureMove(m_csrState->Buffer, 0, Output, Offset, m_csrState->Buffer.size());
				Length -= m_csrState->Buffer.size();
				Offset += m_csrState->Buffer.size();
			}

			Generator->Generate(m_csrState->Buffer, 0, m_csrState->Buffer.size());
			SecureMove(m_csrState->Buffer, 0, Output, Offset, Length);
			m_csrState->Position = Length;
		}
		else
		{
			SecureMove(m_csrState->Buffer, m_csrState->Position, Output, Offset, Length);
			m_csrState->Position += Length;
		}
	}
}

NAMESPACE_PRNGEND
