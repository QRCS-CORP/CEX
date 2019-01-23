#include "CSR.h"
#include "CSG.h"
#include "ProviderFromName.h"
#include "SymmetricKey.h"

NAMESPACE_PRNG

using Drbg::CSG;

const std::string CSR::CLASS_NAME("CSR");

//~~~Constructor~~~//

CSR::CSR(ShakeModes ShakeModeType, Providers ProviderType)
	:
	PrngBase(Prngs::CSR),
	m_isDestroyed(false),
	m_pvdType(ProviderType != Providers::None ? ProviderType :
		throw CryptoRandomException(CLASS_NAME, std::string("Constructor"), std::string("Provider type can not be none!"), ErrorCodes::InvalidParam)),
	m_rngGenerator(new CSG(ShakeModeType, ProviderType)),
	m_shakeModeType(ShakeModeType != ShakeModes::None ? ShakeModeType :
		throw CryptoRandomException(CLASS_NAME, std::string("Constructor"), std::string("Shake mode type can not be none!"), ErrorCodes::IllegalOperation))
{
	Reset();
}

CSR::~CSR()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_pvdType = Providers::None;
		m_shakeModeType = ShakeModes::None;

		if (m_rngGenerator != nullptr)
		{
			m_rngGenerator.reset(nullptr);
		}
	}
}

//~~~Accessors~~~//

const std::string CSR::Name()
{
	return CLASS_NAME + "-" + m_rngGenerator->Name();
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
		throw CryptoRandomException(CLASS_NAME, std::string("Generate"), std::string("The output buffer is too small!"), ErrorCodes::InvalidSize);
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
		throw CryptoRandomException(CLASS_NAME, std::string("Generate"), std::string("The output buffer is too small!"), ErrorCodes::InvalidSize);
	}

	GetRandom(Output, Offset, Length, m_rngGenerator);
}

void CSR::Reset()
{
	Provider::IProvider* pvd = Helper::ProviderFromName::GetInstance(m_pvdType);

	if (!pvd->IsAvailable())
	{
		throw CryptoRandomException(CLASS_NAME, std::string("Reset"), std::string("The random provider can not be instantiated!"), ErrorCodes::NoAccess);
	}

	std::vector<byte> key(m_rngGenerator->LegalKeySizes()[1].KeySize());
	std::vector<byte> cust(m_rngGenerator->LegalKeySizes()[1].NonceSize());
	pvd->Generate(key);
	pvd->Generate(cust);
	delete pvd;

	Cipher::SymmetricKey kp(key, cust);
	m_rngGenerator->Initialize(kp);
	Clear(key);
	Clear(cust);
}

//~~~Private Functions~~~//

void CSR::GetRandom(std::vector<byte> &Output, size_t Offset, size_t Length, std::unique_ptr<IDrbg> &Generator)
{
	Generator->Generate(Output, Offset, Length);
}

void CSR::GetRandom(SecureVector<byte> &Output, size_t Offset, size_t Length, std::unique_ptr<IDrbg> &Generator)
{
	std::vector<byte> smp(Length);

	Generator->Generate(smp, 0, Length);
	Insert(smp, 0, Output, Offset, Length);
	Clear(smp);
}

NAMESPACE_PRNGEND
