#include "HCR.h"
#include "HCG.h"
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
	m_rngGenerator(new HCG(static_cast<SHA2Digests>(DigestType)))
{
	Reset();
}

HCR::~HCR()
{
	m_digestType = SHA2Digests::None;
	m_pvdType = Providers::None;

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

	std::vector<byte> key(m_rngGenerator->LegalKeySizes()[1].KeySize());
	pvd->Generate(key);
	delete pvd;
	m_rngGenerator->Initialize(key);
	Clear(key);
}

//~~~Private Functions~~~//

void HCR::GetRandom(std::vector<byte> &Output, size_t Offset, size_t Length, std::unique_ptr<IDrbg> &Generator)
{
	Generator->Generate(Output, Offset, Length);
}

void HCR::GetRandom(SecureVector<byte> &Output, size_t Offset, size_t Length, std::unique_ptr<IDrbg> &Generator)
{
	std::vector<byte> smp(Length);
	// TODO: change this once secure vectors are in drbgs
	Generator->Generate(smp, 0, Length);
	Insert(smp, 0, Output, Offset, Length);
	Clear(smp);
}

NAMESPACE_PRNGEND
