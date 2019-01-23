#include "BCR.h"
#include "BCG.h"
#include "ProviderFromName.h"
#include "SymmetricKey.h"

NAMESPACE_PRNG

using Drbg::BCG;

const std::string BCR::CLASS_NAME("BCR");

//~~~Constructor~~~//

BCR::BCR(BlockCiphers CipherType, Providers ProviderType, bool Parallel)
	:
	PrngBase(Prngs::BCR),
	m_isDestroyed(false),
	m_isParallel(Parallel),
	m_pvdType(ProviderType != Providers::None ? ProviderType :
		throw CryptoRandomException(CLASS_NAME, std::string("Constructor"), std::string("Provider type can not be none!"), ErrorCodes::InvalidParam)),
	m_rngGenerator(new BCG(CipherType, Enumeration::BlockCipherExtensions::HKDF256, ProviderType)),
	m_rngGeneratorType(CipherType != BlockCiphers::None ? CipherType :
		throw CryptoRandomException(CLASS_NAME, std::string("Constructor"), std::string("Cipher type can not be none!"), ErrorCodes::IllegalOperation))
{
	Reset();
}

BCR::~BCR()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_isParallel = false;
		m_pvdType = Providers::None;
		m_rngGeneratorType = BlockCiphers::None;

		if (m_rngGenerator != nullptr)
		{
			m_rngGenerator.reset(nullptr);
		}
	}
}

//~~~Accessors~~~//

const std::string BCR::Name() 
{ 
	return CLASS_NAME + "-" + m_rngGenerator->Name();
}

//~~~Public Functions~~~//

void BCR::Generate(std::vector<byte> &Output)
{
	GetRandom(Output, 0, Output.size(), m_rngGenerator);
}

void BCR::Generate(std::vector<byte> &Output, size_t Offset, size_t Length)
{
	if ((Output.size() - Offset) < Length)
	{
		throw CryptoRandomException(CLASS_NAME, std::string("Generate"), std::string("The output buffer is too small!"), ErrorCodes::InvalidSize);
	}

	GetRandom(Output, Offset, Length, m_rngGenerator);
}

void BCR::Generate(SecureVector<byte> &Output)
{

	GetRandom(Output, 0, Output.size(), m_rngGenerator);
}

void BCR::Generate(SecureVector<byte> &Output, size_t Offset, size_t Length)
{
	if ((Output.size() - Offset) < Length)
	{
		throw CryptoRandomException(CLASS_NAME, std::string("Generate"), std::string("The output buffer is too small!"), ErrorCodes::InvalidSize);
	}

	GetRandom(Output, Offset, Length, m_rngGenerator);
}

void BCR::Reset()
{
	if (m_isParallel)
	{
		static_cast<BCG*>(m_rngGenerator.get())->IsParallel();
	}

	static_cast<BCG*>(m_rngGenerator.get())->ParallelProfile().IsParallel() = m_isParallel;

	std::vector<byte> key(m_rngGenerator->LegalKeySizes()[1].KeySize());
	std::vector<byte> nonce(m_rngGenerator->LegalKeySizes()[1].NonceSize());

	Provider::IProvider* pvd = Helper::ProviderFromName::GetInstance(m_pvdType);

	if (!pvd->IsAvailable())
	{
		throw CryptoRandomException(CLASS_NAME, std::string("Reset"), std::string("The random provider can not be instantiated!"), ErrorCodes::NoAccess);
	}

	pvd->Generate(key);
	pvd->Generate(nonce);
	delete pvd;

	Cipher::SymmetricKey kp(key, nonce);
	m_rngGenerator->Initialize(kp);
	Clear(key);
	Clear(nonce);
}

//~~~Private Functions~~~//

void BCR::GetRandom(std::vector<byte> &Output, size_t Offset, size_t Length, std::unique_ptr<IDrbg> &Generator)
{
	Generator->Generate(Output, Offset, Length);
}

void BCR::GetRandom(SecureVector<byte> &Output, size_t Offset, size_t Length, std::unique_ptr<IDrbg> &Generator)
{
	std::vector<byte> smp(Length);

	Generator->Generate(smp, 0, Length);
	Insert(smp, 0, Output, Offset, Length);
	Clear(smp);
}

NAMESPACE_PRNGEND
