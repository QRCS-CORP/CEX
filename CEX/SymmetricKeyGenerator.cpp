#include "SymmetricKeyGenerator.h"
#include "ArrayTools.h"
#include "ProviderFromName.h"
#include "SHAKE.h"

NAMESPACE_CIPHER

using Enumeration::ErrorCodes;
using Tools::ArrayTools;

const std::string SymmetricKeyGenerator::CLASS_NAME = "SymmetricKeyGenerator";

//~~~Constructor~~~//

SymmetricKeyGenerator::SymmetricKeyGenerator(SecurityPolicy Policy, Providers ProviderType)
	:
	m_providerType(ProviderType != Providers::None ? ProviderType :
		throw CryptoGeneratorException(CLASS_NAME, std::string("Constructor"), std::string("The provider type can nor be None!"), ErrorCodes::InvalidParam)),
	m_securityPolicy(Policy != SecurityPolicy::None ? Policy :
		throw CryptoGeneratorException(CLASS_NAME, std::string("Constructor"), std::string("The policy type can nor be None!"), ErrorCodes::InvalidParam))
{
}

SymmetricKeyGenerator::~SymmetricKeyGenerator()
{
	m_providerType = Providers::None;
	m_securityPolicy = SecurityPolicy::None;
}

const std::string SymmetricKeyGenerator::Name()
{
	return CLASS_NAME;
}

//~~~Public Functions~~~//

SymmetricKey* SymmetricKeyGenerator::GetSymmetricKey(SymmetricKeySize KeySize)
{
	if (KeySize.KeySize() == 0)
	{
		throw CryptoGeneratorException(Name(), std::string("GetSymmetricKey"), std::string("The key size can not be zero!"), ErrorCodes::InvalidSize);
	}

	SymmetricKey* pkey;

	if (KeySize.IVSize() != 0)
	{
		if (KeySize.InfoSize() != 0)
		{
			SecureVector<uint8_t> tmpk(KeySize.KeySize());
			SecureVector<uint8_t> tmpn(KeySize.IVSize());
			SecureVector<uint8_t> tmpi(KeySize.InfoSize());

			Generate(m_providerType, m_securityPolicy, tmpk, 0, tmpk.size());
			Generate(m_providerType, m_securityPolicy, tmpn, 0, tmpn.size());
			Generate(m_providerType, m_securityPolicy, tmpi, 0, tmpi.size());

			pkey = new SymmetricKey(tmpk, tmpn, tmpi);

		}
		else
		{
			SecureVector<uint8_t> tmpk(KeySize.KeySize());
			SecureVector<uint8_t> tmpn(KeySize.IVSize());

			Generate(m_providerType, m_securityPolicy, tmpk, 0, tmpk.size());
			Generate(m_providerType, m_securityPolicy, tmpn, 0, tmpn.size());

			pkey = new SymmetricKey(tmpk, tmpn);
		}
	}
	else
	{
		SecureVector<uint8_t> tmpk(KeySize.KeySize());

		Generate(m_providerType, m_securityPolicy, tmpk, 0, tmpk.size());

		pkey = new SymmetricKey(tmpk);
	}

	return pkey;
}

SymmetricSecureKey* SymmetricKeyGenerator::GetSecureKey(SymmetricKeySize KeySize)
{
	if (KeySize.KeySize() == 0)
	{
		throw CryptoGeneratorException(Name(), std::string("GetSecureKey"), std::string("The key size can not be zero!"), ErrorCodes::InvalidSize);
	}

	SymmetricSecureKey* pkey = nullptr;

	if (KeySize.IVSize() != 0)
	{
		if (KeySize.InfoSize() != 0)
		{
			SecureVector<uint8_t> tmpk(KeySize.KeySize());
			SecureVector<uint8_t> tmpn(KeySize.IVSize());
			SecureVector<uint8_t> tmpi(KeySize.InfoSize());

			Generate(m_providerType, m_securityPolicy, tmpk, 0, tmpk.size());
			Generate(m_providerType, m_securityPolicy, tmpn, 0, tmpn.size());
			Generate(m_providerType, m_securityPolicy, tmpi, 0, tmpi.size());

			pkey = new SymmetricSecureKey(tmpk, tmpn, tmpi);
		}
		else
		{
			SecureVector<uint8_t> tmpk(KeySize.KeySize());
			SecureVector<uint8_t> tmpn(KeySize.IVSize());

			Generate(m_providerType, m_securityPolicy, tmpk, 0, tmpk.size());
			Generate(m_providerType, m_securityPolicy, tmpn, 0, tmpn.size());

			pkey = new SymmetricSecureKey(tmpk, tmpn);
		}
	}
	else
	{
		SecureVector<uint8_t> tmpk(KeySize.KeySize());

		Generate(m_providerType, m_securityPolicy, tmpk, 0, tmpk.size());

		pkey = new SymmetricSecureKey(tmpk);
	}

	return pkey;
}

void SymmetricKeyGenerator::Generate(SecureVector<uint8_t> &Output, size_t Offset, size_t Length)
{
	if (Length == 0)
	{
		throw CryptoGeneratorException(Name(), std::string("Generate"), std::string("The requested allocation can not be zero size!"), ErrorCodes::InvalidSize);
	}
	if (Output.size() < Offset + Length)
	{
		throw CryptoGeneratorException(Name(), std::string("Generate"), std::string("The output vector is too small!"), ErrorCodes::InvalidSize);
	}

	Generate(m_providerType, m_securityPolicy, Output, Offset, Length);
}

SecureVector<uint8_t> SymmetricKeyGenerator::Generate(size_t Length)
{
	if (Length == 0)
	{
		throw CryptoGeneratorException(Name(), std::string("Generate"), std::string("The requested allocation can not be zero size!"), ErrorCodes::InvalidSize);
	}

	SecureVector<uint8_t> tmpr(Length);

	Generate(m_providerType, m_securityPolicy, tmpr, 0, tmpr.size());

	return tmpr;
}

//~~~Private Functions~~~//

void SymmetricKeyGenerator::Generate(Providers Provider, SecurityPolicy Policy, SecureVector<uint8_t> &Output, size_t Offset, size_t Length)
{
	SecureVector<uint8_t> tmpc(0);
	Enumeration::ShakeModes mode;
	size_t klen;

	switch (Policy)
	{
		case SecurityPolicy::SPL256:
		case SecurityPolicy::SPL256AE:
		{
			mode = Enumeration::ShakeModes::SHAKE256;
			klen = 32;
			break;
		}
		case SecurityPolicy::SPL512:
		case SecurityPolicy::SPL512AE:
		{
			klen = 64;
			mode = Enumeration::ShakeModes::SHAKE512;
			break;
		}
		default:
		{
			mode = Enumeration::ShakeModes::SHAKE256;
			klen = 32;
			break;
		}
	}

	// instantiate the provider and create the seed
	Provider::IProvider* pvd = Helper::ProviderFromName::GetInstance(Provider);
	SecureVector<uint8_t> tmpk(klen);
	pvd->Generate(tmpk);

	// create the SHAKE instance aligned to the security policy
	Kdf::SHAKE gen(mode);

	// customization string is name + provider-name + shake-name
	ArrayTools::AppendString(CLASS_NAME, tmpc);
	ArrayTools::AppendString(pvd->Name(), tmpc);
	ArrayTools::AppendString(gen.Name(), tmpc);

	gen.Initialize(tmpk, tmpc);
	gen.Generate(Output, Offset, Length);
}

NAMESPACE_CIPHEREND
