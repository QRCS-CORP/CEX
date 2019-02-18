#include "SymmetricKeyGenerator.h"
#include "ArrayTools.h"
#include "IntegerTools.h"
#include "ProviderFromName.h"
#include "SHAKE.h"

NAMESPACE_CIPHER

using Enumeration::ErrorCodes;

const std::string SymmetricKeyGenerator::CLASS_NAME = "SymmetricKeyGenerator";

const std::vector<byte> SymmetricKeyGenerator::SIGMA_INFO = { 0x53, 0x79, 0x6D, 0x6D, 0x65, 0x74, 0x72, 0x69, 0x63, 0x4B, 0x65, 0x79, 0x47, 0x65, 0x6E, 0x65, 0x72, 0x61, 0x74, 0x6F, 0x72 };

//~~~Constructor~~~//

// TODO: seamless migrate to secure-vectors
SymmetricKeyGenerator::SymmetricKeyGenerator(SecurityPolicy Policy, Providers ProviderType)
	:
	m_isDestroyed(false),
	m_pvdType(ProviderType != Providers::None ? ProviderType :
		throw CryptoGeneratorException(CLASS_NAME, std::string("Constructor"), std::string("The provider type can nor be None!"), ErrorCodes::InvalidParam)),
	m_secPolicy(Policy != SecurityPolicy::None ? Policy :
		throw CryptoGeneratorException(CLASS_NAME, std::string("Constructor"), std::string("The policy type can nor be None!"), ErrorCodes::InvalidParam)),
	m_shakeCustom(SIGMA_INFO)
{
}

SymmetricKeyGenerator::SymmetricKeyGenerator(SecurityPolicy Policy, const std::vector<byte> &Customization, Providers ProviderType)
	:
	m_isDestroyed(false),
	m_pvdType(ProviderType != Providers::None ? ProviderType :
		throw CryptoGeneratorException(CLASS_NAME, std::string("Constructor"), std::string("The provider type can nor be None!"), ErrorCodes::InvalidParam)),
	m_secPolicy(Policy != SecurityPolicy::None ? Policy :
		throw CryptoGeneratorException(CLASS_NAME, std::string("Constructor"), std::string("The policy type can nor be None!"), ErrorCodes::InvalidParam)),
	m_shakeCustom(Customization.size() != 0 ? Customization:
		throw CryptoGeneratorException(CLASS_NAME, std::string("Constructor"), std::string("The customization array can not be zero length!"), ErrorCodes::InvalidParam))
{
}

SymmetricKeyGenerator::~SymmetricKeyGenerator()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_pvdType = Providers::None;
		m_secPolicy = SecurityPolicy::None;
		Utility::IntegerTools::Clear(m_shakeCustom);
	}
}

const std::string SymmetricKeyGenerator::Name()
{
	std::string name;

	name = Enumeration::SecurityPolicyConvert::ToName(m_secPolicy) + std::string("-") + Enumeration::ProviderConvert::ToName(m_pvdType);

	return name;
}

//~~~Public Functions~~~//

SymmetricKey* SymmetricKeyGenerator::GetSymmetricKey(SymmetricKeySize KeySize)
{
	if (KeySize.KeySize() == 0)
	{
		throw CryptoGeneratorException(CLASS_NAME, std::string("GetSymmetricKey"), std::string("The key size can not be zero!"), ErrorCodes::InvalidSize);
	}

	SymmetricKey* key;

	if (KeySize.NonceSize() != 0)
	{
		if (KeySize.InfoSize() != 0)
		{
			key = new SymmetricKey(Generate(KeySize.KeySize()), Generate(KeySize.NonceSize()), Generate(KeySize.InfoSize()));

		}
		else
		{
			key = new SymmetricKey(Generate(KeySize.KeySize()), Generate(KeySize.NonceSize()));
		}
	}
	else
	{
		key = new SymmetricKey(Generate(KeySize.KeySize()));
	}

	return key;
}

SymmetricSecureKey* SymmetricKeyGenerator::GetSecureKey(SymmetricKeySize KeySize)
{
	if (KeySize.KeySize() == 0)
	{
		throw CryptoGeneratorException(CLASS_NAME, std::string("GetSecureKey"), std::string("The key size can not be zero!"), ErrorCodes::InvalidSize);
	}
	// TODO: fill with secure vectors from updated prngs..
	SymmetricSecureKey* key = nullptr;

	if (KeySize.NonceSize() != 0)
	{
		if (KeySize.InfoSize() != 0)
		{
			key = new SymmetricSecureKey(Generate(KeySize.KeySize()), Generate(KeySize.NonceSize()), Generate(KeySize.InfoSize()), m_secPolicy, m_shakeCustom);
		}
		else
		{
			key = new SymmetricSecureKey(Generate(KeySize.KeySize()), Generate(KeySize.NonceSize()), m_secPolicy, m_shakeCustom);
		}
	}
	else
	{
		key = new SymmetricSecureKey(Generate(KeySize.KeySize()), m_secPolicy, m_shakeCustom);
	}

	return key;
}

void SymmetricKeyGenerator::Generate(std::vector<byte> &Output, size_t Offset, size_t Length)
{
	Generate(m_pvdType, m_secPolicy, m_shakeCustom, Output, Offset, Length);
}

std::vector<byte> SymmetricKeyGenerator::Generate(size_t Length)
{
	std::vector<byte> tmpr(Length);

	Generate(m_pvdType, m_secPolicy, m_shakeCustom, tmpr, 0, tmpr.size());

	return tmpr;
}

//~~~Private Functions~~~//

void SymmetricKeyGenerator::Generate(Providers Provider, SecurityPolicy Policy, const std::vector<byte> &Salt, std::vector<byte> &Output, size_t Offset, size_t Length)
{
	std::vector<byte> cust(0);
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
			klen = 128;
			mode = Enumeration::ShakeModes::SHAKE1024;
		}
	}

	// instantiate the provider and create the seed
	Provider::IProvider* pvd = Helper::ProviderFromName::GetInstance(Provider);
	std::vector<byte> seed(klen);
	pvd->Generate(seed);

	// initialize cSHAKE and generate output
	Kdf::SHAKE gen(mode);

	// customization string is salt/name + provider-name + shake-name
	Utility::ArrayTools::AppendVector(Salt, cust);
	Utility::ArrayTools::AppendString(pvd->Name(), cust);
	Utility::ArrayTools::AppendString(gen.Name(), cust);

	gen.Initialize(seed, Salt);
	gen.Generate(Output, Offset, Length);
}

NAMESPACE_CIPHEREND
