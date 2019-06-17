#include "NTRUPrime.h"
#include "IntegerTools.h"
#include "NTRUSQ4621P653.h"
#include "NTRUSQ4591P761.h"
#include "NTRUSQ5167P857.h"
#include "PrngFromName.h"
#include "Keccak.h"
#include "SymmetricKey.h"

NAMESPACE_NTRUPRIME

using Enumeration::AsymmetricPrimitiveConvert;
using Enumeration::ErrorCodes;
using Utility::IntegerTools;
using Digest::Keccak;
using Enumeration::NTRUParameterConvert;

class NTRUPrime::NtruState
{
public:

	std::vector<byte> DomainKey;
	bool Destroyed;
	bool Encryption;
	bool Initialized;
	NTRUParameters Parameters;

	NtruState(NTRUParameters Params, bool Destroy)
		:
		DomainKey(0),
		Destroyed(Destroy),
		Encryption(false),
		Initialized(false),
		Parameters(Params)
	{
	}

	~NtruState()
	{
		IntegerTools::Clear(DomainKey);
		Destroyed = false;
		Encryption = false;
		Initialized = false;
		Parameters = NTRUParameters::None;
	}
};

//~~~Constructor~~~//

NTRUPrime::NTRUPrime(NTRUParameters Parameters, Prngs PrngType)
	:
	m_ntruState(new NtruState(Parameters != NTRUParameters::None ? Parameters :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::NTRUPrime), std::string("Constructor"), std::string("The ModuleLWE parameter set is invalid!"), ErrorCodes::InvalidParam),
		true)),
	m_rndGenerator(PrngType != Prngs::None ? Helper::PrngFromName::GetInstance(PrngType) :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::NTRUPrime), std::string("Constructor"), std::string("The prng type can not be none!"), ErrorCodes::InvalidParam))
{
}

NTRUPrime::NTRUPrime(NTRUParameters Parameters, IPrng* Prng)
	:
	m_ntruState(new NtruState(Parameters != NTRUParameters::None ? Parameters :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::NTRUPrime), std::string("Constructor"), std::string("The ModuleLWE parameter set is invalid!"), ErrorCodes::InvalidParam),
		false)),
	m_rndGenerator(Prng != nullptr ? Prng :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::NTRUPrime), std::string("Constructor"), std::string("The prng can not be null!"), ErrorCodes::InvalidParam))
{
}

NTRUPrime::~NTRUPrime()
{
	// release keys
	if (m_privateKey != nullptr)
	{
		m_privateKey.release();
	}

	if (m_publicKey != nullptr)
	{
		m_publicKey.release();
	}

	if (m_ntruState->Destroyed)
	{
		if (m_rndGenerator != nullptr)
		{
			// destroy internally generated objects
			m_rndGenerator.reset(nullptr);
		}
	}
	else
	{
		if (m_rndGenerator != nullptr)
		{
			// release the generator (received through ctor2) back to caller
			m_rndGenerator.release();
		}
	}
}

//~~~Accessors~~~//

const size_t NTRUPrime::CipherTextSize()
{
	size_t clen;

	switch (m_ntruState->Parameters)
	{
		case (NTRUParameters::NTRUS1SQ4621N653):
		{
			clen = NTRUSQ4621P653::CIPHERTEXT_SIZE;
			break;
		}
		case (NTRUParameters::NTRUS2SQ4591N761):
		{
			clen = NTRUSQ4591P761::CIPHERTEXT_SIZE;
			break;
		}
		case (NTRUParameters::NTRUS3SQ5167N857):
		{
			clen = NTRUSQ5167P857::CIPHERTEXT_SIZE;
			break;
		}
		default:
		{
			throw CryptoAsymmetricException(Name(), std::string("CipherTextSize"), std::string("The NTRUPrime parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	return clen;
}

std::vector<byte> &NTRUPrime::DomainKey()
{
	return m_ntruState->DomainKey;
}

const AsymmetricPrimitives NTRUPrime::Enumeral()
{
	return AsymmetricPrimitives::NTRUPrime;
}

const bool NTRUPrime::IsEncryption()
{
	return m_ntruState->Encryption;
}

const bool NTRUPrime::IsInitialized()
{
	return m_ntruState->Initialized;
}

const std::string NTRUPrime::Name()
{
	std::string ret;

	ret = AsymmetricPrimitiveConvert::ToName(Enumeral()) + 
		std::string("-") + 
		NTRUParameterConvert::ToName(m_ntruState->Parameters);

	return ret;
}

const NTRUParameters NTRUPrime::Parameters()
{
	return m_ntruState->Parameters;
}

const size_t NTRUPrime::PrivateKeySize()
{
	size_t klen;

	switch (m_ntruState->Parameters)
	{
		case (NTRUParameters::NTRUS1SQ4621N653):
		{
			klen = NTRUSQ4621P653::PRIVATEKEY_SIZE;
			break;
		}
		case (NTRUParameters::NTRUS2SQ4591N761):
		{
			klen = NTRUSQ4591P761::PRIVATEKEY_SIZE;
			break;
		}
		case (NTRUParameters::NTRUS3SQ5167N857):
		{
			klen = NTRUSQ5167P857::PRIVATEKEY_SIZE;
			break;
		}
		default:
		{
			throw CryptoAsymmetricException(Name(), std::string("PrivateKeySize"), std::string("The NTRUPrime parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	return klen;
}

const size_t NTRUPrime::PublicKeySize()
{
	size_t klen;

	switch (m_ntruState->Parameters)
	{
		case (NTRUParameters::NTRUS1SQ4621N653):
		{
			klen = NTRUSQ4621P653::PUBLICKEY_SIZE;
			break;
		}
		case (NTRUParameters::NTRUS2SQ4591N761):
		{
			klen = NTRUSQ4591P761::PUBLICKEY_SIZE;
			break;
		}
		case (NTRUParameters::NTRUS3SQ5167N857):
		{
			klen = NTRUSQ5167P857::PUBLICKEY_SIZE;
			break;
		}
		default:
		{
			throw CryptoAsymmetricException(Name(), std::string("PublicKeySize"), std::string("The NTRUPrime parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	return klen;
}

const size_t NTRUPrime::SharedSecretSize()
{
	return SECRET_SIZE;
}

//~~~Public Functions~~~//

bool NTRUPrime::Decapsulate(const std::vector<byte> &CipherText, std::vector<byte> &SharedSecret)
{
	CEXASSERT(m_ntruState->Initialized, "The cipher has not been initialized");
	CEXASSERT(SharedSecret.size() <= 256, "The shared secret size is too large");

	std::vector<byte> sec(SECRET_SIZE);
	bool result;

	switch (m_ntruState->Parameters)
	{
		case NTRUParameters::NTRUS1SQ4621N653:
		{
			result = NTRUSQ4621P653::Decapsulate(sec, CipherText, m_privateKey->Polynomial());
			break;
		}
		case NTRUParameters::NTRUS2SQ4591N761:
		{
			result = NTRUSQ4591P761::Decapsulate(sec, CipherText, m_privateKey->Polynomial());
			break;
		}
		case NTRUParameters::NTRUS3SQ5167N857:
		{
			result = NTRUSQ5167P857::Decapsulate(sec, CipherText, m_privateKey->Polynomial());
			break;
		}
		default:
		{
			throw CryptoAsymmetricException(Name(), std::string("Decapsulate"), std::string("The NTRU-Prime parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	if (m_ntruState->DomainKey.size() != 0)
	{
		CXOF(m_ntruState->DomainKey, sec, SharedSecret, Keccak::KECCAK512_RATE_SIZE);
	}
	else
	{
		SharedSecret.resize(sec.size());
		MemoryTools::Copy(sec, 0, SharedSecret, 0, sec.size());
	}

	return result;
}

void NTRUPrime::Encapsulate(std::vector<byte> &CipherText, std::vector<byte> &SharedSecret)
{
	CEXASSERT(m_ntruState->Initialized, "The cipher has not been initialized");
	CEXASSERT(SharedSecret.size() <= 256, "The shared secret size is too large");

	std::vector<byte> sec(SECRET_SIZE);

	switch (m_ntruState->Parameters)
	{
		case NTRUParameters::NTRUS1SQ4621N653:
		{
			CipherText.resize(NTRUSQ4621P653::CIPHERTEXT_SIZE);
			NTRUSQ4621P653::Encapsulate(sec, CipherText, m_publicKey->Polynomial(), m_rndGenerator);
			break;
		}
		case NTRUParameters::NTRUS2SQ4591N761:
		{
			CipherText.resize(NTRUSQ4591P761::CIPHERTEXT_SIZE);
			NTRUSQ4591P761::Encapsulate(sec, CipherText, m_publicKey->Polynomial(), m_rndGenerator);
			break;
		}
		case NTRUParameters::NTRUS3SQ5167N857:
		{
			CipherText.resize(NTRUSQ5167P857::CIPHERTEXT_SIZE);
			NTRUSQ5167P857::Encapsulate(sec, CipherText, m_publicKey->Polynomial(), m_rndGenerator);
			break;
		}
		default:
		{
			throw CryptoAsymmetricException(Name(), std::string("Encapsulate"), std::string("The NTRU-Prime parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	if (m_ntruState->DomainKey.size() != 0)
	{
		CXOF(m_ntruState->DomainKey, sec, SharedSecret, Keccak::KECCAK512_RATE_SIZE);
	}
	else
	{
		SharedSecret.resize(sec.size());
		MemoryTools::Copy(sec, 0, SharedSecret, 0, sec.size());
	}
}

AsymmetricKeyPair* NTRUPrime::Generate()
{
	CEXASSERT(m_ntruState->Parameters != NTRUParameters::None, "The parameter setting is invalid");

	std::vector<byte> pk(0);
	std::vector<byte> sk(0);

	switch (m_ntruState->Parameters)
	{
		case NTRUParameters::NTRUS1SQ4621N653:
		{
			pk.resize(NTRUSQ4621P653::PUBLICKEY_SIZE);
			sk.resize(NTRUSQ4621P653::PRIVATEKEY_SIZE);
			NTRUSQ4621P653::Generate(pk, sk, m_rndGenerator);
			break;
		}
		case NTRUParameters::NTRUS2SQ4591N761:
		{
			pk.resize(NTRUSQ4591P761::PUBLICKEY_SIZE);
			sk.resize(NTRUSQ4591P761::PRIVATEKEY_SIZE);
			NTRUSQ4591P761::Generate(pk, sk, m_rndGenerator);
			break;
		}
		case NTRUParameters::NTRUS3SQ5167N857:
		{
			pk.resize(NTRUSQ5167P857::PUBLICKEY_SIZE);
			sk.resize(NTRUSQ5167P857::PRIVATEKEY_SIZE);
			NTRUSQ5167P857::Generate(pk, sk, m_rndGenerator);
			break;
		}
		default:
		{
			throw CryptoAsymmetricException(Name(), std::string("Generate"), std::string("The NTRU-Prime parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	AsymmetricKey* apk = new AsymmetricKey(pk, AsymmetricPrimitives::NTRUPrime, AsymmetricKeyTypes::CipherPublicKey, static_cast<AsymmetricTransforms>(m_ntruState->Parameters));
	AsymmetricKey* ask = new AsymmetricKey(sk, AsymmetricPrimitives::NTRUPrime, AsymmetricKeyTypes::CipherPrivateKey, static_cast<AsymmetricTransforms>(m_ntruState->Parameters));

	return new AsymmetricKeyPair(ask, apk);
}

void NTRUPrime::Initialize(AsymmetricKey* Key)
{
	if (Key->PrimitiveType() != AsymmetricPrimitives::NTRUPrime)
	{
		throw CryptoAsymmetricException(Name(), std::string("Initialize"), std::string("The key is invalid!"), ErrorCodes::InvalidKey);
	}

	if (Key->KeyClass() != AsymmetricKeyTypes::CipherPublicKey && Key->KeyClass() != AsymmetricKeyTypes::CipherPrivateKey)
	{
		throw CryptoAsymmetricException(Name(), std::string("Initialize"), std::string("The key is invalid!"), ErrorCodes::InvalidKey);
	}

	if (Key->KeyClass() == AsymmetricKeyTypes::CipherPublicKey)
	{
		m_publicKey = std::unique_ptr<AsymmetricKey>(Key);
		m_ntruState->Parameters = static_cast<NTRUParameters>(m_publicKey->Parameters());
		m_ntruState->Encryption = true;
	}
	else
	{
		m_privateKey = std::unique_ptr<AsymmetricKey>(Key);
		m_ntruState->Parameters = static_cast<NTRUParameters>(m_privateKey->Parameters());
		m_ntruState->Encryption = false;
	}

	m_ntruState->Initialized = true;
}

void NTRUPrime::CXOF(const std::vector<byte> &Domain, const std::vector<byte> &Key, std::vector<byte> &Secret, size_t Rate)
{
	std::vector<byte> tmpn(Name().begin(), Name().end());
	Keccak::CXOFP1600(Key, Domain, tmpn, Secret, 0, Secret.size(), Rate);
}

NAMESPACE_NTRUPRIMEEND
