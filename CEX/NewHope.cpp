#include "NewHope.h"
#include "IntegerTools.h"
#include "Keccak.h"
#include "MemoryTools.h"
#include "PrngFromName.h"
#include "RLWEQ12289N1024.h"
#include "RLWEQ12289N2048.h"
#include "SymmetricKey.h"

NAMESPACE_RINGLWE

using Enumeration::AsymmetricPrimitiveConvert;
using Tools::IntegerTools;
using Digest::Keccak;
using Tools::MemoryTools;
using Enumeration::NewHopeParameterConvert;

class NewHope::RlweState
{
public:

	std::vector<byte> DomainKey;
	bool Destroyed;
	bool Encryption;
	bool Initialized;
	NewHopeParameters Parameters;

	RlweState(NewHopeParameters Params, bool Destroy)
		:
		DomainKey(0),
		Destroyed(Destroy),
		Encryption(false),
		Initialized(false),
		Parameters(Params)
	{
	}

	~RlweState()
	{
		IntegerTools::Clear(DomainKey);
		Destroyed = false;
		Encryption = false;
		Initialized = false;
		Parameters = NewHopeParameters::None;
	}
};

//~~~Constructor~~~//

NewHope::NewHope(NewHopeParameters Parameters, Prngs PrngType)
	:
	m_rlweState(new RlweState(Parameters == NewHopeParameters::RLWES1Q12289N1024 || 
		Parameters == NewHopeParameters::RLWES2Q12289N2048 ? 
			Parameters :
			throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::NewHope), std::string("Constructor"), std::string("The NewHope parameter set is invalid!"), ErrorCodes::InvalidParam),
		true)),
	m_privateKey(nullptr),
	m_publicKey(nullptr),
	m_rndGenerator(PrngType != Prngs::None ? Helper::PrngFromName::GetInstance(PrngType) :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::NewHope), std::string("Constructor"), std::string("The prng type can not be none!"), ErrorCodes::InvalidParam))
{
}

NewHope::NewHope(NewHopeParameters Parameters, IPrng* Prng)
	:
	m_rlweState(new RlweState(Parameters == NewHopeParameters::RLWES1Q12289N1024 ||
		Parameters == NewHopeParameters::RLWES2Q12289N2048 ?
			Parameters :
			throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::NewHope), std::string("Constructor"), std::string("The NewHope parameter set is invalid!"), ErrorCodes::InvalidParam),
		false)),
	m_privateKey(nullptr),
	m_publicKey(nullptr),
	m_rndGenerator(Prng != nullptr ? Prng :
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::NewHope), std::string("Constructor"), std::string("The prng can not be null!"), ErrorCodes::InvalidParam))
{
}

NewHope::~NewHope()
{
	m_privateKey = nullptr;
	m_publicKey = nullptr;

	if (m_rlweState->Destroyed)
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

const size_t NewHope::CipherTextSize()
{
	size_t clen;

	switch (m_rlweState->Parameters)
	{
		case (NewHopeParameters::RLWES1Q12289N1024):
		{
			clen = RLWEQ12289N1024::CIPHERTEXT_SIZE;
			break;
		}
		case (NewHopeParameters::RLWES2Q12289N2048):
		{
			clen = RLWEQ12289N2048::CIPHERTEXT_SIZE;
			break;
		}
		default:
		{
			// invalid parameter
			throw CryptoAsymmetricException(Name(), std::string("CipherTextSize"), std::string("The NewHope parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	return clen;
}

std::vector<byte> &NewHope::DomainKey()
{
	return m_rlweState->DomainKey;
}

const AsymmetricPrimitives NewHope::Enumeral()
{
	return AsymmetricPrimitives::NewHope;
}

const bool NewHope::IsEncryption()
{
	return m_rlweState->Encryption;
}

const bool NewHope::IsInitialized()
{
	return m_rlweState->Initialized;
}

const std::string NewHope::Name()
{
	std::string ret;

	ret = AsymmetricPrimitiveConvert::ToName(Enumeral()) +
		std::string("-") +
		NewHopeParameterConvert::ToName(m_rlweState->Parameters);

	return ret;
}

const NewHopeParameters NewHope::Parameters()
{
	return m_rlweState->Parameters;
}

const size_t NewHope::PrivateKeySize()
{
	size_t klen;

	switch (m_rlweState->Parameters)
	{
		case (NewHopeParameters::RLWES1Q12289N1024):
		{
			klen = RLWEQ12289N1024::PRIVATEKEY_SIZE;
			break;
		}
		case (NewHopeParameters::RLWES2Q12289N2048):
		{
			klen = RLWEQ12289N2048::PRIVATEKEY_SIZE;
			break;
		}
		default:
		{
			// invalid parameter
			throw CryptoAsymmetricException(Name(), std::string("PrivateKeySize"), std::string("The NewHope parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	return klen;
}

const size_t NewHope::PublicKeySize()
{
	size_t klen;

	switch (m_rlweState->Parameters)
	{
		case (NewHopeParameters::RLWES1Q12289N1024):
		{
			klen = RLWEQ12289N1024::PUBLICKEY_SIZE;
			break;
		}
		case (NewHopeParameters::RLWES2Q12289N2048):
		{
			klen = RLWEQ12289N2048::PUBLICKEY_SIZE;
			break;
		}
		default:
		{
			// invalid parameter
			throw CryptoAsymmetricException(Name(), std::string("PublicKeySize"), std::string("The NewHope parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	return klen;
}

const size_t NewHope::SharedSecretSize()
{
	return SECRET_SIZE;
}

//~~~Public Functions~~~//

bool NewHope::Decapsulate(const std::vector<byte> &CipherText, std::vector<byte> &SharedSecret)
{
	CEXASSERT(m_rlweState->Initialized, "The cipher has not been initialized");
	CEXASSERT(SharedSecret.size() <= 256, "The shared secret size is too large");

	std::vector<byte> sec(SECRET_SIZE);
	bool result;

	switch (m_rlweState->Parameters)
	{
		case (NewHopeParameters::RLWES1Q12289N1024):
		{
			result = RLWEQ12289N1024::Decapsulate(sec, CipherText, m_privateKey->Polynomial());
			break;
		}
		case (NewHopeParameters::RLWES2Q12289N2048):
		{
			result = RLWEQ12289N2048::Decapsulate(sec, CipherText, m_privateKey->Polynomial());
			break;
		}
		default:
		{
			// invalid parameter
			throw CryptoAsymmetricException(Name(), std::string("Decapsulate"), std::string("The NewHope parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	if (m_rlweState->DomainKey.size() != 0)
	{
		CXOF(m_rlweState->DomainKey, sec, SharedSecret, Keccak::KECCAK512_RATE_SIZE);
	}
	else
	{
		SharedSecret.resize(sec.size());
		MemoryTools::Copy(sec, 0, SharedSecret, 0, sec.size());
	}

	return result;
}

void NewHope::Encapsulate(std::vector<byte> &CipherText, std::vector<byte> &SharedSecret)
{
	CEXASSERT(m_rlweState->Initialized, "The cipher has not been initialized");
	CEXASSERT(SharedSecret.size() <= 256, "The shared secret size is too large");

	std::vector<byte> sec(SECRET_SIZE);

	switch (m_rlweState->Parameters)
	{
		case (NewHopeParameters::RLWES1Q12289N1024):
		{
			CipherText.resize(RLWEQ12289N1024::CIPHERTEXT_SIZE);
			RLWEQ12289N1024::Encapsulate(CipherText, sec, m_publicKey->Polynomial(), m_rndGenerator);
			break;
		}
		case (NewHopeParameters::RLWES2Q12289N2048):
		{
			CipherText.resize(RLWEQ12289N2048::CIPHERTEXT_SIZE);
			RLWEQ12289N2048::Encapsulate(CipherText, sec, m_publicKey->Polynomial(), m_rndGenerator);
			break;
		}
		default:
		{
			// invalid parameter
			throw CryptoAsymmetricException(Name(), std::string("Encapsulate"), std::string("The NewHope parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	if (m_rlweState->DomainKey.size() != 0)
	{
		CXOF(m_rlweState->DomainKey, sec, SharedSecret, Keccak::KECCAK512_RATE_SIZE);
	}
	else
	{
		SharedSecret.resize(sec.size());
		MemoryTools::Copy(sec, 0, SharedSecret, 0, sec.size());
	}
}

AsymmetricKeyPair* NewHope::Generate()
{
	CEXASSERT(m_rlweState->Parameters != NewHopeParameters::None, "The parameter setting is invalid");

	std::vector<byte> pk(0);
	std::vector<byte> sk(0);

	switch (m_rlweState->Parameters)
	{
		case (NewHopeParameters::RLWES1Q12289N1024):
		{
			pk.resize(RLWEQ12289N1024::PUBLICKEY_SIZE);
			sk.resize(RLWEQ12289N1024::PRIVATEKEY_SIZE);
			RLWEQ12289N1024::Generate(pk, sk, m_rndGenerator);
			break;
		}
		case (NewHopeParameters::RLWES2Q12289N2048):
		{
			pk.resize(RLWEQ12289N2048::PUBLICKEY_SIZE);
			sk.resize(RLWEQ12289N2048::PRIVATEKEY_SIZE);
			RLWEQ12289N2048::Generate(pk, sk, m_rndGenerator);
			break;
		}
		default:
		{
			// invalid parameter
			throw CryptoAsymmetricException(Name(), std::string("Generate"), std::string("The asymmetric cipher parameter setting is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	AsymmetricKey* apk = new AsymmetricKey(pk, AsymmetricPrimitives::NewHope, AsymmetricKeyTypes::CipherPublicKey, static_cast<AsymmetricParameters>(m_rlweState->Parameters));
	AsymmetricKey* ask = new AsymmetricKey(sk, AsymmetricPrimitives::NewHope, AsymmetricKeyTypes::CipherPrivateKey, static_cast<AsymmetricParameters>(m_rlweState->Parameters));

	return new AsymmetricKeyPair(ask, apk);
}

void NewHope::Initialize(AsymmetricKey* Key)
{
	if (Key->PrimitiveType() != AsymmetricPrimitives::NewHope)
	{
		throw CryptoAsymmetricException(Name(), std::string("Initialize"), std::string("The key is invalid!"), ErrorCodes::InvalidKey);
	}

	if (Key->KeyClass() != AsymmetricKeyTypes::CipherPublicKey && Key->KeyClass() != AsymmetricKeyTypes::CipherPrivateKey)
	{
		throw CryptoAsymmetricException(Name(), std::string("Initialize"), std::string("The key is invalid!"), ErrorCodes::InvalidKey);
	}

	if (Key->KeyClass() == AsymmetricKeyTypes::CipherPublicKey)
	{
		m_publicKey = Key;
		m_rlweState->Parameters = static_cast<NewHopeParameters>(m_publicKey->Parameters());
		m_rlweState->Encryption = true;
	}
	else
	{
		m_privateKey = Key;
		m_rlweState->Parameters = static_cast<NewHopeParameters>(m_privateKey->Parameters());
		m_rlweState->Encryption = false;
	}

	m_rlweState->Initialized = true;
}

void NewHope::CXOF(const std::vector<byte> &Domain, const std::vector<byte> &Key, std::vector<byte> &Secret, size_t Rate)
{
	std::vector<byte> tmpn(Name().begin(), Name().end());
	Keccak::CXOFR24P1600(Key, Domain, tmpn, Secret, 0, Secret.size(), Rate);
}

NAMESPACE_RINGLWEEND
