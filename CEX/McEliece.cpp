#include "McEliece.h"
#include "Keccak.h"
#include "MPKCN4608T96.h"
#include "MPKCN6688T128.h"
#include "MPKCN6960T119.h"
#include "MPKCN8192T128.h"
#include "IntegerTools.h"
#include "PrngFromName.h"
#include "SymmetricKey.h"

NAMESPACE_MCELIECE

using Enumeration::AsymmetricPrimitiveConvert;
using Tools::IntegerTools;
using Digest::Keccak;
using Enumeration::McElieceParameterConvert;

class McEliece::MpkcState
{
public:

	std::vector<uint8_t> DomainKey;
	bool Destroyed;
	bool Encryption;
	bool Initialized;
	McElieceParameters Parameters;

	MpkcState(McElieceParameters Params, bool Destroy)
		:
		DomainKey(0),
		Destroyed(Destroy),
		Encryption(false),
		Initialized(false),
		Parameters(Params)
	{
	}

	~MpkcState()
	{
		IntegerTools::Clear(DomainKey);
		Destroyed = false;
		Encryption = false;
		Initialized = false;
		Parameters = McElieceParameters::None;
	}
};

//~~~Constructor~~~//

McEliece::McEliece(McElieceParameters Parameters, Prngs PrngType)
	:
	m_mpkcState(new MpkcState(Parameters == McElieceParameters::MPKCS3N4608T96 ||
		Parameters == McElieceParameters::MPKCS3N6960T119 ||
		Parameters == McElieceParameters::MPKCS4N6688T128 ||
		Parameters == McElieceParameters::MPKCS5N8192T128 ?
			Parameters :
			throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::McEliece), std::string("Constructor"), std::string("The McEliece parameter set is invalid!"), ErrorCodes::InvalidParam),
		true)),
	m_privateKey(nullptr),
	m_publicKey(nullptr),
	m_rndGenerator(PrngType != Prngs::None ? Helper::PrngFromName::GetInstance(PrngType) : 
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::McEliece), std::string("Constructor"), std::string("The prng type can not be none!"), ErrorCodes::InvalidParam))
{
}

McEliece::McEliece(McElieceParameters Parameters, IPrng* Prng)
	:
	m_mpkcState(new MpkcState(Parameters == McElieceParameters::MPKCS3N4608T96 ||
		Parameters == McElieceParameters::MPKCS3N6960T119 ||
		Parameters == McElieceParameters::MPKCS4N6688T128 ||
		Parameters == McElieceParameters::MPKCS5N8192T128 ?
			Parameters :
			throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::McEliece), std::string("Constructor"), std::string("The McEliece parameter set is invalid!"), ErrorCodes::InvalidParam),
		false)),
	m_privateKey(nullptr),
	m_publicKey(nullptr),
	m_rndGenerator(Prng != nullptr ? Prng : 
		throw CryptoAsymmetricException(AsymmetricPrimitiveConvert::ToName(AsymmetricPrimitives::McEliece), std::string("Constructor"), std::string("The prng can not be null!"), ErrorCodes::IllegalOperation))
{
}

McEliece::~McEliece()
{
	m_privateKey = nullptr;
	m_publicKey = nullptr;

	if (m_mpkcState->Destroyed)
	{
		// destroy internally generated objects
		if (m_rndGenerator != nullptr)
		{
			m_rndGenerator.reset(nullptr);
		}
	}
	else
	{
		if (m_rndGenerator != nullptr)
		{
			// release the external rng (received through ctor2) back to caller
			m_rndGenerator.release();
		}
	}
}

//~~~Accessors~~~//

const size_t McEliece::CipherTextSize()
{
	size_t clen;
	
	switch (m_mpkcState->Parameters)
	{
		case (McElieceParameters::MPKCS3N4608T96):
		{
			clen = MPKCN4608T96::CIPHERTEXT_SIZE;
			break;
		}

		case (McElieceParameters::MPKCS3N6960T119):
		{
			clen = MPKCN6960T119::CIPHERTEXT_SIZE;
			break;
		}
		case (McElieceParameters::MPKCS4N6688T128):
		{
			clen = MPKCN6688T128::CIPHERTEXT_SIZE;
			break;
		}
		case (McElieceParameters::MPKCS5N8192T128):
		{
			clen = MPKCN8192T128::CIPHERTEXT_SIZE;
			break;
		}
		default:
		{
			// invalid parameter
			throw CryptoAsymmetricException(Name(), std::string("CipherTextSize"), std::string("The McEliece parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	return clen;
}

std::vector<uint8_t> &McEliece::DomainKey()
{
	return m_mpkcState->DomainKey;
}

const AsymmetricPrimitives McEliece::Enumeral()
{
	return AsymmetricPrimitives::McEliece;
}

const bool McEliece::IsEncryption()
{
	return m_mpkcState->Encryption;
}

const bool McEliece::IsInitialized()
{
	return m_mpkcState->Initialized;
}

const std::string McEliece::Name()
{
	std::string ret;

	ret = AsymmetricPrimitiveConvert::ToName(Enumeral()) +
		std::string("-") +
		McElieceParameterConvert::ToName(m_mpkcState->Parameters);

	return ret;
}

const McElieceParameters McEliece::Parameters()
{
	return m_mpkcState->Parameters;
}

const size_t McEliece::PrivateKeySize()
{
	size_t klen;

	switch (m_mpkcState->Parameters)
	{
		case (McElieceParameters::MPKCS3N4608T96):
		{
			klen = MPKCN4608T96::PRIVATEKEY_SIZE;
			break;
		}
		case (McElieceParameters::MPKCS3N6960T119):
		{
			klen = MPKCN6960T119::PRIVATEKEY_SIZE;
			break;
		}
		case (McElieceParameters::MPKCS4N6688T128):
		{
			klen = MPKCN6688T128::PRIVATEKEY_SIZE;
			break;
		}
		case (McElieceParameters::MPKCS5N8192T128):
		{
			klen = MPKCN8192T128::PRIVATEKEY_SIZE;
			break;
		}
		default:
		{
			// invalid parameter
			throw CryptoAsymmetricException(Name(), std::string("PrivateKeySize"), std::string("The McEliece parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	return klen;
}

const size_t McEliece::PublicKeySize()
{
	size_t klen;

	switch (m_mpkcState->Parameters)
	{
		case (McElieceParameters::MPKCS3N4608T96):
		{
			klen = MPKCN4608T96::PUBLICKEY_SIZE;
			break;
		}
		case (McElieceParameters::MPKCS3N6960T119):
		{
			klen = MPKCN6960T119::PUBLICKEY_SIZE;
			break;
		}
		case (McElieceParameters::MPKCS4N6688T128):
		{
			klen = MPKCN6688T128::PUBLICKEY_SIZE;
			break;
		}
		case (McElieceParameters::MPKCS5N8192T128):
		{
			klen = MPKCN8192T128::PUBLICKEY_SIZE;
			break;
		}
		default:
		{
			// invalid parameter
			throw CryptoAsymmetricException(Name(), std::string("PublicKeySize"), std::string("The McEliece parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	return klen;
}

const size_t McEliece::SharedSecretSize()
{
	return SECRET_SIZE;
}

//~~~Public Functions~~~//

bool McEliece::Decapsulate(const std::vector<uint8_t> &CipherText, std::vector<uint8_t> &SharedSecret)
{
	CEXASSERT(m_mpkcState->Initialized, "The cipher has not been initialized");

	std::vector<uint8_t> sec(SECRET_SIZE, 0x00);
	bool res;
	
	switch (m_mpkcState->Parameters)
	{
		case McElieceParameters::MPKCS3N4608T96:
		{
			res = MPKCN4608T96::Decapsulate(m_privateKey->Polynomial(), CipherText, sec);
			break;
		}

		case McElieceParameters::MPKCS3N6960T119:
		{
			res = MPKCN6960T119::Decapsulate(m_privateKey->Polynomial(), CipherText, sec);
			break;
		}
		case McElieceParameters::MPKCS4N6688T128:
		{
			res = MPKCN6688T128::Decapsulate(m_privateKey->Polynomial(), CipherText, sec);
			break;
		}
		case McElieceParameters::MPKCS5N8192T128:
		{
			res = MPKCN8192T128::Decapsulate(m_privateKey->Polynomial(), CipherText, sec);
			break;
		}
		default:
		{
			// invalid parameter
			throw CryptoAsymmetricException(Name(), std::string("Decapsulate"), std::string("The McEliece parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	if (res == true)
	{
		if (m_mpkcState->DomainKey.size() != 0)
		{
			CXOF(m_mpkcState->DomainKey, sec, SharedSecret, Keccak::KECCAK512_RATE_SIZE);
		}
		else
		{
			SharedSecret.resize(sec.size());
			MemoryTools::Copy(sec, 0, SharedSecret, 0, sec.size());
		}
	}

	return res;
}

void McEliece::Encapsulate(std::vector<uint8_t> &CipherText, std::vector<uint8_t> &SharedSecret)
{
	CEXASSERT(m_mpkcState->Initialized, "The cipher has not been initialized");
	CEXASSERT(SharedSecret.size() <= 256, "The shared secret size is too large");

	std::vector<uint8_t> sec(SECRET_SIZE);

	switch (m_mpkcState->Parameters)
	{
		case McElieceParameters::MPKCS3N4608T96:
		{
			CipherText.resize(MPKCN4608T96::CIPHERTEXT_SIZE);
			MPKCN4608T96::Encapsulate(m_publicKey->Polynomial(), CipherText, sec, m_rndGenerator);
			break;
		}
		case McElieceParameters::MPKCS3N6960T119:
		{
			bool res;

			CipherText.resize(MPKCN6960T119::CIPHERTEXT_SIZE);
			res = MPKCN6960T119::Encapsulate(m_publicKey->Polynomial(), CipherText, sec, m_rndGenerator);

			if (res == false)
			{
				throw CryptoAsymmetricException(Name(), std::string("Encapsulate"), std::string("The McEliece encasulation padding is invalid!"), ErrorCodes::InvalidState);
			}

			break;
		}
		case McElieceParameters::MPKCS4N6688T128:
		{
			CipherText.resize(MPKCN6688T128::CIPHERTEXT_SIZE);
			MPKCN6688T128::Encapsulate(m_publicKey->Polynomial(), CipherText, sec, m_rndGenerator);
			break;
		}
		case McElieceParameters::MPKCS5N8192T128:
		{
			CipherText.resize(MPKCN8192T128::CIPHERTEXT_SIZE);
			MPKCN8192T128::Encapsulate(m_publicKey->Polynomial(), CipherText, sec, m_rndGenerator);
			break;
		}
		default:
		{
			// invalid parameters
			throw CryptoAsymmetricException(Name(), std::string("Encapsulate"), std::string("The McEliece parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	if (m_mpkcState->DomainKey.size() != 0)
	{
		CXOF(m_mpkcState->DomainKey, sec, SharedSecret, Keccak::KECCAK512_RATE_SIZE);
	}
	else
	{
		SharedSecret.resize(sec.size());
		MemoryTools::Copy(sec, 0, SharedSecret, 0, sec.size());
	}
}

AsymmetricKeyPair* McEliece::Generate()
{
	std::vector<uint8_t> pk(0);
	std::vector<uint8_t> sk(0);

	switch (m_mpkcState->Parameters)
	{
		case McElieceParameters::MPKCS3N4608T96:
		{
			pk.resize(MPKCN4608T96::PUBLICKEY_SIZE);
			sk.resize(MPKCN4608T96::PRIVATEKEY_SIZE);

			if (MPKCN4608T96::Generate(pk, sk, m_rndGenerator) == false)
			{
				throw CryptoAsymmetricException(std::string("McEliece"), std::string("Generate-MPKCS3N4608T96"), std::string("Key generation max retries failure!"), ErrorCodes::MaxExceeded);
			}

			break;
		}
		case McElieceParameters::MPKCS3N6960T119:
		{
			pk.resize(MPKCN6960T119::PUBLICKEY_SIZE);
			sk.resize(MPKCN6960T119::PRIVATEKEY_SIZE);

			if (MPKCN6960T119::Generate(pk, sk, m_rndGenerator) == false)
			{
				throw CryptoAsymmetricException(std::string("McEliece"), std::string("Generate-MPKCS3N6960T119"), std::string("Key generation max retries failure!"), ErrorCodes::MaxExceeded);
			}

			break;
		}
		case McElieceParameters::MPKCS4N6688T128:
		{
			pk.resize(MPKCN6688T128::PUBLICKEY_SIZE);
			sk.resize(MPKCN6688T128::PRIVATEKEY_SIZE);

			if (MPKCN6688T128::Generate(pk, sk, m_rndGenerator) == false)
			{
				throw CryptoAsymmetricException(std::string("McEliece"), std::string("Generate-MPKCS4N6688T128"), std::string("Key generation max retries failure!"), ErrorCodes::MaxExceeded);
			}

			break;
		}
		case McElieceParameters::MPKCS5N8192T128:
		{
			pk.resize(MPKCN8192T128::PUBLICKEY_SIZE);
			sk.resize(MPKCN8192T128::PRIVATEKEY_SIZE);

			if (MPKCN8192T128::Generate(pk, sk, m_rndGenerator) == false)
			{
				throw CryptoAsymmetricException(std::string("McEliece"), std::string("Generate-MPKCS5N8192T128"), std::string("Key generation max retries failure!"), ErrorCodes::MaxExceeded);
			}

			break;
		}
		default:
		{
			// invalid parameter
			throw CryptoAsymmetricException(Name(), std::string("Encapsulate"), std::string("The McEliece parameter set is invalid!"), ErrorCodes::InvalidParam);
		}
	}

	AsymmetricKey* apk = new AsymmetricKey(pk, AsymmetricPrimitives::McEliece, AsymmetricKeyTypes::CipherPublicKey, static_cast<AsymmetricParameters>(m_mpkcState->Parameters));
	AsymmetricKey* ask = new AsymmetricKey(sk, AsymmetricPrimitives::McEliece, AsymmetricKeyTypes::CipherPrivateKey, static_cast<AsymmetricParameters>(m_mpkcState->Parameters));

	return new AsymmetricKeyPair(ask, apk);
}

void McEliece::Initialize(AsymmetricKey* Key)
{
	if (Key->PrimitiveType() != AsymmetricPrimitives::McEliece)
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
		m_mpkcState->Parameters = static_cast<McElieceParameters>(m_publicKey->Parameters());
		m_mpkcState->Encryption = true;
	}
	else
	{
		m_privateKey = Key;
		m_mpkcState->Parameters = static_cast<McElieceParameters>(m_privateKey->Parameters());
		m_mpkcState->Encryption = false;
	}

	m_mpkcState->Initialized = true;
}

void McEliece::CXOF(const std::vector<uint8_t> &Domain, const std::vector<uint8_t> &Key, std::vector<uint8_t> &Secret, size_t Rate)
{
	std::vector<uint8_t> tmpn(Name().begin(), Name().end());
	Keccak::CXOFP1600(Key, Domain, tmpn, Secret, 0, Secret.size(), Rate);
}

NAMESPACE_MCELIECEEND
