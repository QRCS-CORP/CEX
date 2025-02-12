#include "HBA.h"
#include "HKDF.h"
#include "IntegerTools.h"
#include "ParallelTools.h"
#include "IntegerTools.h"
#include "MacFromName.h"
#include "MemoryTools.h"
#include "SHAKE.h"

NAMESPACE_MODE

using Enumeration::AeadModeConvert;
using Enumeration::BlockCipherConvert;
using Enumeration::Digests;
using Tools::IntegerTools;
using Tools::MemoryTools;
using Enumeration::SHA2Digests;
using Kdf::SHAKE;
using Enumeration::ShakeModes;
using Enumeration::StreamAuthenticatorConvert;
using Enumeration::StreamCipherConvert;

class HBA::HbaState
{
public:

	SecureVector<uint8_t> Custom;
	SecureVector<uint8_t> MacKey;
	SecureVector<uint8_t> MacTag;
	SecureVector<uint8_t> Name;
	uint64_t Counter;
	StreamAuthenticators Authenticator;
	SHA2Digests Digest;
	ShakeModes Mode;
	bool Destroy;
	bool Encryption;
	bool Initialized;

	HbaState(bool Destroy)
		:
		Custom(0),
		Digest(SHA2Digests::None),
		MacKey(0),
		MacTag(0),
		Name(0),
		Counter(0),
		Authenticator(StreamAuthenticators::None),
		Mode(ShakeModes::None),
		Destroy(Destroy),
		Encryption(false),
		Initialized(false)
	{
	}

	~HbaState()
	{
		Reset();
	}

	void Reset()
	{
		MemoryTools::Clear(Custom, 0, Custom.size());
		MemoryTools::Clear(MacKey, 0, MacKey.size());
		MemoryTools::Clear(MacTag, 0, MacTag.size());
		MemoryTools::Clear(Name, 0, Name.size());

		Custom.clear();
		MacKey.clear();
		MacTag.clear();
		Name.clear();
		Counter = 0;
		Encryption = false;
		Initialized = false;
	}
};

//~~~Constant Tables~~//

//~~~Constructor~~~//

HBA::HBA(BlockCiphers CipherType, StreamAuthenticators AuthenticatorType)
	:
	m_hbaState(new HbaState(true)),
	m_cipherMode(CipherType != BlockCiphers::None ?
		new ICM(CipherType) :
		throw CryptoCipherModeException(AeadModeConvert::ToName(AeadModes::HBA), std::string("Constructor"), std::string("The block cipher enumeration type can nor be none!"), ErrorCodes::InvalidParam)), //-V2571
	m_macAuthenticator(AuthenticatorType != StreamAuthenticators::None ? 
		Helper::MacFromName::GetInstance(AuthenticatorType) :
		throw CryptoCipherModeException(AeadModeConvert::ToName(AeadModes::HBA), std::string("Constructor"), std::string("The MAC generator enumeration type can not be none!"), ErrorCodes::IllegalOperation)) //-V2571
{
}

HBA::HBA(IBlockCipher* Cipher, StreamAuthenticators AuthenticatorType)
	:
	m_hbaState(new HbaState(false)),
	m_cipherMode(Cipher != nullptr ? 
		new ICM(Cipher) :
		throw CryptoCipherModeException(AeadModeConvert::ToName(AeadModes::HBA), std::string("Constructor"), std::string("The block cipher instance can not be null!"), ErrorCodes::IllegalOperation)), //-V2571
	m_macAuthenticator(AuthenticatorType != StreamAuthenticators::None ?
		Helper::MacFromName::GetInstance(AuthenticatorType) :
		throw CryptoCipherModeException(AeadModeConvert::ToName(AeadModes::HBA), std::string("Constructor"), std::string("The MAC generator enumeration type can not be none!"), ErrorCodes::IllegalOperation)) //-V2571
{
	m_hbaState->Destroy = false;
}

HBA::~HBA()
{
	if (m_macAuthenticator != nullptr)
	{
		m_macAuthenticator.reset(nullptr);
	}

	if (m_hbaState->Destroy)
	{
		if (m_cipherMode != nullptr)
		{
			m_cipherMode.reset(nullptr);
		}
	}
}

//~~~Accessors~~~//

const AeadModes HBA::Enumeral()
{
	return AeadModes::HBA;
}

const bool HBA::IsEncryption()
{
	return m_hbaState->Encryption;
}

const bool HBA::IsInitialized()
{
	return m_hbaState->Initialized;
}

const bool HBA::IsParallel()
{
	return ParallelProfile().IsParallel();
}

const std::vector<SymmetricKeySize> &HBA::LegalKeySizes()
{
	return m_cipherMode->LegalKeySizes();
}

const std::string HBA::Name()
{
	std::string tmpn;

	tmpn = AeadModeConvert::ToName(Enumeral()) + std::string("-") + 
		BlockCipherConvert::ToName(m_cipherMode->CipherType()) + std::string("-") + 
		StreamAuthenticatorConvert::ToName(static_cast<StreamAuthenticators>(m_macAuthenticator->Enumeral()));

	return tmpn;
}

const size_t HBA::ParallelBlockSize()
{
	return ParallelProfile().ParallelBlockSize();
}

ParallelOptions &HBA::ParallelProfile()
{
	return m_cipherMode->ParallelProfile();
}

const std::vector<uint8_t> HBA::Tag()
{
	return SecureUnlock(m_hbaState->MacTag);
}

const void HBA::Tag(SecureVector<uint8_t> &Output)
{
	SecureCopy(m_hbaState->MacTag, 0, Output, 0, m_hbaState->MacTag.size());
}

const size_t HBA::TagSize()
{
	return m_macAuthenticator->TagSize();
}

//~~~Public Functions~~~//

void HBA::Initialize(bool Encryption, ISymmetricKey &Parameters)
{
	SecureVector<uint8_t> tmpk(Parameters.KeySizes().KeySize());
	uint16_t kbits;

	if (!SymmetricKeySize::Contains(LegalKeySizes(), Parameters.KeySizes().KeySize()))
	{
		throw CryptoCipherModeException(Name(), std::string("Initialize"), std::string("Invalid key size; key must be one of the LegalKeySizes in length."), ErrorCodes::InvalidKey);
	}
	if (Parameters.KeySizes().IVSize() != BLOCK_SIZE)
	{
		throw CryptoCipherModeException(Name(), std::string("Initialize"), std::string("Requires a nonce equal in size to the ciphers block size!"), ErrorCodes::InvalidNonce);
	}

	if (m_cipherMode->IsParallel())
	{
		if (ParallelProfile().IsParallel() && ParallelProfile().ParallelBlockSize() < ParallelProfile().ParallelMinimumSize() || ParallelProfile().ParallelBlockSize() > ParallelProfile().ParallelMaximumSize())
		{
			throw CryptoCipherModeException(Name(), std::string("Initialize"), std::string("The parallel block size is out of bounds!"), ErrorCodes::InvalidSize);
		}
		if (ParallelProfile().IsParallel() && ParallelProfile().ParallelBlockSize() % ParallelProfile().ParallelMinimumSize() != 0)
		{
			throw CryptoCipherModeException(Name(), std::string("Initialize"), std::string("The parallel block size must be evenly aligned to the ParallelMinimumSize!"), ErrorCodes::InvalidParam);
		}
	}

	// reset for a new key
	if (IsInitialized() == true)
	{
		m_hbaState->Reset();
		m_macAuthenticator->Reset();
	}

	// set up the state members
	m_hbaState->Authenticator = static_cast<StreamAuthenticators>(m_macAuthenticator->Enumeral());
	// set the initial processed-bytes count to one
	m_hbaState->Counter = 1;
	// store encryption flag
	m_hbaState->Encryption = Encryption;
	// size the mac-tag
	m_hbaState->MacTag.resize(m_macAuthenticator->TagSize());

	// store the customization string -v1.0b
	if (Parameters.KeySizes().InfoSize() != 0)
	{
		m_hbaState->Custom.resize(Parameters.KeySizes().InfoSize());
		// copy the user defined string to the customization parameter
		MemoryTools::Copy(Parameters.Info(), 0, m_hbaState->Custom, 0, Parameters.KeySizes().InfoSize());
	}

	// create the HBA name string 
	std::string tmpn = Name();
	// add mac counter, key-size bits, and algorithm name to name string
	m_hbaState->Name.resize(sizeof(uint64_t) + sizeof(uint16_t) + tmpn.size());
	// mac nonce is always first 8 bytes of name
	IntegerTools::Le64ToBytes(m_hbaState->Counter, m_hbaState->Name, 0);
	// add the cipher key size in bits as an unsigned int16_t integer
	kbits = static_cast<uint16_t>(Parameters.KeySizes().KeySize() * 8);
	IntegerTools::Le16ToBytes(kbits, m_hbaState->Name, sizeof(uint64_t));
	// copy the name string to state
	MemoryTools::CopyFromObject(tmpn.data(), m_hbaState->Name, sizeof(uint64_t) + sizeof(uint16_t), tmpn.size());

	if (m_hbaState->Authenticator != StreamAuthenticators::HMACSHA2256 && m_hbaState->Authenticator != StreamAuthenticators::HMACSHA2512)
	{
		// SHA3 Mode //
		// cipher authenticator size determines key expansion function and Mac generator type; 256, 512, or 1024-bit
		m_hbaState->Mode = (m_hbaState->Authenticator == StreamAuthenticators::KMAC512) ?
			ShakeModes::SHAKE512 : ShakeModes::SHAKE256;

		const size_t KEYLEN = (m_hbaState->Mode == ShakeModes::SHAKE512) ? 
			64 : 32;

		SecureVector<uint8_t> mack(KEYLEN);

		SHAKE gen(m_hbaState->Mode);

		// initialize cSHAKE with k,c,n
		gen.Initialize(Parameters.SecureKey(), m_hbaState->Custom, m_hbaState->Name);

		// generate the CTR key
		gen.Generate(tmpk);

		// initialize the CTR mode
		SymmetricKey ckp(tmpk, Parameters.SecureIV(), Parameters.SecureInfo());
		m_cipherMode->Initialize(true, ckp);

		// generate the mac key
		gen.Generate(mack);

		// initialize the mac
		SymmetricKey mkp(mack);
		m_macAuthenticator->Initialize(mkp);

		// store the mac key
		m_hbaState->MacKey.resize(mack.size());
		SecureMove(mack, 0, m_hbaState->MacKey, 0, mack.size());
	}
	else
	{
		// SHA2 Mode //
		m_hbaState->Digest = (Parameters.KeySizes().KeySize() == 64) ? 
			SHA2Digests::SHA2512 : 
			SHA2Digests::SHA2256;

		const size_t KEYLEN = (m_hbaState->Digest == SHA2Digests::SHA2512) ? 
			64 : 
			32;

		SecureVector<uint8_t> mack(KEYLEN);
		SecureVector<uint8_t> tmpk(KEYLEN);
		SecureVector<uint8_t> zero(0);

		Kdf::HKDF gen(m_hbaState->Digest);

		// extract the kdf key from the user-key and salt
		gen.Extract(Parameters.SecureKey(), m_hbaState->Name, tmpk);

		// initialize HKDF Expand
		SymmetricKey gkp(tmpk, zero, m_hbaState->Custom);
		gen.Initialize(gkp);

		// generate the CTR key
		gen.Generate(tmpk);

		// initialize the CTR mode
		SymmetricKey ckp(tmpk, Parameters.SecureIV(), Parameters.SecureInfo());
		m_cipherMode->Initialize(true, ckp);

		// generate the mac key
		gen.Generate(mack);

		// initialize the mac generator
		SymmetricKey mkp(mack);
		m_macAuthenticator->Initialize(mkp);

		// store the mac key
		m_hbaState->MacKey.resize(mack.size());
		SecureMove(mack, 0, m_hbaState->MacKey, 0, mack.size());
	}

	m_hbaState->Initialized = true;
}

void HBA::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0 || Degree % 2 != 0 || Degree > ParallelProfile().ProcessorCount())
	{
		throw CryptoCipherModeException(Name(), std::string("ParallelMaxDegree"), std::string("Degree setting is invalid!"), ErrorCodes::InvalidParam);
	}

	ParallelProfile().SetMaxDegree(Degree);
}

void HBA::SetAssociatedData(const std::vector<uint8_t> &Input, size_t Offset, size_t Length)
{
	if (IsInitialized() == false)
	{
		throw CryptoCipherModeException(Name(), std::string("SetAssociatedData"), std::string("The cipher has not been initialized!"), ErrorCodes::NotInitialized);
	}

	if (Length - Offset > Input.size())
	{
		throw CryptoCipherModeException(Name(), std::string("SetAssociatedData"), std::string("The input array is too small!"), ErrorCodes::InvalidSize);
	}

	// add the additional data
	if (Length != 0)
	{
		std::vector<uint8_t> actr(sizeof(uint32_t));
		m_macAuthenticator->Update(Input, Offset, Length);
		// seperate encoding for associated data v1.1a
		IntegerTools::Le32ToBytes(static_cast<uint32_t>(Length), actr, 0);
		// the counter terminates the mac update stream
		m_macAuthenticator->Update(actr, 0, actr.size());
	}
}

void HBA::SetAssociatedData(const SecureVector<uint8_t> &Input, size_t Offset, size_t Length)
{
	if (IsInitialized() == false)
	{
		throw CryptoCipherModeException(Name(), std::string("SetAssociatedData"), std::string("The cipher has not been initialized!"), ErrorCodes::NotInitialized);
	}

	if (Length - Offset > Input.size())
	{
		throw CryptoCipherModeException(Name(), std::string("SetAssociatedData"), std::string("The input array is too small!"), ErrorCodes::InvalidSize);
	}

	// add the additional data
	if (Length != 0)
	{
		std::vector<uint8_t> actr(sizeof(uint32_t));
		m_macAuthenticator->Update(SecureUnlock(Input), Offset, Length);
		// seperate encoding for associated data v1.1a
		IntegerTools::Le32ToBytes(static_cast<uint32_t>(Length), actr, 0);
		// the counter terminates the mac update stream
		m_macAuthenticator->Update(actr, 0, actr.size());
	}
}

void HBA::Transform(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset, size_t Length)
{
	if (IsInitialized() == false)
	{
		throw CryptoCipherModeException(Name(), std::string("Transform"), std::string("The cipher mode has not been initialized!"), ErrorCodes::NotInitialized);
	}

	// add the starting position of the nonce to the mac
	m_macAuthenticator->Update(m_cipherMode->Nonce(), 0, m_cipherMode->Nonce().size());

	if (IsEncryption() == true)
	{
		if (Output.size() - OutOffset < Length + TagSize())
		{
			throw CryptoCipherModeException(Name(), std::string("Transform"), std::string("The output array is too small!"), ErrorCodes::InvalidSize);
		}

		// encrypt the plain-text
		m_cipherMode->Transform(Input, InOffset, Output, OutOffset, Length);
		// update the MAC with the cipher-text
		m_macAuthenticator->Update(Output, OutOffset, Length);
		// update the mac counter
		m_hbaState->Counter += Length;

		// finalize and write the MAC code to the end of the output array
		Finalize(Output, OutOffset + Length, m_macAuthenticator->TagSize());
	}
	else
	{
		if (Output.size() - OutOffset < Length)
		{
			throw CryptoCipherModeException(Name(), std::string("Transform"), std::string("The output array is too small!"), ErrorCodes::InvalidSize);
		}

		// update the MAC with the input cipher-text
		m_macAuthenticator->Update(Input, InOffset, Length);
		// update the mac counter
		m_hbaState->Counter += Length;

		// compare the MAC code appended to the ciphertext with the one generated, if they do not match, throw exception bybassing decryption
		if (!Verify(Input, InOffset + Length, m_macAuthenticator->TagSize()))
		{
			throw CryptoAuthenticationFailure(Name(), std::string("Transform"), std::string("The authentication tag does not match!"), ErrorCodes::AuthenticationFailure);
		}

		m_cipherMode->Transform(Input, InOffset, Output, OutOffset, Length);
	}
}

//~~~Private Functions~~~//

void HBA::Finalize(std::vector<uint8_t> &Output, size_t OutOffset, size_t Length)
{
	std::vector<uint8_t> pctr(sizeof(uint64_t));
	SecureVector<uint8_t> mack(0);
	uint64_t mctr;

	// 1.1a: add the number of message bytes processed by the mac, including counter and this encoding string
	mctr = m_hbaState->Counter + m_cipherMode->Nonce().size() + pctr.size();
	IntegerTools::Le64ToBytes(mctr, pctr, 0);

	// the counter terminates the mac update stream
	m_macAuthenticator->Update(pctr, 0, pctr.size());

	// generate the mac code to state tag
	m_macAuthenticator->Finalize(m_hbaState->MacTag, 0);
	// copy the tag to output
	MemoryTools::Copy(m_hbaState->MacTag, 0, Output, OutOffset, Length);

	// create the new mac-key: KDF(k,c,n)
	// name string is an unsigned 64-bit bytes counter + key-size + cipher-name.
	// The generator counter is the number of bytes processed by the cipher; 
	// does not include nonce and Associated lengths processed by the mac, 
	// only the number of bytes processed by the cipher
	IntegerTools::Le64ToBytes(m_hbaState->Counter, m_hbaState->Name, 0);

	if (m_hbaState->Mode != ShakeModes::None)
	{
		// generate the new mac key
		SHAKE gen(m_hbaState->Mode);

		// bytes counter provides cSHAKE domain seperation in the stream; will generate a unique mac-key each time
		gen.Initialize(m_hbaState->MacKey, m_hbaState->Custom, m_hbaState->Name);

		SymmetricKeySize ks = m_macAuthenticator->LegalKeySizes()[0];

		// generate the new mac key
		mack.resize(ks.KeySize());
		gen.Generate(mack);
	}
	else
	{
		SecureVector<uint8_t> zero(0);
		const size_t KEYLEN = (m_hbaState->Digest == SHA2Digests::SHA2512) ? 
			64 : 
			32;

		SecureVector<uint8_t> tmpk(KEYLEN);

		// generate the new mac key
		Kdf::HKDF gen(m_hbaState->Digest);

		// extract the hkdf key from the previous mac-key and counter+salt
		gen.Extract(m_hbaState->MacKey, m_hbaState->Name, tmpk);

		// initialize HKDF Expand
		SymmetricKey gkp(tmpk, zero, m_hbaState->Custom);
		gen.Initialize(gkp);

		// generate the new mac key
		mack.resize(KEYLEN);
		gen.Generate(mack);
	}

	// reset the generator with the new key
	SymmetricKey kpm(mack);
	m_macAuthenticator->Initialize(kpm);

	// store the new key and erase the temporary key
	SecureMove(mack, 0, m_hbaState->MacKey, 0, mack.size());
}

bool HBA::Verify(const std::vector<uint8_t> &Input, size_t InOffset, size_t Length)
{
	std::vector<uint8_t> code(m_macAuthenticator->TagSize());
	bool ret;

	// finalize the mac-code
	Finalize(code, 0, code.size());

	if (m_hbaState->MacTag.size() != 0)
	{
		MemoryTools::Clear(m_hbaState->MacTag, 0, m_hbaState->MacTag.size());
		m_hbaState->MacTag.resize(m_macAuthenticator->TagSize());
	}

	// store mac-code in state
	MemoryTools::Copy(code, 0, m_hbaState->MacTag, 0, m_hbaState->MacTag.size());

	// constant-time comparison of cipher-text MAC and MAC code generated internally
	ret = IntegerTools::Compare(m_hbaState->MacTag, 0, Input, InOffset, Length);

	return ret;
}

NAMESPACE_MODEEND
