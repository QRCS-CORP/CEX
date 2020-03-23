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
using Utility::IntegerTools;
using Utility::MemoryTools;
using Enumeration::SHA2Digests;
using Enumeration::ShakeModes;
using Enumeration::StreamAuthenticatorConvert;
using Enumeration::StreamCipherConvert;

class HBA::HbaState
{
public:

	SecureVector<byte> Associated;
	SecureVector<byte> Custom;
	SecureVector<byte> MacKey;
	SecureVector<byte> MacTag;
	SecureVector<byte> Name;
	ulong Counter;
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
		MemoryTools::Clear(Associated, 0, Associated.size());
		MemoryTools::Clear(Custom, 0, Custom.size());
		MemoryTools::Clear(MacKey, 0, MacKey.size());
		MemoryTools::Clear(MacTag, 0, MacTag.size());
		MemoryTools::Clear(Name, 0, Name.size());

		Associated.clear();
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

const std::vector<byte> HBA::HBA_INFO =
{
	0x48, 0x42, 0x41, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, 0x20, 0x31, 0x2E, 0x30, 0x62
};

//~~~Constructor~~~//

HBA::HBA(BlockCiphers CipherType, StreamAuthenticators AuthenticatorType)
	:
	m_hbaState(new HbaState(true)),
	m_cipherMode(CipherType != BlockCiphers::None ? 
		new CTR(CipherType) :
		throw CryptoCipherModeException(AeadModeConvert::ToName(AeadModes::HBA), std::string("Constructor"), std::string("The block cipher enumeration type can nor be none!"), ErrorCodes::InvalidParam)),
	m_macAuthenticator(AuthenticatorType != StreamAuthenticators::None ? 
		Helper::MacFromName::GetInstance(AuthenticatorType) :
		throw CryptoCipherModeException(AeadModeConvert::ToName(AeadModes::HBA), std::string("Constructor"), std::string("The MAC generator enumeration type can not be none!"), ErrorCodes::IllegalOperation))
{
}

HBA::HBA(IBlockCipher* Cipher, StreamAuthenticators AuthenticatorType)
	:
	m_hbaState(new HbaState(false)),
	m_cipherMode(Cipher != nullptr ? 
		new CTR(Cipher) :
		throw CryptoCipherModeException(AeadModeConvert::ToName(AeadModes::HBA), std::string("Constructor"), std::string("The block cipher instance can not be null!"), ErrorCodes::IllegalOperation)),
	m_macAuthenticator(AuthenticatorType != StreamAuthenticators::None ?
		Helper::MacFromName::GetInstance(AuthenticatorType) :
		throw CryptoCipherModeException(AeadModeConvert::ToName(AeadModes::HBA), std::string("Constructor"), std::string("The MAC generator enumeration type can not be none!"), ErrorCodes::IllegalOperation))
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
	else
	{
		if (m_cipherMode != nullptr)
		{
			m_cipherMode.release();
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

const std::vector<byte> HBA::Tag()
{
	return SecureUnlock(m_hbaState->MacTag);
}

const void HBA::Tag(SecureVector<byte> &Output)
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
	SecureVector<byte> tmpk(Parameters.KeySizes().KeySize());
	ushort kbits;

	if (!SymmetricKeySize::Contains(LegalKeySizes(), Parameters.KeySizes().KeySize()))
	{
		throw CryptoCipherModeException(Name(), std::string("Initialize"), std::string("Invalid key size; key must be one of the LegalKeySizes in length."), ErrorCodes::InvalidKey);
	}
	if (Parameters.KeySizes().NonceSize() != BLOCK_SIZE)
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
	if (IsInitialized())
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

	// create the cSHAKE customization string
	m_hbaState->Custom.resize(Parameters.KeySizes().InfoSize() + HBA_INFO.size());
	// copy the version string to the customization parameter
	MemoryTools::Copy(HBA_INFO, 0, m_hbaState->Custom, 0, HBA_INFO.size());
	// copy the user defined string to the customization parameter
	MemoryTools::Copy(Parameters.Info(), 0, m_hbaState->Custom, HBA_INFO.size(), Parameters.KeySizes().InfoSize());

	// create the HBA name string 
	std::string tmpn = Name();
	// add mac counter, key-size bits, and algorithm name to name string
	m_hbaState->Name.resize(sizeof(ulong) + sizeof(ushort) + tmpn.size());
	// mac nonce is always first 8 bytes of name
	IntegerTools::Le64ToBytes(m_hbaState->Counter, m_hbaState->Name, 0);
	// add the cipher key size in bits as an unsigned short integer
	kbits = static_cast<ushort>(Parameters.KeySizes().KeySize() * 8);
	IntegerTools::Le16ToBytes(kbits, m_hbaState->Name, sizeof(ulong));
	// copy the name string to state
	MemoryTools::CopyFromObject(tmpn.data(), m_hbaState->Name, sizeof(ulong) + sizeof(ushort), tmpn.size());

	if (m_hbaState->Authenticator != StreamAuthenticators::HMACSHA256 && m_hbaState->Authenticator != StreamAuthenticators::HMACSHA512)
	{
		// SHA3 Mode //
		// cipher authenticator size determines key expansion function and Mac generator type; 256, 512, or 1024-bit
		m_hbaState->Mode = (m_hbaState->Authenticator == StreamAuthenticators::KMAC512) ?
			ShakeModes::SHAKE512 : (m_hbaState->Authenticator == StreamAuthenticators::KMAC256) ? 
			ShakeModes::SHAKE256 : ShakeModes::SHAKE1024;

		const size_t KEYLEN = (m_hbaState->Mode == ShakeModes::SHAKE512) ? 64 : (m_hbaState->Mode == ShakeModes::SHAKE256) ? 32 : 128;
		SecureVector<byte> mack(KEYLEN);

		Kdf::SHAKE gen(m_hbaState->Mode);

		// initialize cSHAKE with k,c,n
		gen.Initialize(Parameters.SecureKey(), m_hbaState->Custom, m_hbaState->Name);

		// generate the CTR key
		gen.Generate(tmpk);

		// initialize the CTR mode
		SymmetricKey ckp(tmpk, Parameters.SecureNonce(), Parameters.SecureInfo());
		m_cipherMode->Initialize(true, ckp);

		// generate the mac key
		gen.Generate(mack);

		// initialize the mac
		SymmetricKey mkp(mack);
		m_macAuthenticator->Initialize(mkp);

		// store the mac key
		m_hbaState->MacKey.resize(mack.size());
		SecureMove(mack, m_hbaState->MacKey, 0);
	}
	else
	{
		// SHA2 Mode //
		m_hbaState->Digest = (Parameters.KeySizes().KeySize() == 64) ? SHA2Digests::SHA512 : SHA2Digests::SHA256;
		const size_t KEYLEN = (m_hbaState->Digest == SHA2Digests::SHA512) ? 64 : 32;
		SecureVector<byte> mack(KEYLEN);
		SecureVector<byte> tmpk(KEYLEN);
		SecureVector<byte> zero(0);

		Kdf::HKDF gen(m_hbaState->Digest);

		// extract the kdf key from the user-key and salt
		gen.Extract(Parameters.SecureKey(), m_hbaState->Name, tmpk);

		// initialize HKDF Expand
		SymmetricKey gkp(tmpk, zero, m_hbaState->Custom);
		gen.Initialize(gkp);

		// generate the CTR key
		gen.Generate(tmpk);

		// initialize the CTR mode
		SymmetricKey ckp(tmpk, Parameters.SecureNonce(), Parameters.SecureInfo());
		m_cipherMode->Initialize(true, ckp);

		// generate the mac key
		gen.Generate(mack);

		// initialize the mac generator
		SymmetricKey mkp(mack);
		m_macAuthenticator->Initialize(mkp);

		// store the mac key
		m_hbaState->MacKey.resize(mack.size());
		SecureMove(mack, m_hbaState->MacKey, 0);
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

void HBA::SetAssociatedData(const std::vector<byte> &Input, size_t Offset, size_t Length)
{
	if (!IsInitialized())
	{
		throw CryptoCipherModeException(Name(), std::string("SetAssociatedData"), std::string("The cipher has not been initialized!"), ErrorCodes::NotInitialized);
	}

	m_hbaState->Associated.resize(Length);
	MemoryTools::Copy(Input, Offset, m_hbaState->Associated, 0, Length);
}

void HBA::SetAssociatedData(const SecureVector<byte> &Input, size_t Offset, size_t Length)
{
	if (!IsInitialized())
	{
		throw CryptoCipherModeException(Name(), std::string("SetAssociatedData"), std::string("The cipher has not been initialized!"), ErrorCodes::NotInitialized);
	}

	m_hbaState->Associated.resize(Length);
	SecureCopy(Input, Offset, m_hbaState->Associated, 0, Length);
}

void HBA::Transform(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	if (!IsInitialized())
	{
		throw CryptoCipherModeException(Name(), std::string("Transform"), std::string("The cipher mode has not been initialized!"), ErrorCodes::NotInitialized);
	}

	// add the starting position of the nonce to the mac
	m_macAuthenticator->Update(m_cipherMode->Nonce(), 0, m_cipherMode->Nonce().size());

	if (IsEncryption())
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

void HBA::Finalize(std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	std::vector<byte> mctr(sizeof(ulong));
	SecureVector<byte> mack(0);

	// 1.0b: add the total number of bytes processed by the mac, including this terminating string
	IntegerTools::LeIncrease8(mctr, m_hbaState->Counter + m_hbaState->Associated.size() + m_cipherMode->Nonce().size() + mctr.size());

	// add the additional data
	if (m_hbaState->Associated.size() != 0)
	{
		m_macAuthenticator->Update(SecureUnlock(m_hbaState->Associated), 0, m_hbaState->Associated.size());
		// clear the associated data, reset for each transformation, assignable with a call to SetAssociatedData
		MemoryTools::Clear(m_hbaState->Associated, 0, m_hbaState->Associated.size());
		m_hbaState->Associated.resize(0);
	}

	// the counter terminates the mac update stream
	m_macAuthenticator->Update(mctr, 0, mctr.size());

	// generate the mac code to state tag
	m_macAuthenticator->Finalize(m_hbaState->MacTag, 0);
	// copy the tag to output
	MemoryTools::Copy(m_hbaState->MacTag, 0, Output, OutOffset, Length);

	// create the new mac-key: KDF(k,c,n)
	// name string is an unsigned 64-bit bytes counter + key-size + cipher-name
	// the generator counter is the number of bytes processed by the cipher; 
	// does not include nonce and Associated lengths processed by the mac, 
	// only the number of bytes processed by the cipher
	IntegerTools::Le64ToBytes(m_hbaState->Counter, m_hbaState->Name, 0);

	if (m_hbaState->Mode != ShakeModes::None)
	{
		// generate the new mac key
		Kdf::SHAKE gen(m_hbaState->Mode);

		// bytes counter provides cSHAKE domain seperation in the stream; will generate a unique mac-key each time
		gen.Initialize(m_hbaState->MacKey, m_hbaState->Custom, m_hbaState->Name);

		// use the second key parameter of legal keys to set the mac key length, the stronger [recommended] setting
		SymmetricKeySize ks = m_macAuthenticator->LegalKeySizes()[1];

		// generate the new mac key
		mack.resize(ks.KeySize());
		gen.Generate(mack);
	}
	else
	{
		SecureVector<byte> zero(0);
		const size_t KEYLEN = (m_hbaState->Digest == SHA2Digests::SHA512) ? 64 : 32;
		SecureVector<byte> tmpk(KEYLEN);

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
	SecureMove(mack, m_hbaState->MacKey, 0);
}

bool HBA::Verify(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	std::vector<byte> code(m_macAuthenticator->TagSize());
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
