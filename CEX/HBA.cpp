#include "HBA.h"
#include "IntegerTools.h"
#include "ParallelTools.h"
#include "IntegerTools.h"
#include "MacFromName.h"
#include "MemoryTools.h"
#include "SHAKE.h"

NAMESPACE_MODE

using Enumeration::BlockCipherConvert;
using Enumeration::AeadModeConvert;
using Utility::IntegerTools;
using Utility::MemoryTools;
using Enumeration::ShakeModes;
using Enumeration::StreamCipherConvert;

class HBA::HbaState
{
public:

	SecureVector<byte> AAD;
	SecureVector<byte> Custom;
	SecureVector<byte> MacKey;
	SecureVector<byte> MacTag;
	SecureVector<byte> Name;
	ulong Counter;
	StreamAuthenticators Authenticator;
	ShakeModes Mode;
	bool AutoIncrement;
	bool Destroy;
	bool Encryption;
	bool Finalized;
	bool Initialized;
	bool Preserve;

	HbaState()
		:
		Custom(0),
		MacKey(0),
		MacTag(0),
		Name(0),
		Counter(0),
		Authenticator(StreamAuthenticators::None),
		Mode(ShakeModes::None),
		AutoIncrement(false),
		Destroy(false),
		Encryption(false),
		Finalized(false),
		Initialized(false),
		Preserve(false)
	{
	}

	~HbaState()
	{
		MemoryTools::Clear(AAD, 0, AAD.size());
		MemoryTools::Clear(Custom, 0, Custom.size());
		MemoryTools::Clear(MacKey, 0, MacKey.size());
		MemoryTools::Clear(MacTag, 0, MacTag.size());
		MemoryTools::Clear(Name, 0, Name.size());

		Counter = 0;
		Authenticator = StreamAuthenticators::None;
		Mode = ShakeModes::None;
		AutoIncrement = false;
		Encryption = false;
		Finalized = false;
		Initialized = false;
		Preserve = false;
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
		Finalized = false;
		Initialized = false;
	}
};

//~~~Constant Tables~~//

const std::vector<byte> HBA::OMEGA_INFO =
{
	0x43, 0x48, 0x41, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, 0x20, 0x31, 0x2E, 0x30, 0x61
};

//~~~Constructor~~~//

HBA::HBA(BlockCiphers CipherType, StreamAuthenticators AuthenticatorType)
	:
	m_chaState(new HbaState()),
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
	m_chaState(new HbaState()),
	m_cipherMode(Cipher != nullptr ? 
		new CTR(Cipher) :
		throw CryptoCipherModeException(AeadModeConvert::ToName(AeadModes::HBA), std::string("Constructor"), std::string("The block cipher instance can not be null!"), ErrorCodes::IllegalOperation)),
	m_macAuthenticator(AuthenticatorType != StreamAuthenticators::None ?
		Helper::MacFromName::GetInstance(AuthenticatorType) :
		throw CryptoCipherModeException(AeadModeConvert::ToName(AeadModes::HBA), std::string("Constructor"), std::string("The MAC generator enumeration type can not be none!"), ErrorCodes::IllegalOperation))
{
}

HBA::~HBA()
{
	if (m_macAuthenticator != nullptr)
	{
		m_macAuthenticator.reset(nullptr);
	}

	if (m_chaState->Destroy)
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

bool &HBA::AutoIncrement()
{
	// does nothing, not supported or required with this mode
	return m_chaState->AutoIncrement;
}

const AeadModes HBA::Enumeral()
{
	return AeadModes::HBA;
}

const bool HBA::IsEncryption()
{
	return m_chaState->Encryption;
}

const bool HBA::IsInitialized()
{
	return m_chaState->Initialized;
}

const bool HBA::IsParallel()
{
	return ParallelProfile().IsParallel();
}

const std::vector<SymmetricKeySize> &HBA::LegalKeySizes()
{
	return m_cipherMode->LegalKeySizes();
}

const size_t HBA::MaxTagSize()
{
	return m_macAuthenticator->TagSize();
}

const size_t HBA::MinTagSize()
{
	return m_macAuthenticator->TagSize();
}

const std::string HBA::Name()
{
	std::string tmpn;

	tmpn = AeadModeConvert::ToName(Enumeral()) + std::string("-") + BlockCipherConvert::ToName(m_cipherMode->CipherType());

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

bool &HBA::PreserveAD()
{
	return m_chaState->Preserve;
}

const std::vector<byte> HBA::Tag()
{
	return SecureUnlock(m_chaState->MacTag);
}

const void HBA::Tag(SecureVector<byte> &Output)
{
	SecureCopy(m_chaState->MacTag, 0, Output, 0, m_chaState->MacTag.size());
}

//~~~Public Functions~~~//

void HBA::Finalize(std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	if (!IsInitialized())
	{
		throw CryptoCipherModeException(Name(), std::string("Finalize"), std::string("The cipher mode has not been finalized!"), ErrorCodes::NotInitialized);
	}

	SecureVector<byte> tmpc(Length);
	Finalize(tmpc, 0, Length);
	MemoryTools::Copy(tmpc, 0, Output, OutOffset, Length);
}

void HBA::Finalize(SecureVector<byte> &Output, size_t OutOffset, size_t Length)
{
	std::vector<byte> mctr(sizeof(ulong));

	if (!IsInitialized())
	{
		throw CryptoCipherModeException(Name(), std::string("Finalize"), std::string("The cipher mode has not been finalized!"), ErrorCodes::NotInitialized);
	}
	if (Length > m_macAuthenticator->TagSize())
	{
		throw CryptoCipherModeException(Name(), std::string("Finalize"), std::string("The length is longer than the mac code generated!"), ErrorCodes::InvalidSize);
	}

	// add the additional data
	if (m_chaState->AAD.size() != 0)
	{
		m_macAuthenticator->Update(SecureUnlock(m_chaState->AAD), 0, m_chaState->AAD.size());

		if (!PreserveAD())
		{
			// reset the tag if we are not maintaining it
			MemoryTools::Clear(m_chaState->AAD, 0, m_chaState->AAD.size());
			m_chaState->AAD.resize(0);
		}
	}

	// add the aad, nonce, and processed byte-count sizes to the mac counter
	IntegerTools::LeIncrease8(mctr, m_chaState->Counter + m_chaState->AAD.size() + m_cipherMode->Nonce().size());
	// the counter terminates the mac update stream
	m_macAuthenticator->Update(mctr, 0, mctr.size());

	// generate the mac code to state and copy to output
	m_chaState->MacTag.resize(m_macAuthenticator->TagSize());
	m_macAuthenticator->Finalize(m_chaState->MacTag, 0);
	SecureCopy(m_chaState->MacTag, 0, Output, OutOffset, Length);

	// create the new mac key: cSHAKE(k,c,n)
	// name string is an unsigned 64-bit bytes counter + key-size + cipher-name
	// the state counter is the number of bytes processed by the cipher
	IntegerTools::Le64ToBytes(m_chaState->Counter, m_chaState->Name, 0);
	// extract the new mac key
	Kdf::SHAKE gen(m_chaState->Mode);
	// bytes counter provides cSHAKE domain seperation in the stream; will generate a unique mac-key each time
	gen.Initialize(m_chaState->MacKey, m_chaState->Custom, m_chaState->Name);
	// use the second key parameter of legal keys to set the mac key length, the stronger [recommended] setting
	SymmetricKeySize ks = m_macAuthenticator->LegalKeySizes()[1];
	SecureVector<byte> mack(ks.KeySize());
	// generate the new mac key
	gen.Generate(mack);

	// reset the generator with the new key
	SymmetricKey kpm(mack);
	m_macAuthenticator->Initialize(kpm);
	// store the new key and erase the temporary key
	SecureMove(mack, m_chaState->MacKey, 0);
	m_chaState->Finalized = true;
}

void HBA::Initialize(bool Encryption, ISymmetricKey &Parameters)
{
	SecureVector<byte> tmpk(Parameters.KeySizes().KeySize());
	ushort kbits;

	if (!SymmetricKeySize::Contains(LegalKeySizes(), Parameters.KeySizes().KeySize()))
	{
		throw CryptoSymmetricException(Name(), std::string("Initialize"), std::string("Invalid key size; key must be one of the LegalKeySizes in length."), ErrorCodes::InvalidKey);
	}
	if (Parameters.KeySizes().NonceSize() != BLOCK_SIZE)
	{
		throw CryptoSymmetricException(Name(), std::string("Initialize"), std::string("Requires a nonce equal in size to the ciphers block size!"), ErrorCodes::InvalidNonce);
	}

	if (m_cipherMode->IsParallel())
	{
		if (ParallelProfile().IsParallel() && ParallelProfile().ParallelBlockSize() < ParallelProfile().ParallelMinimumSize() || ParallelProfile().ParallelBlockSize() > ParallelProfile().ParallelMaximumSize())
		{
			throw CryptoSymmetricException(Name(), std::string("Initialize"), std::string("The parallel block size is out of bounds!"), ErrorCodes::InvalidSize);
		}
		if (ParallelProfile().IsParallel() && ParallelProfile().ParallelBlockSize() % ParallelProfile().ParallelMinimumSize() != 0)
		{
			throw CryptoSymmetricException(Name(), std::string("Initialize"), std::string("The parallel block size must be evenly aligned to the ParallelMinimumSize!"), ErrorCodes::InvalidParam);
		}
	}

	// reset for a new key
	if (IsInitialized())
	{
		m_chaState->Reset();
	}

	// set up the state members
	m_chaState->Authenticator = static_cast<StreamAuthenticators>(m_macAuthenticator->Enumeral());
	// set the initial cipher and mac counter values
	m_chaState->Counter = 1;
	// store encryption flag
	m_chaState->Encryption = Encryption;

	// create the cSHAKE customization string
	m_chaState->Custom.resize(Parameters.KeySizes().InfoSize() + OMEGA_INFO.size());
	// copy the version string to the customization parameter
	MemoryTools::Copy(OMEGA_INFO, 0, m_chaState->Custom, 0, OMEGA_INFO.size());
	// copy the user defined string to the customization parameter
	MemoryTools::Copy(Parameters.Info(), 0, m_chaState->Custom, OMEGA_INFO.size(), Parameters.KeySizes().InfoSize());

	// create the HBA name string
	std::string tmpn = Name();
	// add mac counter, key-size bits, and algorithm name to name string
	m_chaState->Name.resize(sizeof(ulong) + sizeof(ushort) + tmpn.size());
	// mac nonce is always first 8 bytes of name
	IntegerTools::Le64ToBytes(m_chaState->Counter, m_chaState->Name, 0);
	// add the cipher key size in bits as an unsigned short integer
	kbits = static_cast<ushort>(Parameters.KeySizes().KeySize() * 8);
	IntegerTools::Le16ToBytes(kbits, m_chaState->Name, sizeof(ulong));
	// copy the name string to state
	MemoryTools::CopyFromObject(tmpn.data(), m_chaState->Name, sizeof(ulong) + sizeof(ushort), tmpn.size());

	// cipher key size determines key expansion function and Mac generator type; 256 or 512-bit
	m_chaState->Mode = (Parameters.KeySizes().KeySize() == 64) ? ShakeModes::SHAKE512 : (Parameters.KeySizes().KeySize() == 32) ? ShakeModes::SHAKE256 : ShakeModes::SHAKE1024;
	Kdf::SHAKE gen(m_chaState->Mode);
	// initialize cSHAKE with k,c,n
	gen.Initialize(Parameters.SecureKey(), m_chaState->Custom, m_chaState->Name);
	// generate the CTR key
	gen.Generate(tmpk);

	// initialize the CTR mode
	SymmetricKey ckp(tmpk, Parameters.SecureNonce(), Parameters.SecureInfo());
	m_cipherMode->Initialize(true, ckp);

	// generate the mac key
	SymmetricKeySize ks = m_macAuthenticator->LegalKeySizes()[1];
	SecureVector<byte> mack(ks.KeySize());
	gen.Generate(mack);

	// initialize the mac
	SymmetricKey kpm(mack);
	m_macAuthenticator->Initialize(kpm);

	// add the starting position of the nonce to the mac
	m_macAuthenticator->Update(m_cipherMode->Nonce(), 0, m_cipherMode->Nonce().size());

	// store the mac key
	m_chaState->MacKey.resize(mack.size());
	SecureMove(mack, m_chaState->MacKey, 0);
	m_chaState->Finalized = false;
	m_chaState->Initialized = true;
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
		throw CryptoSymmetricException(Name(), std::string("SetAssociatedData"), std::string("The cipher has not been initialized!"), ErrorCodes::NotInitialized);
	}

	m_chaState->AAD.resize(Length);
	MemoryTools::Copy(Input, Offset, m_chaState->AAD, 0, Length);
}

void HBA::SetAssociatedData(const SecureVector<byte> &Input, size_t Offset, size_t Length)
{
	if (!IsInitialized())
	{
		throw CryptoSymmetricException(Name(), std::string("SetAssociatedData"), std::string("The cipher has not been initialized!"), ErrorCodes::NotInitialized);
	}

	m_chaState->AAD.resize(Length);
	SecureCopy(Input, Offset, m_chaState->AAD, 0, Length);
}

void HBA::Transform(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");
	CEXASSERT(IntegerTools::Min(Input.size() - InOffset, Output.size() - OutOffset) >= Length, "The data arrays are smaller than the the request-size!");

	if (IsEncryption())
	{
		m_cipherMode->Transform(Input, InOffset, Output, OutOffset, Length);
		m_macAuthenticator->Update(Output, OutOffset, Length);
	}
	else
	{
		m_macAuthenticator->Update(Input, InOffset, Length);
		m_cipherMode->Transform(Input, InOffset, Output, OutOffset, Length);
	}

	// update the mac counter
	m_chaState->Counter += Length;
}

bool HBA::Verify(const std::vector<byte> &Input, size_t Offset, size_t Length)
{
	bool ret;

	if (Length < MIN_TAGSIZE)
	{
		throw CryptoCipherModeException(Name(), std::string("Verify"), std::string("The length must be minimum of 12 and maximum of MAC code size!"), ErrorCodes::InvalidSize);
	}
	if (IsEncryption())
	{
		throw CryptoCipherModeException(Name(), std::string("Verify"), std::string("The mode has not been initialized for decryption!"), ErrorCodes::IllegalOperation);
	}
	if (!IsInitialized() && m_chaState->MacTag.size() == 0)
	{
		throw CryptoCipherModeException(Name(), std::string("Verify"), std::string("The cipher mode has not been initialized!"), ErrorCodes::NotInitialized);
	}

	// skipped finalization and used verify directly on decrypt
	if (!m_chaState->Finalized)
	{
		m_chaState->MacTag.resize(m_macAuthenticator->TagSize());
		Finalize(m_chaState->MacTag, 0, m_chaState->MacTag.size());
	}

	ret = IntegerTools::Compare(m_chaState->MacTag, 0, Input, Offset, Length);
	m_chaState->Finalized = true;

	return ret;
}

bool HBA::Verify(const SecureVector<byte> &Input, size_t Offset, size_t Length)
{
	bool ret;

	if (Length < MIN_TAGSIZE)
	{
		throw CryptoCipherModeException(Name(), std::string("Verify"), std::string("The length must be minimum of 12 and maximum of MAC code size!"), ErrorCodes::InvalidSize);
	}
	if (IsEncryption())
	{
		throw CryptoCipherModeException(Name(), std::string("Verify"), std::string("The mode has not been initialized for decryption!"), ErrorCodes::IllegalOperation);
	}
	if (!IsInitialized() && m_chaState->MacTag.size() == 0)
	{
		throw CryptoCipherModeException(Name(), std::string("Verify"), std::string("The cipher mode has not been initialized!"), ErrorCodes::NotInitialized);
	}

	if (!m_chaState->Finalized)
	{
		m_chaState->MacTag.resize(m_macAuthenticator->TagSize());
		Finalize(m_chaState->MacTag, 0, m_chaState->MacTag.size());
	}

	ret = IntegerTools::Compare(m_chaState->MacTag, 0, Input, Offset, Length);
	m_chaState->Finalized = true;

	return ret;
}

NAMESPACE_MODEEND
