#include "GCM.h"
#include "IntegerTools.h"
#include "MemoryTools.h"

NAMESPACE_MODE

using Enumeration::BlockCipherConvert;
using Enumeration::AeadModeConvert;
using Tools::IntegerTools;
using Tools::MemoryTools;

class GCM::GcmState
{
public:

	std::vector<byte> AAD;
	SecureVector<byte> Buffer;
	SecureVector<byte> Key;
	std::vector<byte> Nonce;
	std::vector<byte> Tag;
	size_t Counter;
	bool Destroyed;
	bool Encryption;
	bool Finalized;
	bool Initialized;

	GcmState(bool IsDestroyed)
		:
		AAD(0),
		Buffer(0),
		Key(0),
		Nonce(BLOCK_SIZE, 0x00),
		Tag(BLOCK_SIZE, 0x00),
		Counter(0),
		Destroyed(IsDestroyed),
		Encryption(false),
		Finalized(false),
		Initialized(false)
	{
	}

	~GcmState()
	{
		Reset();
	}

	void Reset()
	{
		MemoryTools::Clear(AAD, 0, AAD.size());
		MemoryTools::Clear(Buffer, 0, Buffer.size());
		MemoryTools::Clear(Key, 0, Key.size());
		MemoryTools::Clear(Nonce, 0, Nonce.size());
		MemoryTools::Clear(Tag, 0, Tag.size());
		Counter = 0;
		Destroyed = false;
		Encryption = false;
		Finalized = false;
		Initialized = false;
	}
};

//~~~Constructor~~~//

GCM::GCM(BlockCiphers CipherType)
	:
	m_gcmState(new GcmState(true)),
	m_cipherMode(CipherType != BlockCiphers::None ? 
		new CTR(CipherType) : 
		throw CryptoCipherModeException(AeadModeConvert::ToName(AeadModes::GCM), std::string("Constructor"), std::string("The block cipher type can nor be None!"), ErrorCodes::InvalidParam)), //-V2571
	m_macAuthenticator(new Digest::GHASH()),
	m_legalKeySizes((CipherType == BlockCiphers::AES || CipherType == BlockCiphers::Serpent) ?
		std::vector<SymmetricKeySize> { 
			SymmetricKeySize(16, BLOCK_SIZE, 0), 
			SymmetricKeySize(24, BLOCK_SIZE, 0),
			SymmetricKeySize(32, BLOCK_SIZE, 0) } :
		std::vector<SymmetricKeySize> { 
			SymmetricKeySize(16, BLOCK_SIZE, 0), 
			SymmetricKeySize(32, BLOCK_SIZE, 0), 
			SymmetricKeySize(64, BLOCK_SIZE, 0) }),
	m_parallelProfile(BLOCK_SIZE, m_cipherMode->ParallelProfile().IsParallel(), m_cipherMode->ParallelProfile().ParallelBlockSize(),
		m_cipherMode->ParallelProfile().ParallelMaxDegree(), true, m_cipherMode->Engine()->StateCacheSize(), true)
{
}

GCM::GCM(IBlockCipher* Cipher)
	:
	m_gcmState(new GcmState(false)),
	m_cipherMode(Cipher != nullptr ? new CTR(Cipher) :
		throw CryptoCipherModeException(AeadModeConvert::ToName(AeadModes::GCM), std::string("Constructor"), std::string("The block cipher can nor be null!"), ErrorCodes::IllegalOperation)), //-V2571
	m_macAuthenticator(new Digest::GHASH()),
	m_legalKeySizes((Cipher == nullptr || Cipher->Enumeral() == BlockCiphers::AES || Cipher->Enumeral() == BlockCiphers::Serpent) ?
		std::vector<SymmetricKeySize> { 
			SymmetricKeySize(16, BLOCK_SIZE, 0), 
			SymmetricKeySize(24, BLOCK_SIZE, 0), 
			SymmetricKeySize(32, BLOCK_SIZE, 0) } :
		std::vector<SymmetricKeySize>{ 
			SymmetricKeySize(16, BLOCK_SIZE, 0), 
			SymmetricKeySize(32, BLOCK_SIZE, 0), 
			SymmetricKeySize(64, BLOCK_SIZE, 0) }),
	m_parallelProfile(BLOCK_SIZE, m_cipherMode->ParallelProfile().IsParallel(), m_cipherMode->ParallelProfile().ParallelBlockSize(),
		m_cipherMode->ParallelProfile().ParallelMaxDegree(), true, m_cipherMode->Engine()->StateCacheSize(), true)
{
}

GCM::~GCM()
{
	if (m_macAuthenticator)
	{
		m_macAuthenticator->Reset();
		m_macAuthenticator.reset(nullptr);
	}

	if (m_gcmState->Destroyed)
	{
		if (m_cipherMode != nullptr)
		{
			m_cipherMode.reset(nullptr);
		}
	}
}

//~~~Accessors~~~//

const AeadModes GCM::Enumeral()
{
	return AeadModes::GCM;
}

const bool GCM::IsEncryption()
{
	return m_gcmState->Encryption;
}

const bool GCM::IsInitialized()
{
	return m_gcmState->Initialized;
}

const bool GCM::IsParallel()
{
	return m_parallelProfile.IsParallel();
}

const std::vector<SymmetricKeySize> &GCM::LegalKeySizes()
{
	return m_legalKeySizes;
}

const std::string GCM::Name()
{
	std::string tmpn;

	tmpn = AeadModeConvert::ToName(Enumeral()) + std::string("-") + BlockCipherConvert::ToName(m_cipherMode->CipherType());

	return tmpn;
}

const size_t GCM::ParallelBlockSize()
{
	return m_parallelProfile.ParallelBlockSize();
}

ParallelOptions &GCM::ParallelProfile()
{
	return m_parallelProfile;
}

const std::vector<byte> GCM::Tag()
{
	return m_gcmState->Tag;
}

const void GCM::Tag(SecureVector<byte> &Output)
{
	SecureInsert(m_gcmState->Tag, 0, Output, 0, m_gcmState->Tag.size());
}

const size_t GCM::TagSize()
{
	return m_macAuthenticator->TagSize();
}

//~~~Public Functions~~~//

void GCM::Initialize(bool Encryption, ISymmetricKey &Parameters)
{
	MemoryTools::Clear(m_gcmState->AAD, 0, m_gcmState->AAD.size());
	m_macAuthenticator->Reset();
	MemoryTools::Clear(m_gcmState->Buffer, 0, m_gcmState->Buffer.size());
	m_gcmState->Counter = 0;

	MemoryTools::Clear(m_gcmState->Tag, 0, m_gcmState->Tag.size());

	if (Parameters.KeySizes().IVSize() < MIN_NONCESIZE)
	{
		throw CryptoCipherModeException(Name(), std::string("Initialize"), std::string("Requires a nonce of minimum 10 bytes in length!"), ErrorCodes::InvalidNonce);
	}

	if (m_parallelProfile.IsParallel())
	{
		if (IsParallel() && ParallelBlockSize() < m_parallelProfile.ParallelMinimumSize() || ParallelBlockSize() > m_parallelProfile.ParallelMaximumSize())
		{
			throw CryptoCipherModeException(Name(), std::string("Initialize"), std::string("The parallel block size is out of bounds!"), ErrorCodes::InvalidSize);
		}
		if (IsParallel() && ParallelBlockSize() % m_parallelProfile.ParallelMinimumSize() != 0)
		{
			throw CryptoCipherModeException(Name(), std::string("Initialize"), std::string("The parallel block size must be evenly aligned to the ParallelMinimumSize!"), ErrorCodes::InvalidParam);
		}
	}

	if (Parameters.KeySizes().KeySize() == 0)
	{
		if (Parameters.SecureIV() == m_gcmState->Buffer)
		{
			throw CryptoCipherModeException(Name(), std::string("Initialize"), std::string("The nonce can not be zeroised or repeating!"), ErrorCodes::InvalidNonce);
		}
		if (!m_cipherMode->IsInitialized())
		{
			throw CryptoCipherModeException(Name(), std::string("Initialize"), std::string("First initialization requires a key and nonce!"), ErrorCodes::IllegalOperation);
		}
	}
	else
	{
		if (!SymmetricKeySize::Contains(LegalKeySizes(), Parameters.KeySizes().KeySize()))
		{
			throw CryptoCipherModeException(Name(), std::string("Initialize"), std::string("Invalid key size; key must be one of the LegalKeySizes in length!"), ErrorCodes::InvalidKey);
		}

		// key the block-cipher and create the hash key
		m_cipherMode->Engine()->Initialize(true, Parameters);
		std::vector<byte> tmph(BLOCK_SIZE);
		const std::vector<byte> ZEROES(BLOCK_SIZE, 0x00);
		m_cipherMode->Engine()->Transform(ZEROES, 0, tmph, 0);

		std::vector<ulong> gkey = 
		{
			IntegerTools::BeBytesTo64(tmph, 0),
			IntegerTools::BeBytesTo64(tmph, 8)
		};

		// initialize the ghash function
		m_macAuthenticator->Initialize(gkey);
		// store the key in a secure-vector
		m_gcmState->Key.resize(Parameters.KeySizes().KeySize());
		MemoryTools::Copy(Parameters.SecureKey(), 0, m_gcmState->Key, 0, m_gcmState->Key.size());
	}

	// load the state
	m_gcmState->Encryption = Encryption;
	m_gcmState->Buffer.resize(Parameters.KeySizes().IVSize());
	MemoryTools::Copy(Parameters.IV(), 0, m_gcmState->Buffer, 0, m_gcmState->Buffer.size());

	// create the CTR mode nonce
	if (m_gcmState->Buffer.size() == MIN_TAGSIZE)
	{
		MemoryTools::Copy(m_gcmState->Buffer, 0, m_gcmState->Nonce, 0, m_gcmState->Buffer.size());
		m_gcmState->Nonce[BLOCK_SIZE - 1] = 0x01;
	}
	else
	{
		std::vector<byte> tmpn(BLOCK_SIZE);
		m_macAuthenticator->Multiply(SecureUnlock(m_gcmState->Buffer), tmpn, m_gcmState->Buffer.size());
		m_macAuthenticator->Finalize(tmpn, 0, m_gcmState->Buffer.size());
		MemoryTools::Copy(tmpn, 0, m_gcmState->Nonce, 0, m_gcmState->Nonce.size());
	}

	// initialize the CTR mode
	SymmetricKey ckp(m_gcmState->Key, SecureLock(m_gcmState->Nonce));
	m_cipherMode->Initialize(true, ckp);
	m_cipherMode->ParallelProfile().Calculate(m_parallelProfile.IsParallel(), m_parallelProfile.ParallelBlockSize(), m_parallelProfile.ParallelMaxDegree());

	// permute the nonce for ghash
	std::vector<byte> tmpn(BLOCK_SIZE);
	m_cipherMode->Transform(tmpn, 0, m_gcmState->Nonce, 0, BLOCK_SIZE);

	// reset the initialization and finalization state
	m_gcmState->Finalized = false;
	m_gcmState->Initialized = true;
}

void GCM::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0 || Degree % 2 != 0 || Degree > m_parallelProfile.ProcessorCount())
	{
		throw CryptoCipherModeException(Name(), std::string("ParallelMaxDegree"), std::string("Degree setting is invalid!"), ErrorCodes::NotSupported);
	}

	m_parallelProfile.SetMaxDegree(Degree);
}

void GCM::SetAssociatedData(const std::vector<byte> &Input, size_t Offset, size_t Length)
{
	if (IsInitialized() == false)
	{
		throw CryptoCipherModeException(Name(), std::string("SetAssociatedData"), std::string("The cipher mode has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (m_gcmState->AAD.size() != 0)
	{
		throw CryptoCipherModeException(Name(), std::string("SetAssociatedData"), std::string("The associated data has already been set!"), ErrorCodes::IllegalOperation);
	}

	m_gcmState->AAD.resize(Length);
	MemoryTools::Copy(Input, Offset, m_gcmState->AAD, 0, Length);
	m_macAuthenticator->Multiply(m_gcmState->AAD, m_gcmState->Tag, Length);
}

void GCM::SetAssociatedData(const SecureVector<byte> &Input, size_t Offset, size_t Length)
{
	if (IsInitialized() == false)
	{
		throw CryptoCipherModeException(Name(), std::string("SetAssociatedData"), std::string("The cipher mode has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (m_gcmState->AAD.size() != 0)
	{
		throw CryptoCipherModeException(Name(), std::string("SetAssociatedData"), std::string("The associated data has already been set!"), ErrorCodes::IllegalOperation);
	}

	m_gcmState->AAD.resize(Length);
	MemoryTools::Copy(Input, Offset, m_gcmState->AAD, 0, Length);
	m_macAuthenticator->Multiply(m_gcmState->AAD, m_gcmState->Tag, Length);
}

void GCM::Transform(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");
	CEXASSERT(IntegerTools::Min(Input.size() - InOffset, Output.size() - OutOffset) >= Length, "The data arrays are smaller than the the block-size!");

	m_gcmState->Counter += Length;

	if (IsEncryption() == true)
	{
		// encrypt plain-text
		m_cipherMode->Transform(Input, InOffset, Output, OutOffset, Length);
		// process the cipher-text
		m_macAuthenticator->Update(Output, OutOffset, m_gcmState->Tag, Length);
		// append the tag to the cipher-text
		Finalize(Output, OutOffset + Length, TagSize());
	}
	else
	{
		// process the cipher-text
		m_macAuthenticator->Update(Input, InOffset, m_gcmState->Tag, Length);

		// compare the MAC code appended to the ciphertext with the one generated, if they do not match, throw exception bybassing decryption
		if (!Verify(Input, InOffset + Length, TagSize()))
		{
			throw CryptoAuthenticationFailure(Name(), std::string("Transform"), std::string("The authentication tag does not match!"), ErrorCodes::AuthenticationFailure);
		}

		m_cipherMode->Transform(Input, InOffset, Output, OutOffset, Length);
	}
}

//~~~Private Functions~~~//

void GCM::Finalize(std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	if (Length < MIN_TAGSIZE || Length > BLOCK_SIZE)
	{
		throw CryptoCipherModeException(Name(), std::string("Finalize"), std::string("The length must be minimum of 12 and maximum of MAC code size!"), ErrorCodes::InvalidSize);
	}
	if (IsInitialized() == false)
	{
		throw CryptoCipherModeException(Name(), std::string("Finalize"), std::string("The cipher mode has not been finalized!"), ErrorCodes::NotInitialized);
	}

	// finalize the mac to the tag vector
	m_macAuthenticator->Finalize(m_gcmState->Tag, m_gcmState->AAD.size(), m_gcmState->Counter); 

	// mix the tag with the nonce
	MemoryTools::XOR128(m_gcmState->Nonce, 0, m_gcmState->Tag, 0);

	// reset aad
	MemoryTools::Clear(m_gcmState->AAD, 0, m_gcmState->AAD.size());
	m_gcmState->AAD.resize(0);

	// reset the hash function and internal state
	m_macAuthenticator->Clear();

	// reset state
	MemoryTools::Clear(m_gcmState->Nonce, 0, m_gcmState->Nonce.size());
	m_gcmState->Counter = 0;
	MemoryTools::Copy(m_gcmState->Tag, 0, Output, OutOffset, Length);
	m_gcmState->Initialized = false;
}

bool GCM::Verify(const std::vector<byte> &Input, size_t Offset, size_t Length)
{
	std::vector<byte> code(TagSize());
	bool ret;

	// finalize the mac-code
	Finalize(code, 0, code.size());

	MemoryTools::Clear(m_gcmState->Tag, 0, TagSize());
	m_gcmState->Tag.resize(TagSize());

	// constant-time comparison of cipher-text MAC and MAC code generated internally
	ret = IntegerTools::Compare(code, 0, Input, Offset, Length);

	if (ret == true)
	{
		// store mac-code in state
		MemoryTools::Copy(code, 0, m_gcmState->Tag, 0, TagSize());
	}

	return ret;
}

NAMESPACE_MODEEND
