#include "GCM.h"
#include "IntegerTools.h"
#include "MemoryTools.h"

NAMESPACE_MODE

using Enumeration::BlockCipherConvert;
using Enumeration::CipherModeConvert;
using Utility::IntegerTools;
using Utility::MemoryTools;

class GCM::GcmState
{
public:

	std::vector<byte> AAD;
	SecureVector<byte> Buffer;
	SecureVector<byte> Key;
	std::vector<byte> Nonce;
	std::vector<byte> Tag;
	size_t Counter;
	bool AutoIncrement;
	bool Destroyed;
	bool Encryption;
	bool Finalized;
	bool Initialized;
	bool Preserve;

	GcmState(bool IsDestroyed)
		:
		AAD(0),
		Buffer(0),
		Key(0),
		Nonce(BLOCK_SIZE, 0x00),
		Tag(BLOCK_SIZE, 0x00),
		Counter(0),
		AutoIncrement(false),
		Destroyed(IsDestroyed),
		Encryption(false),
		Finalized(false),
		Initialized(false),
		Preserve(false)
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
		AutoIncrement = false;
		Destroyed = false;
		Encryption = false;
		Finalized = false;
		Initialized = false;
		Preserve = false;
	}
};

//~~~Constructor~~~//

GCM::GCM(BlockCiphers CipherType)
	:
	m_gcmState(new GcmState(true)),
	m_cipherMode(CipherType != BlockCiphers::None ? new CTR(CipherType) :
		throw CryptoCipherModeException(CipherModeConvert::ToName(CipherModes::GCM), std::string("Constructor"), std::string("The block cipher type can nor be None!"), ErrorCodes::InvalidParam)),
	m_gcmHash(new Digest::GHASH()),
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
		throw CryptoCipherModeException(CipherModeConvert::ToName(CipherModes::GCM), std::string("Constructor"), std::string("The block cipher can nor be null!"), ErrorCodes::IllegalOperation)),
	m_gcmHash(new Digest::GHASH()),
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
	if (m_gcmHash)
	{
		m_gcmHash->Reset();
		m_gcmHash.reset(nullptr);
	}

	if (m_gcmState->Destroyed)
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

bool &GCM::AutoIncrement()
{
	return m_gcmState->AutoIncrement;
}

const size_t GCM::BlockSize()
{
	return BLOCK_SIZE;
}

const BlockCiphers GCM::CipherType()
{
	return m_cipherMode->Engine()->Enumeral();
}

IBlockCipher* GCM::Engine()
{
	return m_cipherMode->Engine();
}

const CipherModes GCM::Enumeral()
{
	return CipherModes::GCM;
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

const size_t GCM::MaxTagSize()
{
	return BLOCK_SIZE;
}

const size_t GCM::MinTagSize()
{
	return MIN_TAGSIZE;
}

const std::string GCM::Name()
{
	std::string tmpn;

	tmpn = CipherModeConvert::ToName(Enumeral()) + std::string("-") + BlockCipherConvert::ToName(CipherType());

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

bool &GCM::PreserveAD()
{
	return m_gcmState->Preserve;
}

const std::vector<byte> GCM::Tag()
{
	return m_gcmState->Tag;
}

//~~~Public Functions~~~//

void GCM::DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");
	CEXASSERT(!IsEncryption(), "The cipher mode has been initialized for encryption!");
	CEXASSERT(IntegerTools::Min(Input.size(), Output.size()) >= BLOCK_SIZE, "The data arrays are smaller than the the block-size!");

	Decrypt128(Input, 0, Output, 0);
}

void GCM::DecryptBlock(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");
	CEXASSERT(!IsEncryption(), "The cipher mode has been initialized for encryption!");
	CEXASSERT(IntegerTools::Min(Input.size() - InOffset, Output.size() - OutOffset) >= BLOCK_SIZE, "The data arrays are smaller than the the block-size!");

	Decrypt128(Input, InOffset, Output, OutOffset);
}

void GCM::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");
	CEXASSERT(IsEncryption(), "The cipher mode has been initialized for encryption!");
	CEXASSERT(IntegerTools::Min(Input.size(), Output.size()) >= BLOCK_SIZE, "The data arrays are smaller than the the block-size!");

	Encrypt128(Input, 0, Output, 0);
}

void GCM::EncryptBlock(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");
	CEXASSERT(IsEncryption(), "The cipher mode has been initialized for encryption!");
	CEXASSERT(IntegerTools::Min(Input.size() - InOffset, Output.size() - OutOffset) >= BLOCK_SIZE, "The data arrays are smaller than the the block-size!");

	Encrypt128(Input, InOffset, Output, OutOffset);
}

void GCM::Finalize(std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	if (Length < MIN_TAGSIZE || Length > BLOCK_SIZE)
	{
		throw CryptoCipherModeException(Name(), std::string("Finalize"), std::string("The length must be minimum of 12 and maximum of MAC code size!"), ErrorCodes::InvalidSize);
	}
	if (!IsInitialized())
	{
		throw CryptoCipherModeException(Name(), std::string("Finalize"), std::string("The cipher mode has not been finalized!"), ErrorCodes::NotInitialized);
	}

	Compute();
	MemoryTools::Copy(m_gcmState->Tag, 0, Output, OutOffset, Length);
}

void GCM::Finalize(SecureVector<byte> &Output, size_t OutOffset, size_t Length)
{
	if (Length < MIN_TAGSIZE || Length > BLOCK_SIZE)
	{
		throw CryptoCipherModeException(Name(), std::string("Finalize"), std::string("The length must be minimum of 12 and maximum of MAC code size!"), ErrorCodes::InvalidSize);
	}
	if (!IsInitialized())
	{
		throw CryptoCipherModeException(Name(), std::string("Finalize"), std::string("The cipher mode has not been finalized!"), ErrorCodes::NotInitialized);
	}

	Compute();
	MemoryTools::Copy(m_gcmState->Tag, 0, Output, OutOffset, Length);
}

void GCM::Initialize(bool Encryption, ISymmetricKey &Parameters)
{
	if (!PreserveAD())
	{
		MemoryTools::Clear(m_gcmState->AAD, 0, m_gcmState->AAD.size());
	}

	if (!AutoIncrement())
	{
		m_gcmHash->Reset();
		MemoryTools::Clear(m_gcmState->Buffer, 0, m_gcmState->Buffer.size());
		m_gcmState->Counter = 0;
	}

	MemoryTools::Clear(m_gcmState->Tag, 0, m_gcmState->Tag.size());

	if (Parameters.KeySizes().NonceSize() < MIN_NONCESIZE)
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
		if (Parameters.SecureNonce() == m_gcmState->Buffer)
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
		const std::vector<byte> ZEROES(BLOCK_SIZE);
		m_cipherMode->Engine()->Transform(ZEROES, 0, tmph, 0);

		std::vector<ulong> gkey = 
		{
			IntegerTools::BeBytesTo64(tmph, 0),
			IntegerTools::BeBytesTo64(tmph, 8)
		};

		// initialize the ghash function
		m_gcmHash->Initialize(gkey);
		// store the key in a secure-vector
		m_gcmState->Key.resize(Parameters.KeySizes().KeySize());
		MemoryTools::Copy(Parameters.SecureKey(), 0, m_gcmState->Key, 0, m_gcmState->Key.size());
	}

	// load the state
	m_gcmState->Encryption = Encryption;
	m_gcmState->Buffer.resize(Parameters.KeySizes().NonceSize());
	MemoryTools::Copy(Parameters.Nonce(), 0, m_gcmState->Buffer, 0, m_gcmState->Buffer.size());

	// create the CTR mode nonce
	if (m_gcmState->Buffer.size() == MIN_TAGSIZE)
	{
		MemoryTools::Copy(m_gcmState->Buffer, 0, m_gcmState->Nonce, 0, m_gcmState->Buffer.size());
		m_gcmState->Nonce[BLOCK_SIZE - 1] = 0x01;
	}
	else
	{
		std::vector<byte> tmpn(BLOCK_SIZE);
		m_gcmHash->Multiply(Unlock(m_gcmState->Buffer), tmpn, m_gcmState->Buffer.size());
		m_gcmHash->Finalize(tmpn, 0, m_gcmState->Buffer.size());
		MemoryTools::Copy(tmpn, 0, m_gcmState->Nonce, 0, m_gcmState->Nonce.size());
	}

	// initialize the CTR mode
	SymmetricKey ckp(m_gcmState->Key, Lock(m_gcmState->Nonce));
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
	if (!IsInitialized())
	{
		throw CryptoCipherModeException(Name(), std::string("SetAssociatedData"), std::string("The cipher mode has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (m_gcmState->AAD.size() != 0)
	{
		throw CryptoCipherModeException(Name(), std::string("SetAssociatedData"), std::string("The associated data has already been set!"), ErrorCodes::IllegalOperation);
	}

	m_gcmState->AAD.resize(Length);
	MemoryTools::Copy(Input, Offset, m_gcmState->AAD, 0, Length);
	m_gcmHash->Multiply(m_gcmState->AAD, m_gcmState->Tag, Length);
}

void GCM::Transform(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");
	CEXASSERT(IntegerTools::Min(Input.size() - InOffset, Output.size() - OutOffset) >= Length, "The data arrays are smaller than the the block-size!");

	if (IsEncryption())
	{
		m_cipherMode->Transform(Input, InOffset, Output, OutOffset, Length);
		m_gcmHash->Update(Output, OutOffset, m_gcmState->Tag, Length);
	}
	else
	{
		m_gcmHash->Update(Input, InOffset, m_gcmState->Tag, Length);
		m_cipherMode->Transform(Input, InOffset, Output, OutOffset, Length);
	}

	m_gcmState->Counter += Length;
}

bool GCM::Verify(const std::vector<byte> &Input, size_t Offset, size_t Length)
{
	if (IsEncryption())
	{
		throw CryptoCipherModeException(Name(), std::string("Verify"), std::string("The cipher mode has not been initialized for decryption!"), ErrorCodes::NotInitialized);
	}
	if (!IsInitialized() && !m_gcmState->Finalized)
	{
		throw CryptoCipherModeException(Name(), std::string("Verify"), std::string("The cipher mode has not been initialized for decryption!"), ErrorCodes::NotInitialized);
	}
	if (Length < MIN_TAGSIZE || Length > BLOCK_SIZE)
	{
		throw CryptoCipherModeException(Name(), std::string("Verify"), std::string("The length must be minimum of 12 and maximum of MAC code size!"), ErrorCodes::InvalidSize);
	}

	if (!m_gcmState->Finalized)
	{
		Compute();
	}

	return IntegerTools::Compare(m_gcmState->Tag, 0, Input, Offset, Length);
}

bool GCM::Verify(const SecureVector<byte> &Input, size_t Offset, size_t Length)
{
	if (IsEncryption())
	{
		throw CryptoCipherModeException(Name(), std::string("Verify"), std::string("The cipher mode has not been initialized for decryption!"), ErrorCodes::NotInitialized);
	}
	if (!IsInitialized() && !m_gcmState->Finalized)
	{
		throw CryptoCipherModeException(Name(), std::string("Verify"), std::string("The cipher mode has not been initialized for decryption!"), ErrorCodes::NotInitialized);
	}
	if (Length < MIN_TAGSIZE || Length > BLOCK_SIZE)
	{
		throw CryptoCipherModeException(Name(), std::string("Verify"), std::string("The length must be minimum of 12 and maximum of MAC code size!"), ErrorCodes::InvalidSize);
	}

	if (!m_gcmState->Finalized)
	{
		Compute();
	}

	return IntegerTools::Compare(m_gcmState->Tag, 0, Input, Offset, Length);
}

//~~~Private Functions~~~//

void GCM::Compute()
{
	// finalize the mac to the tag vector
	m_gcmHash->Finalize(m_gcmState->Tag, m_gcmState->AAD.size(), m_gcmState->Counter);
	// mix the tag with the nonce
	MemoryTools::XOR128(m_gcmState->Nonce, 0, m_gcmState->Tag, 0);

	// clear if not retaining AAD
	if (!m_gcmState->Preserve)
	{
		MemoryTools::Clear(m_gcmState->AAD, 0, m_gcmState->AAD.size());
		m_gcmState->AAD.resize(0);
	}

	// reset the hash function and internal state
	m_gcmHash->Clear();
	m_gcmState->Initialized = false;
	MemoryTools::Clear(m_gcmState->Nonce, 0, m_gcmState->Nonce.size());
	m_gcmState->Counter = 0;

	// if using auto, increment the nonce and re-initialize the mode
	if (AutoIncrement())
	{
		SecureVector<byte> tmpn = m_gcmState->Buffer;
		IntegerTools::BeIncrement8(tmpn);
		const SecureVector<byte> ZERO(0);
		SymmetricKey kp(ZERO, tmpn);
		Initialize(IsEncryption(), kp);

		if (m_gcmState->Preserve)
		{
			m_gcmHash->Multiply(m_gcmState->AAD, m_gcmState->Tag, m_gcmState->AAD.size());
		}
	}

	m_gcmState->Finalized = true;
}

void GCM::Decrypt128(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	m_gcmHash->Update(Input, InOffset, m_gcmState->Tag, BLOCK_SIZE);
	m_cipherMode->EncryptBlock(Input, InOffset, Output, OutOffset);
	m_gcmState->Counter += BLOCK_SIZE;
}

void GCM::Encrypt128(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	m_cipherMode->EncryptBlock(Input, InOffset, Output, OutOffset);
	m_gcmHash->Update(Input, InOffset, m_gcmState->Tag, BLOCK_SIZE);
	m_gcmState->Counter += BLOCK_SIZE;
}

NAMESPACE_MODEEND
