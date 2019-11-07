#include "EAX.h"
#include "IntegerTools.h"
#include "ParallelTools.h"

NAMESPACE_MODE

using Enumeration::BlockCipherConvert;
using Enumeration::CipherModeConvert;
using Utility::IntegerTools;
using Utility::MemoryTools;

class EAX::EaxState
{
public:

	std::vector<byte> AAD;
	std::vector<byte> Buffer;
	SecureVector<byte> Key;
	SecureVector<byte> Nonce;
	std::vector<byte> Tag;
	bool AutoIncrement;
	bool Destroyed;
	bool Encryption;
	bool Initialized;
	bool Preserve;

	EaxState(bool IsDestroyed)
		:
		AAD(0),
		Buffer(BLOCK_SIZE, 0x00),
		Key(0),
		Nonce(BLOCK_SIZE, 0x00),
		Tag(0),
		AutoIncrement(false),
		Destroyed(IsDestroyed),
		Encryption(false),
		Initialized(false),
		Preserve(false)
	{
	}

	~EaxState()
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
		AutoIncrement = false;
		Destroyed = false;
		Encryption = false;
		Initialized = false;
		Preserve = false;
	}
};

//~~~Constructor~~~//

EAX::EAX(BlockCiphers CipherType)
	:
	m_eaxState(new EaxState(true)),
	m_cipherMode(CipherType != BlockCiphers::None ? new CTR(CipherType) :
		throw CryptoCipherModeException(CipherModeConvert::ToName(CipherModes::EAX), std::string("Constructor"), std::string("The block cipher enumeration type can nor be none!"), ErrorCodes::InvalidParam)),
	m_macGenerator(new Mac::CMAC(m_cipherMode->Engine())),
	m_parallelProfile(BLOCK_SIZE, m_cipherMode->ParallelProfile().IsParallel(), m_cipherMode->ParallelProfile().ParallelBlockSize(),
		m_cipherMode->ParallelProfile().ParallelMaxDegree(), true, m_cipherMode->Engine()->StateCacheSize(), true)
{
}

EAX::EAX(IBlockCipher* Cipher)
	:
	m_eaxState(new EaxState(false)),
	m_cipherMode(Cipher != nullptr ? new CTR(Cipher) :
		throw CryptoCipherModeException(CipherModeConvert::ToName(CipherModes::EAX), std::string("Constructor"), std::string("The block cipher instance can nor be null!"), ErrorCodes::IllegalOperation)),
	m_macGenerator(new Mac::CMAC(Cipher)),
	m_parallelProfile(BLOCK_SIZE, m_cipherMode->ParallelProfile().IsParallel(), m_cipherMode->ParallelProfile().ParallelBlockSize(),
		m_cipherMode->ParallelProfile().ParallelMaxDegree(), true, m_cipherMode->Engine()->StateCacheSize(), true)
{
}

EAX::~EAX()
{
	if (m_macGenerator != nullptr)
	{
		m_macGenerator.reset(nullptr);
	}

	if (m_eaxState->Destroyed)
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

bool &EAX::AutoIncrement() 
{
	return m_eaxState->AutoIncrement; 
}

const size_t EAX::BlockSize()
{ 
	return BLOCK_SIZE; 
}

const BlockCiphers EAX::CipherType() 
{ 
	return m_cipherMode->Engine()->Enumeral();
}

IBlockCipher* EAX::Engine() 
{ 
	return m_cipherMode->Engine();
}

const CipherModes EAX::Enumeral()
{
	return CipherModes::EAX; 
}

const bool EAX::IsEncryption()
{ 
	return m_eaxState->Encryption; 
}

const bool EAX::IsInitialized() 
{ 
	return m_eaxState->Initialized; 
}

const bool EAX::IsParallel() 
{
	return m_parallelProfile.IsParallel();
}

const std::vector<SymmetricKeySize> &EAX::LegalKeySizes()
{
	return m_cipherMode->LegalKeySizes();
}

const size_t EAX::MaxTagSize() 
{ 
	return BLOCK_SIZE;
}

const size_t EAX::MinTagSize()
{
	return MIN_TAGSIZE; 
}

const std::string EAX::Name()
{ 
	std::string tmpn;

	tmpn = CipherModeConvert::ToName(Enumeral()) + std::string("-") + BlockCipherConvert::ToName(CipherType());

	return tmpn;
}

const size_t EAX::ParallelBlockSize()
{ 
	return m_parallelProfile.ParallelBlockSize(); 
}

ParallelOptions &EAX::ParallelProfile()
{
	return m_parallelProfile;
}

bool &EAX::PreserveAD()
{ 
	return m_eaxState->Preserve; 
}

const std::vector<byte> EAX::Tag()
{
	return m_eaxState->Tag;
}

//~~~Public Functions~~~//

void EAX::DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");
	CEXASSERT(!IsEncryption(), "The cipher mode has been initialized for encryption!");
	CEXASSERT(IntegerTools::Min(Input.size(), Output.size()) >= BLOCK_SIZE, "The data arrays are smaller than the the block-size!");

	Decrypt128(Input, 0, Output, 0);
}

void EAX::DecryptBlock(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");
	CEXASSERT(!IsEncryption(), "The cipher mode has been initialized for encryption!");
	CEXASSERT(IntegerTools::Min(Input.size() - InOffset, Output.size() - OutOffset) >= BLOCK_SIZE, "The data arrays are smaller than the the block-size!");

	Decrypt128(Input, InOffset, Output, OutOffset);
}

void EAX::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");
	CEXASSERT(IsEncryption(), "The cipher mode has been initialized for encryption!");
	CEXASSERT(IntegerTools::Min(Input.size(), Output.size()) >= BLOCK_SIZE, "The data arrays are smaller than the the block-size!");

	Encrypt128(Input, 0, Output, 0);
}

void EAX::EncryptBlock(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");
	CEXASSERT(IsEncryption(), "The cipher mode has been initialized for encryption!");
	CEXASSERT(IntegerTools::Min(Input.size() - InOffset, Output.size() - OutOffset) >= BLOCK_SIZE, "The data arrays are smaller than the the block-size!");

	Encrypt128(Input, InOffset, Output, OutOffset);
}

void EAX::Finalize(std::vector<byte> &Output, size_t OutOffset, size_t Length)
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
	MemoryTools::Copy(m_eaxState->Tag, 0, Output, OutOffset, Length);
}

void EAX::Finalize(SecureVector<byte> &Output, size_t OutOffset, size_t Length)
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
	MemoryTools::Copy(m_eaxState->Tag, 0, Output, OutOffset, Length);
}

void EAX::Initialize(bool Encryption, ISymmetricKey &Parameters)
{
	if (!SymmetricKeySize::Contains(LegalKeySizes(), Parameters.KeySizes().KeySize(), Parameters.KeySizes().NonceSize()))
	{
		throw CryptoCipherModeException(Name(), std::string("Initialize"), std::string("Invalid key size; the nonce must be 16 bytes, and the key must be one of the LegalKeySizes in length!"), ErrorCodes::InvalidKey);
	}

	if (m_parallelProfile.IsParallel())
	{
		if (m_parallelProfile.IsParallel() && m_parallelProfile.ParallelBlockSize() < m_parallelProfile.ParallelMinimumSize() || m_parallelProfile.ParallelBlockSize() > m_parallelProfile.ParallelMaximumSize())
		{
			throw CryptoCipherModeException(Name(), std::string("Initialize"), std::string("The parallel block size is out of bounds!"), ErrorCodes::InvalidSize);
		}
		if (m_parallelProfile.IsParallel() && m_parallelProfile.ParallelBlockSize() % m_parallelProfile.ParallelMinimumSize() != 0)
		{
			throw CryptoCipherModeException(Name(), std::string("Initialize"), std::string("The parallel block size must be evenly aligned to the ParallelMinimumSize!"), ErrorCodes::InvalidParam);
		}
	}

	// load the state
	m_eaxState->Encryption = Encryption;
	m_eaxState->Key.resize(Parameters.KeySizes().KeySize());
	// copy the key and nonce
	MemoryTools::Copy(Parameters.Key(), 0, m_eaxState->Key, 0, m_eaxState->Key.size());
	MemoryTools::Copy(Parameters.Nonce(), 0, m_eaxState->Buffer, 0, m_eaxState->Buffer.size());

	// initialize the MAC generator
	SymmetricKey mkp(m_eaxState->Key);
	m_macGenerator->Initialize(mkp);
	// update and finalize to the cipher nonce
	UpdateTag(0x00);
	m_macGenerator->Update(m_eaxState->Buffer, 0, m_eaxState->Buffer.size());
	m_macGenerator->Finalize(m_eaxState->Nonce, 0);
	// re-initialize the MAC
	m_macGenerator->Initialize(mkp);

	// initialize the CTR mode
	SymmetricKey ckp(m_eaxState->Key, m_eaxState->Nonce, Parameters.SecureInfo());
	m_cipherMode->Initialize(Encryption, ckp);
	m_cipherMode->ParallelProfile().Calculate(m_parallelProfile.IsParallel(), m_parallelProfile.ParallelBlockSize(), m_parallelProfile.ParallelMaxDegree());

	// if the state has been previously finalized, reset the tag
	if (!AutoIncrement())
	{
		MemoryTools::Clear(m_eaxState->Tag, 0, m_eaxState->Tag.size());
		m_eaxState->Tag.resize(0);
	}

	m_eaxState->Initialized = true;
}

void EAX::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0 || Degree % 2 != 0 || Degree > m_parallelProfile.ProcessorCount())
	{
		throw CryptoCipherModeException(Name(), std::string("ParallelMaxDegree"), std::string("Degree setting is invalid!"), ErrorCodes::InvalidParam);
	}

	m_parallelProfile.SetMaxDegree(Degree);
}

void EAX::SetAssociatedData(const std::vector<byte> &Input, size_t Offset, size_t Length)
{
	if (!IsInitialized())
	{
		throw CryptoCipherModeException(Name(), std::string("SetAssociatedData"), std::string("The cipher mode has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (m_eaxState->AAD.size() != 0)
	{
		throw CryptoCipherModeException(Name(), std::string("SetAssociatedData"), std::string("The associated data has already been set!"), ErrorCodes::IllegalOperation);
	}

	// size the AAD string
	m_eaxState->AAD.resize(m_macGenerator->TagSize());
	// update the tag and finalize to new AAD
	UpdateTag(0x01);
	m_macGenerator->Update(Input, Offset, Length);
	m_macGenerator->Finalize(m_eaxState->AAD, 0);
	// increment update counter
	m_macGenerator->Clear();
	UpdateTag(0x02);
}

void EAX::Transform(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");
	CEXASSERT(IntegerTools::Min(Input.size() - InOffset, Output.size() - OutOffset) >= Length, "The data arrays are smaller than the the block-size!");

	if (IsEncryption())
	{
		m_cipherMode->Transform(Input, InOffset, Output, OutOffset, Length);
		m_macGenerator->Update(Output, OutOffset, Length);
	}
	else
	{
		m_macGenerator->Update(Input, InOffset, Length);
		m_cipherMode->Transform(Input, InOffset, Output, OutOffset, Length);
	}
}

bool EAX::Verify(const std::vector<byte> &Input, size_t Offset, size_t Length)
{
	if (Length < MIN_TAGSIZE || Length > BLOCK_SIZE)
	{
		throw CryptoCipherModeException(Name(), std::string("Verify"), std::string("The length must be minimum of 12 and maximum of MAC code size!"), ErrorCodes::InvalidSize);
	}
	if (IsEncryption())
	{
		throw CryptoCipherModeException(Name(), std::string("Verify"), std::string("The mode has not been initialized for decryption!"), ErrorCodes::IllegalOperation);
	}
	if (!IsInitialized() && m_eaxState->Tag.size() == 0)
	{
		throw CryptoCipherModeException(Name(), std::string("Verify"), std::string("The cipher mode has not been initialized!"), ErrorCodes::NotInitialized);
	}

	if (m_eaxState->Tag.size() == 0)
	{
		Compute();
	}

	return IntegerTools::Compare(m_eaxState->Tag, 0, Input, Offset, Length);
}

bool EAX::Verify(const SecureVector<byte> &Input, size_t Offset, size_t Length)
{
	if (Length < MIN_TAGSIZE || Length > BLOCK_SIZE)
	{
		throw CryptoCipherModeException(Name(), std::string("Verify"), std::string("The length must be minimum of 12 and maximum of MAC code size!"), ErrorCodes::InvalidSize);
	}
	if (IsEncryption())
	{
		throw CryptoCipherModeException(Name(), std::string("Verify"), std::string("The mode has not been initialized for decryption!"), ErrorCodes::IllegalOperation);
	}
	if (!IsInitialized() && m_eaxState->Tag.size() == 0)
	{
		throw CryptoCipherModeException(Name(), std::string("Verify"), std::string("The cipher mode has not been initialized!"), ErrorCodes::NotInitialized);
	}

	if (m_eaxState->Tag.size() == 0)
	{
		Compute();
	}

	return IntegerTools::Compare(m_eaxState->Tag, 0, Input, Offset, Length);
}

//~~~Private Functions~~~//

void EAX::Compute()
{
	// finalize to the tag state-vector
	m_eaxState->Tag.resize(m_macGenerator->BlockSize());
	m_macGenerator->Finalize(m_eaxState->Tag, 0);
	m_eaxState->AAD.resize(BLOCK_SIZE);

	// update the tag with the nonce and AAD
	for (size_t i = 0; i < m_eaxState->Tag.size(); ++i)
	{
		m_eaxState->Tag[i] ^= static_cast<byte>(m_eaxState->Nonce[i] ^ m_eaxState->AAD[i]);
	}

	// reset the tag if we are not maintaining it
	if (!PreserveAD())
	{
		MemoryTools::Clear(m_eaxState->AAD, 0, m_eaxState->AAD.size());
		m_eaxState->AAD.resize(0);
	}

	// clear the MAC iv and reset the nonce
	m_macGenerator->Clear();
	MemoryTools::Clear(m_eaxState->Nonce, 0, m_eaxState->Nonce.size());
	m_eaxState->Initialized = false;

	// auto-increment the counter and re-initialize the mode
	if (AutoIncrement())
	{
		IntegerTools::BeIncrement8(m_eaxState->Buffer);
		SymmetricKey kp(m_eaxState->Key, SecureLock(m_eaxState->Buffer));
		Initialize(IsEncryption(), kp);

		if (PreserveAD())
		{
			UpdateTag(0x02);
		}
	}
}

void EAX::Decrypt128(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	m_macGenerator->Update(Input, InOffset, BLOCK_SIZE);
	m_cipherMode->EncryptBlock(Input, InOffset, Output, OutOffset);
}

void EAX::Encrypt128(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	m_cipherMode->EncryptBlock(Input, InOffset, Output, OutOffset);
	m_macGenerator->Update(Input, InOffset, BLOCK_SIZE);
}

void EAX::UpdateTag(byte Tag)
{
	std::vector<byte> tmpv(BLOCK_SIZE);
	tmpv[tmpv.size() - 1] = Tag;
	m_macGenerator->Update(tmpv, 0, tmpv.size());
}

NAMESPACE_MODEEND
