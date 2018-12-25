#include "EAX.h"
#include "IntUtils.h"
#include "ParallelUtils.h"
#include "SymmetricKey.h"

NAMESPACE_MODE

const std::string EAX::CLASS_NAME("EAX");

//~~~Constructor~~~//

EAX::EAX(BlockCiphers CipherType, BlockCipherExtensions CipherExtensionType)
	:
	m_cipherMode(CipherType != BlockCiphers::None ? new CTR(CipherType, CipherExtensionType) :
		throw CryptoCipherModeException("EAX:CTor", "The Cipher type can not be none!")),
	m_aadData(m_cipherMode->BlockSize()),
	m_aadLoaded(false),
	m_aadPreserve(false),
	m_autoIncrement(false),
	m_blockSize(m_cipherMode->BlockSize()),
	m_cipherKey(0),
	m_cipherType(CipherType),
	m_destroyEngine(true),
	m_eaxNonce(0),
	m_eaxVector(m_blockSize),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isFinalized(false),
	m_isInitialized(false),
	m_isLoaded(false),
	m_legalKeySizes(0),
	m_macGenerator(new Mac::CMAC(m_cipherMode->Engine())),
	m_macSize(m_blockSize),
	m_msgTag(m_blockSize),
	m_parallelProfile(m_blockSize, m_cipherMode->ParallelProfile().IsParallel(), m_cipherMode->ParallelProfile().ParallelBlockSize(),
		m_cipherMode->ParallelProfile().ParallelMaxDegree(), true, m_cipherMode->Engine()->StateCacheSize(), true)
{
	Scope();
}

EAX::EAX(IBlockCipher* Cipher)
	:
	m_cipherMode(Cipher != nullptr ? new CTR(Cipher) :
		throw CryptoCipherModeException("EAX:CTor", "The Cipher can not be null!")),
	m_aadData(m_cipherMode->BlockSize()),
	m_aadLoaded(false),
	m_aadPreserve(false),
	m_autoIncrement(false),
	m_blockSize(m_cipherMode->BlockSize()),
	m_cipherKey(0),
	m_cipherType(Cipher->Enumeral()),
	m_destroyEngine(false),
	m_eaxNonce(0),
	m_eaxVector(m_blockSize),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isFinalized(false),
	m_isInitialized(false),
	m_isLoaded(false),
	m_legalKeySizes(0),
	m_macGenerator(new Mac::CMAC(Cipher)),
	m_macSize(m_blockSize),
	m_msgTag(m_blockSize),
	m_parallelProfile(m_blockSize, m_cipherMode->ParallelProfile().IsParallel(), m_cipherMode->ParallelProfile().ParallelBlockSize(),
		m_cipherMode->ParallelProfile().ParallelMaxDegree(), true, m_cipherMode->Engine()->StateCacheSize(), true)
{
	Scope();
}

EAX::~EAX()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_aadLoaded = false;
		m_aadPreserve = false;
		m_autoIncrement = false;
		m_blockSize = 0;
		m_cipherType = BlockCiphers::None;
		m_isEncryption = false;
		m_isFinalized = false;
		m_isInitialized = false;
		m_isLoaded = false;
		m_macSize = 0;
		m_parallelProfile.Reset();

		Utility::IntUtils::ClearVector(m_aadData);
		Utility::IntUtils::ClearVector(m_cipherKey);
		Utility::IntUtils::ClearVector(m_eaxNonce);
		Utility::IntUtils::ClearVector(m_eaxVector);
		Utility::IntUtils::ClearVector(m_legalKeySizes);
		Utility::IntUtils::ClearVector(m_msgTag);

		if (m_macGenerator != nullptr)
		{
			m_macGenerator.reset(nullptr);
		}

		if (m_destroyEngine)
		{
			m_destroyEngine = false;

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
}

//~~~Accessors~~~//

bool &EAX::AutoIncrement() 
{
	return m_autoIncrement; 
}

const size_t EAX::BlockSize()
{ 
	return m_blockSize; 
}

const BlockCiphers EAX::CipherType() 
{ 
	return m_cipherType;
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
	return m_isEncryption; 
}

const bool EAX::IsInitialized() 
{ 
	return m_isInitialized; 
}

const bool EAX::IsParallel() 
{
	return m_parallelProfile.IsParallel();
}

const std::vector<SymmetricKeySize> &EAX::LegalKeySizes()
{
	return m_legalKeySizes;
}

const size_t EAX::MaxTagSize() 
{ 
	return m_macSize;
}

const size_t EAX::MinTagSize()
{
	return MIN_TAGSIZE; 
}

const std::string EAX::Name()
{ 
	return CLASS_NAME + "-" + m_cipherMode->Engine()->Name();
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
	return m_aadPreserve; 
}

const std::vector<byte> EAX::Tag()
{
	CexAssert(m_isFinalized, "The cipher mode has not been finalized");

	return m_msgTag;
}

//~~~Public Functions~~~//

void EAX::DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Decrypt128(Input, 0, Output, 0);
}

void EAX::DecryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	Decrypt128(Input, InOffset, Output, OutOffset);
}

void EAX::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Encrypt128(Input, 0, Output, 0);
}

void EAX::EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	Encrypt128(Input, InOffset, Output, OutOffset);
}

void EAX::Finalize(std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	CexAssert(m_isInitialized, "The cipher mode has not been initialized");
	CexAssert(Length >= MIN_TAGSIZE || Length <= BLOCK_SIZE, "The cipher mode has not been initialized");

	CalculateMac();
	Utility::MemUtils::Copy(m_msgTag, 0, Output, OutOffset, Length);
}

void EAX::Initialize(bool Encryption, ISymmetricKey &KeyParams)
{
	// recheck params
	Reset();

	if (KeyParams.Key().size() == 0)
	{
		if (KeyParams.Nonce() == m_eaxVector)
		{
			throw CryptoSymmetricCipherException("EAX:Initialize", "The nonce can not be zeroised or repeating!");
		}
		if (!m_cipherMode->IsInitialized())
		{
			throw CryptoSymmetricCipherException("EAX:Initialize", "First initialization requires a key and nonce!");
		}
	}
	else
	{
		if (!SymmetricKeySize::Contains(LegalKeySizes(), KeyParams.Key().size()))
		{
			throw CryptoSymmetricCipherException("EAX:Initialize", "Invalid key size! Key must be one of the LegalKeySizes() in length.");
		}

		// TODO: change to secure key and review
		m_cipherKey = KeyParams.Key();
	}

	if (KeyParams.Nonce().size() != m_cipherMode->BlockSize())
	{
		throw CryptoSymmetricCipherException("EAX:Initialize", "Requires a nonce equal in size to the ciphers block size!");
	}
	if (m_parallelProfile.IsParallel() && m_parallelProfile.ParallelBlockSize() < m_parallelProfile.ParallelMinimumSize() || m_parallelProfile.ParallelBlockSize() > m_parallelProfile.ParallelMaximumSize())
	{
		throw CryptoSymmetricCipherException("EAX:Initialize", "The parallel block size is out of bounds!");
	}
	if (m_parallelProfile.IsParallel() && m_parallelProfile.ParallelBlockSize() % m_parallelProfile.ParallelMinimumSize() != 0)
	{
		throw CryptoSymmetricCipherException("EAX:Initialize", "The parallel block size must be evenly aligned to the ParallelMinimumSize!");
	}

	// 
	m_isEncryption = Encryption;
	m_eaxNonce = KeyParams.Nonce();
	Key::Symmetric::SymmetricKey kp(m_cipherKey);
	m_macGenerator->Initialize(kp);

	UpdateTag(0, m_eaxNonce);
	m_macGenerator->Finalize(m_eaxVector, 0);
	m_macGenerator->Initialize(kp);
	m_cipherMode->Initialize(Encryption, Key::Symmetric::SymmetricKey(m_cipherKey, m_eaxVector, KeyParams.Info()));

	if (m_isFinalized)
	{
		Utility::MemUtils::Clear(m_msgTag, 0, m_msgTag.size());
		m_isFinalized = false;
	}

	m_isInitialized = true;
}

void EAX::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0 || Degree % 2 != 0 || Degree > m_parallelProfile.ProcessorCount())
	{
		throw CryptoSymmetricCipherException("EAX:ParallelMaxDegree", "Degree setting is invalid!");
	}

	m_parallelProfile.SetMaxDegree(Degree);
}

void EAX::SetAssociatedData(const std::vector<byte> &Input, const size_t Offset, const size_t Length)
{
	if (!m_isInitialized)
	{
		throw CryptoSymmetricCipherException("EAX:SetAssociatedData", "The cipher mode has not been initialized!");
	}
	if (m_aadLoaded)
	{
		throw CryptoSymmetricCipherException("EAX:SetAssociatedData", "The associated data has already been set!");
	}

	UpdateTag(1, std::vector<byte>(0));
	m_macGenerator->Update(Input, Offset, Length);
	m_macGenerator->Finalize(m_aadData, 0);
	UpdateTag(2, std::vector<byte>(0));
	m_aadLoaded = true;
}

void EAX::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	CexAssert(m_isInitialized, "The cipher mode has not been initialized!");
	CexAssert(Utility::IntUtils::Min(Input.size() - InOffset, Output.size() - OutOffset) >= Length, "The data arrays are smaller than the the block-size!");

	if (m_isEncryption)
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

bool EAX::Verify(const std::vector<byte> &Input, const size_t Offset, const size_t Length)
{
	CexAssert(!m_isEncryption, "the cipher mode has not been initialized for decryption");
	CexAssert(Length >= MIN_TAGSIZE || Length <= m_macSize, "the length must be minimum of 12 and maximum of MAC code size");
	CexAssert(!(!m_isInitialized && !m_isFinalized), "the cipher mode has not been initialized for decryption");

	if (!m_isFinalized)
	{
		CalculateMac();
	}

	return Utility::IntUtils::Compare(m_msgTag, 0, Input, Offset, Length);
}

//~~~Private Functions~~~//

void EAX::CalculateMac()
{
	m_macGenerator->Finalize(m_msgTag, 0);

	for (size_t i = 0; i < m_msgTag.size(); ++i)
	{
		m_msgTag[i] ^= static_cast<byte>(m_eaxVector[i] ^ m_aadData[i]);
	}

	Reset();

	if (m_autoIncrement)
	{
		Utility::IntUtils::BeIncrement8(m_eaxNonce);
		std::vector<byte> zero(0);
		Initialize(m_isEncryption, Key::Symmetric::SymmetricKey(zero, m_eaxNonce));

		if (m_aadPreserve)
		{
			UpdateTag(2, std::vector<byte>(0));
		}
	}

	m_isFinalized = true;
}

void EAX::Decrypt128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	CexAssert(m_isInitialized, "The cipher mode has not been initialized!");

	m_macGenerator->Update(Input, InOffset, m_blockSize);
	m_cipherMode->EncryptBlock(Input, InOffset, Output, OutOffset);
}

void EAX::Encrypt128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	CexAssert(m_isInitialized, "The cipher mode has not been initialized!");
	CexAssert(Utility::IntUtils::Min(Input.size() - InOffset, Output.size() - OutOffset) >= BLOCK_SIZE, "The data arrays are smaller than the the block-size!");

	m_cipherMode->EncryptBlock(Input, InOffset, Output, OutOffset);
	m_macGenerator->Update(Input, InOffset, m_blockSize);
}

void EAX::Reset()
{
	if (!m_aadPreserve)
	{
		m_aadLoaded = false;
		Utility::MemUtils::Clear(m_aadData, 0, m_aadData.size());
	}

	m_cipherMode->ParallelProfile().Calculate(m_parallelProfile.IsParallel(), m_parallelProfile.ParallelBlockSize(), m_parallelProfile.ParallelMaxDegree());
	m_isInitialized = false;
	m_macGenerator->Reset();
	Utility::MemUtils::Clear(m_eaxVector, 0, m_eaxVector.size());
}

void EAX::Scope()
{
	std::vector<SymmetricKeySize> keySizes = m_cipherMode->LegalKeySizes();
	m_legalKeySizes.resize(keySizes.size());

	for (size_t i = 0; i < m_legalKeySizes.size(); i++)
	{
		m_legalKeySizes[i] = SymmetricKeySize(keySizes[i].KeySize(), keySizes[i].NonceSize(), keySizes[i].NonceSize());
	}
}

void EAX::UpdateTag(byte Tag, const std::vector<byte> &Nonce)
{
	std::vector<byte> tmp(m_macSize);
	tmp[tmp.size() - 1] = Tag;
	m_macGenerator->Update(tmp, 0, tmp.size());

	if (Nonce.size() != 0)
	{
		m_macGenerator->Update(Nonce, 0, Nonce.size());
	}
}

NAMESPACE_MODEEND
