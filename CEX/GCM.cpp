#include "GCM.h"
#include "IntegerTools.h"
#include "SymmetricKey.h"

NAMESPACE_MODE

using Utility::IntegerTools;

const std::string GCM::CLASS_NAME("GCM");

//~~~Constructor~~~//

GCM::GCM(BlockCiphers CipherType)
	:
	m_aadData(0),
	m_aadLoaded(false),
	m_aadPreserve(false),
	m_aadSize(0),
	m_autoIncrement(false),
	m_checkSum(BLOCK_SIZE),
	m_cipherMode(CipherType != BlockCiphers::None ? new CTR(CipherType) :
		throw CryptoCipherModeException(CLASS_NAME, std::string("Constructor"), std::string("The block cipher type can nor be None!"), ErrorCodes::InvalidParam)),
	m_cipherType(CipherType),
	m_destroyEngine(true),
	m_gcmHash(new Mac::GHASH()),
	m_gcmKey(0),
	m_gcmNonce(0),
	m_gcmVector(0),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isFinalized(false),
	m_isInitialized(false),
	m_legalKeySizes(0),
	m_msgSize(0),
	m_msgTag(BLOCK_SIZE),
	m_parallelProfile(BLOCK_SIZE, m_cipherMode->ParallelProfile().IsParallel(), m_cipherMode->ParallelProfile().ParallelBlockSize(),
		m_cipherMode->ParallelProfile().ParallelMaxDegree(), true, m_cipherMode->Engine()->StateCacheSize(), true)
{
	Scope();
}

GCM::GCM(IBlockCipher* Cipher)
	:
	m_aadData(0),
	m_aadLoaded(false),
	m_aadPreserve(false),
	m_aadSize(0),
	m_autoIncrement(false),
	m_checkSum(BLOCK_SIZE),
	m_cipherMode(Cipher != nullptr ? new CTR(Cipher) :
		throw CryptoCipherModeException(CLASS_NAME, std::string("Constructor"), std::string("The block cipher can nor be null!"), ErrorCodes::IllegalOperation)),
	m_cipherType(Cipher->Enumeral()),
	m_destroyEngine(false),
	m_gcmHash(new Mac::GHASH()),
	m_gcmKey(0),
	m_gcmNonce(0),
	m_gcmVector(0),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isFinalized(false),
	m_isInitialized(false),
	m_legalKeySizes(0),
	m_msgSize(0),
	m_msgTag(BLOCK_SIZE),
	m_parallelProfile(BLOCK_SIZE, m_cipherMode->ParallelProfile().IsParallel(), m_cipherMode->ParallelProfile().ParallelBlockSize(),
		m_cipherMode->ParallelProfile().ParallelMaxDegree(), true, m_cipherMode->Engine()->StateCacheSize(), true)
{
	Scope();
}

GCM::~GCM()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_aadLoaded = false;
		m_aadPreserve = false;
		m_aadSize = 0;
		m_autoIncrement = false;
		m_cipherType = BlockCiphers::None;
		m_isEncryption = false;
		m_isFinalized = false;
		m_isInitialized = false;
		m_msgSize = 0;
		m_parallelProfile.Reset();

		IntegerTools::Clear(m_aadData);
		IntegerTools::Clear(m_gcmKey);
		IntegerTools::Clear(m_gcmNonce);
		IntegerTools::Clear(m_gcmVector);
		IntegerTools::Clear(m_legalKeySizes);
		IntegerTools::Clear(m_msgTag);
		IntegerTools::Clear(m_checkSum);

		if (m_gcmHash)
		{
			m_gcmHash->Reset();
			m_gcmHash.reset(nullptr);
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

bool &GCM::AutoIncrement()
{
	return m_autoIncrement;
}

const size_t GCM::BlockSize()
{
	return BLOCK_SIZE;
}

const BlockCiphers GCM::CipherType()
{
	return m_cipherType;
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
	return m_isEncryption;
}

const bool GCM::IsInitialized()
{
	return m_isInitialized;
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
	return CLASS_NAME + "-" + m_cipherMode->Engine()->Name();
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
	return m_aadPreserve;
}

const std::vector<byte> GCM::Tag()
{
	CEXASSERT(m_isFinalized, "The cipher mode has not been finalized");

	return m_msgTag;
}

//~~~Public Functions~~~//

void GCM::DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Decrypt128(Input, 0, Output, 0);
}

void GCM::DecryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	Decrypt128(Input, InOffset, Output, OutOffset);
}

void GCM::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Encrypt128(Input, 0, Output, 0);
}

void GCM::EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	Encrypt128(Input, InOffset, Output, OutOffset);
}

void GCM::Finalize(std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	CEXASSERT(m_isInitialized, "The cipher mode has not been initialized");
	CEXASSERT(Length >= MIN_TAGSIZE || Length <= BLOCK_SIZE, "The cipher mode has not been initialized");

	CalculateMac();
	Utility::MemoryTools::Copy(m_msgTag, 0, Output, OutOffset, Length);
}

void GCM::Initialize(bool Encryption, ISymmetricKey &KeyParams)
{
	Reset();

	if (KeyParams.Nonce().size() < 8)
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

	if (KeyParams.Key().size() == 0)
	{
		if (KeyParams.Nonce() == m_gcmNonce)
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
		if (!SymmetricKeySize::Contains(LegalKeySizes(), KeyParams.Key().size()))
		{
			throw CryptoCipherModeException(Name(), std::string("Initialize"), std::string("Invalid key size; key must be one of the LegalKeySizes in length!"), ErrorCodes::InvalidKey);
		}

		// key the cipher and generate the hash key
		m_cipherMode->Engine()->Initialize(true, KeyParams);
		std::vector<byte> tmpH(BLOCK_SIZE);
		const std::vector<byte> ZEROES(BLOCK_SIZE);
		m_cipherMode->Engine()->Transform(ZEROES, 0, tmpH, 0);

		std::vector<ulong> gKey = 
		{
			IntegerTools::BeBytesTo64(tmpH, 0),
			IntegerTools::BeBytesTo64(tmpH, 8)
		};

		m_gcmHash->Initialize(gKey);
		m_gcmKey = KeyParams.Key();
	}

	m_isEncryption = Encryption;
	m_gcmNonce = KeyParams.Nonce();
	m_gcmVector = m_gcmNonce;

	if (m_gcmVector.size() == 12)
	{
		m_gcmVector.resize(16);
		m_gcmVector[15] = 1;
	}
	else
	{
		std::vector<byte> tmpN(BLOCK_SIZE);
		m_gcmHash->ProcessSegment(m_gcmVector, 0, tmpN, m_gcmVector.size());
		m_gcmHash->FinalizeBlock(tmpN, 0, m_gcmVector.size());
		m_gcmVector = tmpN;
	}

	m_cipherMode->Initialize(true, Cipher::SymmetricKey(m_gcmKey, m_gcmVector));
	std::vector<byte> tmpN(BLOCK_SIZE);
	m_cipherMode->Transform(tmpN, 0, m_gcmVector, 0, BLOCK_SIZE);

	if (m_isFinalized)
	{
		Utility::MemoryTools::Clear(m_msgTag, 0, m_msgTag.size());
		m_isFinalized = false;
	}

	m_isInitialized = true;
}

void GCM::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0 || Degree % 2 != 0 || Degree > m_parallelProfile.ProcessorCount())
	{
		throw CryptoCipherModeException(Name(), std::string("ParallelMaxDegree"), std::string("Degree setting is invalid!"), ErrorCodes::NotSupported);
	}

	m_parallelProfile.SetMaxDegree(Degree);
}

void GCM::SetAssociatedData(const std::vector<byte> &Input, const size_t Offset, const size_t Length)
{
	if (!m_isInitialized)
	{
		throw CryptoCipherModeException(Name(), std::string("SetAssociatedData"), std::string("The cipher mode has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (m_aadLoaded)
	{
		throw CryptoCipherModeException(Name(), std::string("SetAssociatedData"), std::string("The associated data has already been set!"), ErrorCodes::IllegalOperation);
	}

	m_aadData.resize(Length);
	Utility::MemoryTools::Copy(Input, Offset, m_aadData, 0, Length);
	m_gcmHash->ProcessSegment(Input, Offset, m_checkSum, Length);

	m_aadSize = Length;
	m_aadLoaded = true;
}

void GCM::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	CEXASSERT(m_isInitialized, "The cipher mode has not been initialized!");
	CEXASSERT(IntegerTools::Min(Input.size() - InOffset, Output.size() - OutOffset) >= Length, "The data arrays are smaller than the the block-size!");

	if (m_isEncryption)
	{
		m_cipherMode->Transform(Input, InOffset, Output, OutOffset, Length);
		m_gcmHash->Update(Output, OutOffset, m_checkSum, Length);
	}
	else
	{
		m_gcmHash->Update(Input, InOffset, m_checkSum, Length);
		m_cipherMode->Transform(Input, InOffset, Output, OutOffset, Length);
	}

	m_msgSize += Length;
}

bool GCM::Verify(const std::vector<byte> &Input, const size_t Offset, const size_t Length)
{
	CEXASSERT(Length >= MIN_TAGSIZE || Length <= BLOCK_SIZE, "The length must be minimum of 12 and maximum of MAC code size");

	if (m_isEncryption)
	{
		throw CryptoCipherModeException(Name(), std::string("SetAssociatedData"), std::string("The cipher mode has not been initialized for decryption!"), ErrorCodes::NotInitialized);
	}
	if (!m_isInitialized && !m_isFinalized)
	{
		throw CryptoCipherModeException(Name(), std::string("SetAssociatedData"), std::string("The cipher mode has not been initialized for decryption!"), ErrorCodes::NotInitialized);
	}

	if (!m_isFinalized)
	{
		CalculateMac();
	}

	return IntegerTools::Compare(m_msgTag, 0, Input, Offset, Length);
}

//~~~Private Functions~~~//

void GCM::CalculateMac()
{
	m_gcmHash->FinalizeBlock(m_checkSum, m_aadSize, m_msgSize);
	Utility::MemoryTools::XOR(m_gcmVector, 0, m_checkSum, 0, BLOCK_SIZE);
	Utility::MemoryTools::COPY128(m_checkSum, 0, m_msgTag, 0);
	Reset();

	if (m_autoIncrement)
	{
		std::vector<byte> tmpN = m_gcmNonce;
		IntegerTools::BeIncrement8(tmpN);
		std::vector<byte> zero(0);
		Initialize(m_isEncryption, Cipher::SymmetricKey(zero, tmpN));

		if (m_aadPreserve)
		{
			m_gcmHash->ProcessSegment(m_aadData, 0, m_checkSum, m_aadData.size());
		}
	}

	m_isFinalized = true;
}

void GCM::Decrypt128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	CEXASSERT(m_isInitialized, "The cipher mode has not been initialized!");
	CEXASSERT(IntegerTools::Min(Input.size() - InOffset, Output.size() - OutOffset) >= BLOCK_SIZE, "The data arrays are smaller than the the block-size!");

	m_gcmHash->Update(Input, InOffset, m_checkSum, BLOCK_SIZE);
	m_cipherMode->EncryptBlock(Input, InOffset, Output, OutOffset);
	m_msgSize += BLOCK_SIZE;
}

void GCM::Encrypt128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	CEXASSERT(m_isInitialized, "The cipher mode has not been initialized!");
	CEXASSERT(IntegerTools::Min(Input.size() - InOffset, Output.size() - OutOffset) >= BLOCK_SIZE, "The data arrays are smaller than the the block-size!");

	m_cipherMode->EncryptBlock(Input, InOffset, Output, OutOffset);
	m_gcmHash->Update(Input, InOffset, m_checkSum, BLOCK_SIZE);
	m_msgSize += BLOCK_SIZE;
}

void GCM::Reset()
{
	if (!m_aadPreserve)
	{
		if (m_aadSize != 0)
		{
			Utility::MemoryTools::Clear(m_aadData, 0, m_aadData.size());
		}

		m_aadLoaded = false;
		m_aadSize = 0;
	}

	m_cipherMode->ParallelProfile().Calculate(m_parallelProfile.IsParallel(), m_parallelProfile.ParallelBlockSize(), m_parallelProfile.ParallelMaxDegree());
	m_gcmHash->Reset();
	m_isInitialized = false;
	Utility::MemoryTools::Clear(m_gcmVector, 0, m_gcmVector.size());
	Utility::MemoryTools::Clear(m_checkSum, 0, m_checkSum.size());
	m_msgSize = 0;
}

void GCM::Scope()
{
	std::vector<SymmetricKeySize> keySizes = m_cipherMode->LegalKeySizes();
	m_legalKeySizes.resize(keySizes.size());

	for (size_t i = 0; i < m_legalKeySizes.size(); i++)
	{	
		m_legalKeySizes[i] = SymmetricKeySize(keySizes[i].KeySize(), keySizes[i].NonceSize(), keySizes[i].NonceSize());
	}
}

NAMESPACE_MODEEND
