#include "EAX.h"
#include "ArrayUtils.h"
#include "CMAC.h"
#include "IntUtils.h"
#include "ParallelUtils.h"
#include "SymmetricKey.h"

NAMESPACE_MODE

using Utility::ArrayUtils;
using Utility::IntUtils;

//~~~Constructor~~~//

EAX::EAX(BlockCiphers CipherType)
	:
	m_cipherMode(CipherType),
	m_aadData(m_cipherMode.BlockSize()),
	m_aadLoaded(false),
	m_aadPreserve(false),
	m_blockSize(m_cipherMode.BlockSize()),
	m_cipherKey(0),
	m_cipherType(CipherType),
	m_destroyEngine(true),
	m_eaxNonce(0),
	m_eaxVector(m_blockSize),
	m_isFinalized(false),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_isLoaded(false),
	m_legalKeySizes(0),
	m_macGenerator(m_cipherMode.Engine()),
	m_macSize(m_blockSize),
	m_msgTag(m_blockSize),
	m_parallelProfile(m_blockSize, m_cipherMode.ParallelProfile().IsParallel(), m_cipherMode.ParallelProfile().ParallelBlockSize(), 
		m_cipherMode.ParallelProfile().ParallelMaxDegree(), true, m_cipherMode.Engine()->StateCacheSize(), true)
{
	Scope();
}

EAX::EAX(IBlockCipher* Cipher)
	:
	m_cipherMode(Cipher != 0 ? Cipher : throw CryptoCipherModeException("EAX:CTor", "The Cipher can not be null!")),
	m_aadData(m_cipherMode.BlockSize()),
	m_aadLoaded(false),
	m_aadPreserve(false),
	m_blockSize(m_cipherMode.BlockSize()),
	m_cipherKey(0),
	m_cipherType(Cipher->Enumeral()),
	m_destroyEngine(false),
	m_eaxNonce(0),
	m_eaxVector(m_blockSize),
	m_isFinalized(false),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_isLoaded(false),
	m_legalKeySizes(0),
	m_macGenerator(Cipher),
	m_macSize(m_blockSize),
	m_msgTag(m_blockSize),
	m_parallelProfile(m_blockSize, m_cipherMode.ParallelProfile().IsParallel(), m_cipherMode.ParallelProfile().ParallelBlockSize(),
		m_cipherMode.ParallelProfile().ParallelMaxDegree(), true, m_cipherMode.Engine()->StateCacheSize(), true)
{
	Scope();
}

EAX::~EAX()
{
	Destroy();
}

//~~~Public Functions~~~//

void EAX::DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	DecryptBlock(Input, 0, Output, 0);
}

void EAX::DecryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	CEXASSERT(m_isInitialized, "The cipher mode has not been initialized!");

	m_macGenerator.Update(Input, InOffset, m_blockSize);
	m_cipherMode.EncryptBlock(Input, InOffset, Output, OutOffset);
}

void EAX::Destroy()
{
	m_isDestroyed = true;
	m_aadPreserve = false;
	m_blockSize = 0;
	m_cipherType = BlockCiphers::None;
	m_aadLoaded = false;
	m_isEncryption = false;
	m_isInitialized = false;
	m_isLoaded = false;
	m_macSize = 0;
	m_parallelProfile.Reset();

	try
	{
		ArrayUtils::ClearVector(m_aadData);
		ArrayUtils::ClearVector(m_cipherKey);
		ArrayUtils::ClearVector(m_eaxNonce);
		ArrayUtils::ClearVector(m_eaxVector);
		ArrayUtils::ClearVector(m_msgTag);

		if (m_destroyEngine)
		{
			m_destroyEngine = false;

			if (m_cipherMode.IsInitialized())
				m_cipherMode.Destroy();
			if (m_macGenerator.IsInitialized())
				m_macGenerator.Destroy();
		}
	}
	catch (std::exception& ex)
	{
		throw CryptoCipherModeException("EAX:Destroy", "Could not clear all variables!", std::string(ex.what()));
	}
}

void EAX::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	EncryptBlock(Input, 0, Output, 0);
}

void EAX::EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	CEXASSERT(m_isInitialized, "The cipher mode has not been initialized!");
	CEXASSERT(IntUtils::Min(Input.size() - InOffset, Output.size() - OutOffset) >= BLOCK_SIZE, "The data arrays are smaller than the the block-size!");

	m_cipherMode.EncryptBlock(Input, InOffset, Output, OutOffset);
	m_macGenerator.Update(Input, InOffset, m_blockSize);
}

void EAX::Finalize(std::vector<byte> &Output, const size_t Offset, const size_t Length)
{
	if (!m_isInitialized)
		throw CryptoCipherModeException("EAX:Finalize", "The cipher mode has not been initialized!");
	if (Length < TAG_MINLEN || Length > m_macSize)
		throw CryptoCipherModeException("EAX:Finalize", "The length must be minimum of 12 and maximum of MAC code size!");

	CalculateMac();
	memcpy(&Output[Offset], &m_msgTag[0], Length);
}

void EAX::Initialize(bool Encryption, ISymmetricKey &KeyParams)
{
	// recheck params
	Scope();

	if (KeyParams.Key().size() == 0)
	{
		if (KeyParams.Nonce() == m_eaxVector)
			throw CryptoSymmetricCipherException("EAX:Initialize", "The nonce can not be zeroised or repeating!");
		if (!m_cipherMode.IsInitialized())
			throw CryptoSymmetricCipherException("EAX:Initialize", "First initialization requires a key and nonce!");
	}
	else
	{
		if (!SymmetricKeySize::Contains(LegalKeySizes(), KeyParams.Key().size()))
			throw CryptoSymmetricCipherException("EAX:Initialize", "Invalid key size! Key must be one of the LegalKeySizes() in length.");

		m_cipherKey = KeyParams.Key();
	}

	if (KeyParams.Nonce().size() != m_cipherMode.BlockSize())
		throw CryptoSymmetricCipherException("EAX:Initialize", "Requires a nonce equal in size to the ciphers block size!");
	if (m_parallelProfile.IsParallel() && m_parallelProfile.ParallelBlockSize() < m_parallelProfile.ParallelMinimumSize() || m_parallelProfile.ParallelBlockSize() > m_parallelProfile.ParallelMaximumSize())
		throw CryptoSymmetricCipherException("EAX:Initialize", "The parallel block size is out of bounds!");
	if (m_parallelProfile.IsParallel() && m_parallelProfile.ParallelBlockSize() % m_parallelProfile.ParallelMinimumSize() != 0)
		throw CryptoSymmetricCipherException("EAX:Initialize", "The parallel block size must be evenly aligned to the ParallelMinimumSize!");

	m_isEncryption = Encryption;
	m_eaxNonce = KeyParams.Nonce();
	Key::Symmetric::SymmetricKey kp(m_cipherKey);
	m_macGenerator.Initialize(kp);
	UpdateTag((byte)0, m_eaxNonce);
	m_macGenerator.Finalize(m_eaxVector, 0);
	m_macGenerator.Initialize(kp);

	// hx extended ciphers
	if (KeyParams.Info().size() != 0 && m_cipherMode.Engine()->KdfEngine() != Digests::None)
		m_cipherMode.Initialize(Encryption, Key::Symmetric::SymmetricKey(m_cipherKey, m_eaxVector, KeyParams.Info()));
	else
		m_cipherMode.Initialize(Encryption, Key::Symmetric::SymmetricKey(m_cipherKey, m_eaxVector));

	if (m_isFinalized)
	{
		memset(&m_msgTag[0], (byte)0, m_msgTag.size());
		m_isFinalized = false;
	}

	m_isInitialized = true;
}

void EAX::SetAssociatedData(const std::vector<byte> &Input, const size_t Offset, const size_t Length)
{
	if (!m_isInitialized)
		throw CryptoSymmetricCipherException("EAX:SetAssociatedData", "The cipher has not been initialized!");
	if (m_aadLoaded)
		throw CryptoSymmetricCipherException("EAX:SetAssociatedData", "The associated data has already been set!");

	UpdateTag((byte)1, std::vector<byte>(0));
	m_macGenerator.Update(Input, Offset, Length);
	m_macGenerator.Finalize(m_aadData, 0);
	UpdateTag((byte)2, std::vector<byte>(0));
	m_aadLoaded = true;
}

size_t EAX::Transform(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	const size_t PRCSZE = IntUtils::Min(Output.size(), Input.size());
	Transform(Input, 0, Output, 0, PRCSZE);
	return PRCSZE;
}

size_t EAX::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	if (m_parallelProfile.IsParallel() && (IntUtils::Min(Input.size() - InOffset, Output.size() - OutOffset) >= m_parallelProfile.ParallelBlockSize()))
	{
		Transform(Input, InOffset, Output, OutOffset, m_parallelProfile.ParallelBlockSize());
		return m_parallelProfile.ParallelBlockSize();
	}
	else
	{
		if (m_isEncryption)
			EncryptBlock(Input, InOffset, Output, OutOffset);
		else
			DecryptBlock(Input, InOffset, Output, OutOffset);

		return BLOCK_SIZE;
	}
}

void EAX::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	CEXASSERT(m_isInitialized, "The cipher mode has not been initialized!");
	CEXASSERT(IntUtils::Min(Input.size() - InOffset, Output.size() - OutOffset) >= Length, "The data arrays are smaller than the the block-size!");

	if (m_isEncryption)
	{
		m_cipherMode.Transform(Input, InOffset, Output, OutOffset, Length);
		m_macGenerator.Update(Output, OutOffset, Length);
	}
	else
	{
		m_macGenerator.Update(Input, InOffset, Length);
		m_cipherMode.Transform(Input, InOffset, Output, OutOffset, Length);
	}
}

bool EAX::Verify(const std::vector<byte> &Input, const size_t Offset, const size_t Length)
{
	if (m_isEncryption)
		throw CryptoCipherModeException("EAX:Verify", "The cipher mode has not been initialized for decryption!");
	if (!m_isInitialized && !m_isFinalized)
		throw CryptoCipherModeException("EAX:Verify", "The cipher mode has not been initialized!");
	if (Length < TAG_MINLEN || Length > m_macSize)
		throw CryptoCipherModeException("EAX:Verify", "The length must be minimum of 12 and maximum of MAC code size!");

	if (!m_isFinalized)
		CalculateMac();

	return ArrayUtils::Compare(m_msgTag, 0, Input, Offset, Length);
}

//~~~Private Functions~~~//

void EAX::CalculateMac()
{
	m_macGenerator.Finalize(m_msgTag, 0);

	for (size_t i = 0; i < m_msgTag.size(); ++i)
		m_msgTag[i] ^= (byte)(m_eaxVector[i] ^ m_aadData[i]);

	Reset();

	if (m_autoIncrement)
	{
		ArrayUtils::IncrementBE8(m_eaxNonce);
		std::vector<byte> zero(0);
		Initialize(m_isEncryption, Key::Symmetric::SymmetricKey(zero, m_eaxNonce));

		if (m_aadPreserve)
			UpdateTag((byte)2, std::vector<byte>(0));
	}

	m_isFinalized = true;
}

void EAX::Reset()
{
	if (!m_aadPreserve)
	{
		m_aadLoaded = false;
		memset(&m_aadData[0], (byte)0, m_aadData.size());
	}

	m_isInitialized = false;
	m_macGenerator.Reset();
	memset(&m_eaxVector[0], (byte)0, m_eaxVector.size());
}

void EAX::Scope()
{
	if (m_legalKeySizes.size() == 0)
		m_legalKeySizes = m_cipherMode.LegalKeySizes();

	if (!m_cipherMode.ParallelProfile().IsDefault())
		m_cipherMode.ParallelProfile().Calculate(m_parallelProfile.IsParallel(), m_cipherMode.ParallelProfile().ParallelBlockSize(), m_cipherMode.ParallelProfile().ParallelMaxDegree());
}

void EAX::UpdateTag(byte Tag, const std::vector<byte> &Nonce)
{
	std::vector<byte> tmp(m_macSize);
	tmp[tmp.size() - 1] = Tag;
	m_macGenerator.Update(tmp, 0, tmp.size());

	if (Nonce.size() != 0)
		m_macGenerator.Update(Nonce, 0, Nonce.size());
}

NAMESPACE_MODEEND