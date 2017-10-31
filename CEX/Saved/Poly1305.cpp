#include "Poly1305.h"
#include "CMAC.h"
#include "IntUtils.h"
#include "MemUtils.h"
#include "ParallelUtils.h"
#include "SymmetricKey.h"

NAMESPACE_MODE

const std::string Poly1305::CLASS_NAME("Poly1305");

//~~~Properties~~~//

bool &Poly1305::AutoIncrement()
{
	return m_autoIncrement;
}

const size_t Poly1305::BlockSize()
{
	return m_blockSize;
}

const BlockCiphers Poly1305::CipherType()
{
	return m_cipherType;
}

IBlockCipher* Poly1305::Engine()
{
	return m_strmCipher;
}

const CipherModes Poly1305::Enumeral()
{
	return CipherModes::Poly1305;
}

const bool Poly1305::IsEncryption()
{
	return m_isEncryption;
}

const bool Poly1305::IsInitialized()
{
	return m_isInitialized;
}

const bool Poly1305::IsParallel()
{
	return m_parallelProfile.IsParallel();
}

const std::vector<SymmetricKeySize> &Poly1305::LegalKeySizes()
{
	return m_legalKeySizes;
}

const size_t Poly1305::MaxTagSize()
{
	return m_macSize;
}

const size_t Poly1305::MinTagSize()
{
	return MIN_TAGSIZE;
}

const std::string Poly1305::Name()
{
	return CLASS_NAME + "-" + m_cipherMode.Engine()->Name();
}

const size_t Poly1305::ParallelBlockSize()
{
	return m_parallelProfile.ParallelBlockSize();
}

ParallelOptions &Poly1305::ParallelProfile()
{
	return m_cipherMode.ParallelProfile();
}

bool &Poly1305::PreserveAD()
{
	return m_aadPreserve;
}

const std::vector<byte> Poly1305::Tag()
{
	if (!m_isFinalized)
		throw CryptoCipherModeException("Poly1305:Tag", "The cipher mode has not been finalized!");

	return m_msgTag;
}

//~~~Constructor~~~//

Poly1305::Poly1305(BlockCiphers CipherType)
	:
	m_aadLoaded(false)
{
	Scope();
}

Poly1305::Poly1305(IBlockCipher* Cipher)
	:
	m_aadLoaded(false)
{
	Scope();
}

Poly1305::~Poly1305()
{
	Destroy();
}

//~~~Public Functions~~~//

void Poly1305::DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{

}

void Poly1305::DecryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{

}

void Poly1305::Destroy()
{

	try
	{

	}
	catch (std::exception& ex)
	{
		throw CryptoCipherModeException("Poly1305:Destroy", "Could not clear all variables!", std::string(ex.what()));
	}
}

void Poly1305::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	
}

void Poly1305::EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	
}

void Poly1305::Finalize(std::vector<byte> &Output, const size_t Offset, const size_t Length)
{
	if (!m_isInitialized)
		throw CryptoCipherModeException("Poly1305:Finalize", "The cipher mode has not been initialized!");
	if (Length < MIN_TAGSIZE || Length > m_macSize)
		throw CryptoCipherModeException("Poly1305:Finalize", "The length must be minimum of 12 and maximum of MAC code size!");

	CalculateMac();
	Utility::MemUtils::Copy<byte>(m_msgTag, 0, Output, Offset, Length);
}

void Poly1305::Initialize(bool Encryption, ISymmetricKey &KeyParams)
{
	// recheck params
	Scope();


	m_isInitialized = true;
}

void Poly1305::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0)
		throw CryptoCipherModeException("Poly1305:ParallelMaxDegree", "Parallel degree can not be zero!");
	if (Degree % 2 != 0)
		throw CryptoCipherModeException("Poly1305:ParallelMaxDegree", "Parallel degree must be an even number!");
	if (Degree > m_parallelProfile.ProcessorCount())
		throw CryptoCipherModeException("Poly1305:ParallelMaxDegree", "Parallel degree can not exceed processor count!");

	m_parallelProfile.SetMaxDegree(Degree);
}

void Poly1305::SetAssociatedData(const std::vector<byte> &Input, const size_t Offset, const size_t Length)
{
	if (!m_isInitialized)
		throw CryptoSymmetricCipherException("Poly1305:SetAssociatedData", "The cipher has not been initialized!");
	if (m_aadLoaded)
		throw CryptoSymmetricCipherException("Poly1305:SetAssociatedData", "The associated data has already been set!");

}

void Poly1305::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	CEXASSERT(m_isInitialized, "The cipher mode has not been initialized!");
	CEXASSERT(Utility::IntUtils::Min(Input.size() - InOffset, Output.size() - OutOffset) >= Length, "The data arrays are smaller than the the block-size!");


}

bool Poly1305::Verify(const std::vector<byte> &Input, const size_t Offset, const size_t Length)
{
	if (m_isEncryption)
		throw CryptoCipherModeException("Poly1305:Verify", "The cipher mode has not been initialized for decryption!");
	if (!m_isInitialized && !m_isFinalized)
		throw CryptoCipherModeException("Poly1305:Verify", "The cipher mode has not been initialized!");
	if (Length < MIN_TAGSIZE || Length > m_macSize)
		throw CryptoCipherModeException("Poly1305:Verify", "The length must be minimum of 12 and maximum of MAC code size!");

	if (!m_isFinalized)
		CalculateMac();

	return Utility::IntUtils::Compare<byte>(m_msgTag, 0, Input, Offset, Length);
}

//~~~Private Functions~~~//

void Poly1305::CalculateMac()
{

}

void Poly1305::Reset()
{
	/*if (!m_aadPreserve)
	{
		m_aadLoaded = false;
		Utility::MemUtils::Clear<byte>(m_aadData, 0, m_aadData.size());
	}

	m_isInitialized = false;
	m_macGenerator.Reset();
	Utility::MemUtils::Clear<byte>(m_eaxVector, 0, m_eaxVector.size());*/
}

void Poly1305::Scope()
{
	/*if (m_legalKeySizes.size() == 0)
		m_legalKeySizes = m_cipherMode.LegalKeySizes();

	if (!m_cipherMode.ParallelProfile().IsDefault())
		m_cipherMode.ParallelProfile().Calculate(m_parallelProfile.IsParallel(), m_cipherMode.ParallelProfile().ParallelBlockSize(), m_cipherMode.ParallelProfile().ParallelMaxDegree());*/
}

void Poly1305::UpdateTag(byte Tag, const std::vector<byte> &Nonce)
{
	/*std::vector<byte> tmp(m_macSize);
	tmp[tmp.size() - 1] = Tag;
	m_macGenerator.Update(tmp, 0, tmp.size());

	if (Nonce.size() != 0)
		m_macGenerator.Update(Nonce, 0, Nonce.size());*/
}

NAMESPACE_MODEEND