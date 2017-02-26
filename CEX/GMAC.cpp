#include "GMAC.h"
#include "ArrayUtils.h"
#include "BlockCipherFromName.h"
#include "IntUtils.h"
#include "SymmetricKey.h"

NAMESPACE_MAC

using Utility::IntUtils;

GMAC::GMAC(BlockCiphers CipherType)
	:
	m_blockCipher(Helper::BlockCipherFromName::GetInstance(CipherType)),
	m_cipherType(CipherType),
	m_destroyEngine(true),
	m_gmacHash(0),
	m_gmacNonce(0),
	m_gmacKey(0),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_legalKeySizes(0),
	m_msgBuffer(BLOCK_SIZE),
	m_msgCode(BLOCK_SIZE),
	m_msgCounter(0),
	m_msgOffset(0)
{
	Scope();
}

GMAC::GMAC(IBlockCipher* Cipher)
	:
	m_blockCipher(Cipher != 0 ? Cipher : throw CryptoMacException("GMAC:CTor", "The Cipher can not be null!")),
	m_cipherType(Cipher->Enumeral()),
	m_destroyEngine(false),
	m_gmacHash(0),
	m_gmacNonce(0),
	m_gmacKey(0),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_legalKeySizes(0),
	m_msgBuffer(BLOCK_SIZE),
	m_msgCode(BLOCK_SIZE),
	m_msgCounter(0),
	m_msgOffset(0)
{
	Scope();
}

GMAC::~GMAC()
{
	Destroy();
}

//~~~Public Functions~~~//

void GMAC::Compute(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	if (!m_isInitialized)
		throw CryptoMacException("GMAC:Compute", "The Mac is not initialized!");

	if (Output.size() != BLOCK_SIZE)
		Output.resize(BLOCK_SIZE);

	Update(Input, 0, Input.size());
	Finalize(Output, 0);
}

void GMAC::Destroy()
{
	if (!m_isDestroyed)
	{
		m_cipherType = BlockCiphers::None;
		m_isDestroyed = true;
		m_isInitialized = false;
		m_msgCounter = 0;
		m_msgOffset = 0;

		try
		{
			m_gmacHash->Reset();

			if (m_destroyEngine)
			{
				m_destroyEngine = false;

				if (m_blockCipher != 0)
					delete m_blockCipher;
			}

			Utility::ArrayUtils::ClearVector(m_gmacNonce);
			Utility::ArrayUtils::ClearVector(m_gmacKey);
			Utility::ArrayUtils::ClearVector(m_legalKeySizes);
			Utility::ArrayUtils::ClearVector(m_msgBuffer);
			Utility::ArrayUtils::ClearVector(m_msgCode);

		}
		catch (std::exception& ex)
		{
			throw CryptoMacException("GMAC:Destroy", "Could not clear all variables!", std::string(ex.what()));
		}
	}
}

size_t GMAC::Finalize(std::vector<byte> &Output, size_t OutOffset)
{
	if (!m_isInitialized)
		throw CryptoMacException("GMAC:Finalize", "The Mac is not initialized!");
	if ((Output.size() - OutOffset) < BLOCK_SIZE)
		throw CryptoMacException("GMAC:Finalize", "The Output buffer is too short!");

	m_gmacHash->FinalizeBlock(m_msgCode, m_msgCounter, 0);
	IntUtils::XORBLK(m_gmacNonce, 0, m_msgCode, 0, BLOCK_SIZE);
	memcpy(&Output[OutOffset], &m_msgCode[0], BLOCK_SIZE);
	Reset();

	return BLOCK_SIZE;
}

void GMAC::Initialize(ISymmetricKey &KeyParams)
{
	if (KeyParams.Nonce().size() < TAG_MINLEN)
		throw CryptoMacException("GMAC:Initialize", "The length must be minimum of 12 and maximum of MAC code size!");
	if (!SymmetricKeySize::Contains(LegalKeySizes(), KeyParams.Key().size()))
		throw CryptoMacException("GMAC:Initialize", "Invalid key size! Key must be one of the LegalKeySizes() in length.");

	if (m_isInitialized)
		Reset();

	if (KeyParams.Key().size() != 0)
	{
		// key the cipher and generate H
		m_blockCipher->Initialize(true, KeyParams);
		std::vector<byte> tmpH(BLOCK_SIZE);
		const std::vector<byte> ZEROES(BLOCK_SIZE);
		m_blockCipher->Transform(ZEROES, 0, tmpH, 0);

		m_gmacKey =
		{
			IntUtils::BytesToBe64(tmpH, 0),
			IntUtils::BytesToBe64(tmpH, 8)
		};

		m_gmacHash = new GHASH(m_gmacKey);
	}

	// initialize the nonce
	m_gmacNonce = KeyParams.Nonce();

	if (m_gmacNonce.size() == 12)
	{
		m_gmacNonce.resize(16);
		m_gmacNonce[15] = 1;
	}
	else
	{
		std::vector<byte> y0(BLOCK_SIZE);
		m_gmacHash->ProcessSegment(m_gmacNonce, 0, y0, m_gmacNonce.size());
		m_gmacHash->FinalizeBlock(y0, 0, m_gmacNonce.size());
		m_gmacNonce = y0;
	}

	m_blockCipher->Transform(m_gmacNonce, m_gmacNonce);
	m_isInitialized = true;
}

void GMAC::Reset()
{
	memset(&m_gmacNonce[0], (byte)0, m_gmacNonce.size());
	memset(&m_msgCode[0], (byte)0, m_msgCode.size());
	memset(&m_msgBuffer[0], (byte)0, m_msgBuffer.size());
	m_msgCounter = 0;
	m_msgOffset = 0;
}

void GMAC::Update(byte Input)
{
	m_gmacHash->Update(std::vector<byte> { Input }, 0, m_msgCode, 1);
}

void GMAC::Update(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	if (Length == 0)
		return;
	if (!m_isInitialized)
		throw CryptoMacException("GMAC:Update", "The Mac is not initialized!");
	if ((InOffset + Length) > Input.size())
		throw CryptoMacException("GMAC:Update", "The Input buffer is too short!");

	m_gmacHash->Update(Input, InOffset, m_msgCode, Length);
	m_msgCounter += Length;
}

void GMAC::Scope()
{
	m_legalKeySizes.resize(m_blockCipher->LegalKeySizes().size());
	// recommended iv is 12 bytes with gmac
	for (size_t i = 0; i < m_legalKeySizes.size(); ++i)
		m_legalKeySizes[i] = SymmetricKeySize(m_blockCipher->LegalKeySizes()[i].KeySize(), 12, m_blockCipher->LegalKeySizes()[i].InfoSize());
}

NAMESPACE_MACEND