#include "GMAC.h"
#include "BlockCipherFromName.h"
#include "IntUtils.h"
#include "MemUtils.h"

NAMESPACE_MAC

const std::string GMAC::CLASS_NAME("GMAC");

//~~~Constructor~~~//

GMAC::GMAC(BlockCiphers CipherType, BlockCipherExtensions CipherExtensionType)
	:
	m_blockCipher(CipherType != BlockCiphers::None ? Helper::BlockCipherFromName::GetInstance(CipherType, CipherExtensionType) :
		throw CryptoMacException("GMAC:CTor", "The Cipher type can not be none!")),
	m_cipherType(CipherType),
	m_destroyEngine(true),
	m_gmacHash(new Mac::GHASH()),
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
	m_blockCipher(Cipher != nullptr ? Cipher : 
		throw CryptoMacException("GMAC:CTor", "The Cipher can not be null!")),
	m_cipherType(Cipher->Enumeral()),
	m_destroyEngine(false),
	m_gmacHash(new Mac::GHASH()),
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
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_cipherType = BlockCiphers::None;
		m_isInitialized = false;
		m_msgCounter = 0;
		m_msgOffset = 0;

		Utility::IntUtils::ClearVector(m_gmacKey);
		Utility::IntUtils::ClearVector(m_gmacNonce);
		Utility::IntUtils::ClearVector(m_legalKeySizes);
		Utility::IntUtils::ClearVector(m_msgBuffer);
		Utility::IntUtils::ClearVector(m_msgCode);

		if (m_gmacHash != nullptr)
		{
			m_gmacHash->Reset();
			m_gmacHash.reset(nullptr);
		}

		if (m_destroyEngine)
		{
			m_destroyEngine = false;
			if (m_blockCipher != nullptr)
			{
				m_blockCipher.reset(nullptr);
			}
		}
		else
		{
			if (m_blockCipher != nullptr)
			{
				m_blockCipher.release();
			}
		}
	}
}

//~~~Accessors~~~//

const size_t GMAC::BlockSize() 
{
	return m_blockCipher->BlockSize(); 
}

const BlockCiphers GMAC::CipherType()
{ 
	return m_cipherType; 
}

const Macs GMAC::Enumeral()
{
	return Macs::GMAC;
}

const size_t GMAC::MacSize() 
{ 
	return BLOCK_SIZE; 
}

const bool GMAC::IsInitialized()
{ 
	return m_isInitialized; 
}

std::vector<SymmetricKeySize> GMAC::LegalKeySizes() const 
{
	return m_legalKeySizes; 
};

const std::string GMAC::Name()
{ 
	return CLASS_NAME + "-" + m_blockCipher->Name();
}

//~~~Public Functions~~~//

void GMAC::Compute(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	if (!m_isInitialized)
	{
		throw CryptoMacException("GMAC:Compute", "The generator has not been initialized!");
	}

	if (Output.size() != BLOCK_SIZE)
	{
		Output.resize(BLOCK_SIZE);
	}

	Update(Input, 0, Input.size());
	Finalize(Output, 0);
}

size_t GMAC::Finalize(std::vector<byte> &Output, size_t OutOffset)
{
	if (!m_isInitialized)
	{
		throw CryptoMacException("GMAC:Finalize", "The generator has not been initialized!");
	}
	if ((Output.size() - OutOffset) < BLOCK_SIZE)
	{
		throw CryptoMacException("GMAC:Finalize", "The Output buffer is too short!");
	}

	m_gmacHash->FinalizeBlock(m_msgCode, m_msgCounter, 0);
	Utility::MemUtils::XorBlock(m_gmacNonce, 0, m_msgCode, 0, BLOCK_SIZE);
	Utility::MemUtils::Copy(m_msgCode, 0, Output, OutOffset, BLOCK_SIZE);
	Reset();

	return BLOCK_SIZE;
}

void GMAC::Initialize(ISymmetricKey &KeyParams)
{
	if (KeyParams.Nonce().size() < TAG_MINLEN)
	{
		throw CryptoMacException("GMAC:Initialize", "The length must be minimum of 12, and maximum of MAC code size!");
	}
	if (!SymmetricKeySize::Contains(LegalKeySizes(), KeyParams.Key().size()))
	{
		throw CryptoMacException("GMAC:Initialize", "Invalid key size! Key must be one of the LegalKeySizes() in length.");
	}

	if (m_isInitialized)
	{
		Reset();
	}

	if (KeyParams.Key().size() != 0)
	{
		// key the cipher and generate H
		m_blockCipher->Initialize(true, KeyParams);
		std::vector<byte> tmpH(BLOCK_SIZE);
		const std::vector<byte> ZEROES(BLOCK_SIZE);
		m_blockCipher->Transform(ZEROES, 0, tmpH, 0);

		m_gmacKey =
		{
			Utility::IntUtils::BeBytesTo64(tmpH, 0),
			Utility::IntUtils::BeBytesTo64(tmpH, 8)
		};

		m_gmacHash->Initialize(m_gmacKey);
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
	Utility::MemUtils::Clear(m_gmacNonce, 0, m_gmacNonce.size());
	Utility::MemUtils::Clear(m_msgBuffer, 0, m_msgBuffer.size());
	Utility::MemUtils::Clear(m_msgCode, 0, m_msgCode.size());
	m_gmacHash->Reset();
	m_msgCounter = 0;
	m_msgOffset = 0;
}

void GMAC::Update(byte Input)
{
	CexAssert(m_isInitialized, "The Mac is not initialized");

	m_gmacHash->Update(std::vector<byte> { Input }, 0, m_msgCode, 1);
}

void GMAC::Update(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	CexAssert(m_isInitialized, "The Mac is not initialized!");
	CexAssert((InOffset + Length) <= Input.size(), "The Input buffer is too short!");

	if (Length != 0)
	{
		m_gmacHash->Update(Input, InOffset, m_msgCode, Length);
		m_msgCounter += Length;
	}
}

void GMAC::Scope()
{
	m_legalKeySizes.resize(m_blockCipher->LegalKeySizes().size());
	std::vector<SymmetricKeySize> keySizes = m_blockCipher->LegalKeySizes();

	// recommended iv is 12 bytes with gmac
	for (size_t i = 0; i < m_legalKeySizes.size(); ++i)
	{
		m_legalKeySizes[i] = SymmetricKeySize(keySizes[i].KeySize(), 12, keySizes[i].InfoSize());
	}
}

NAMESPACE_MACEND
