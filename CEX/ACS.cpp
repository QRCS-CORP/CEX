#include "ACS.h"
#include "IntUtils.h"
#include "MacFromName.h"
#include "MemUtils.h"
#include "SHAKE.h"
#include "SymmetricKey.h"

NAMESPACE_STREAM

using Utility::IntUtils;
using Utility::MemUtils;
using Key::Symmetric::SymmetricKey;

const std::vector<byte> ACS::CSHAKE_CUST = { 0x43, 0x53, 0x58, 0x32, 0x35, 0x36 };
const std::string ACS::CLASS_NAME("ACS");
const std::string ACS::OMEGA_INFO("ACS version 1.0");

//~~~Constructor~~~//

ACS::ACS(BlockCiphers CipherType, BlockCipherExtensions CipherExtensionType, StreamAuthenticators AuthenticatorType)
	:
	m_authenticatorType(AuthenticatorType),
	m_cipherMode(CipherType != BlockCiphers::None ? new CTR(CipherType, CipherExtensionType) :
		throw CryptoSymmetricCipherException("ACS:CTor", "The Cipher type can not be none!")),
	m_cipherType(CipherType),
	m_distributionCode(0),
	m_generatorMode(ShakeModes::SHAKE256),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_legalKeySizes(m_cipherMode->LegalKeySizes()),
	m_macAuthenticator(AuthenticatorType == StreamAuthenticators::None ? nullptr :
		Helper::MacFromName::GetInstance(AuthenticatorType)),
	m_macCounter(0),
	m_macKey(nullptr),
	m_parallelProfile(BLOCK_SIZE, m_cipherMode->ParallelProfile().IsParallel(), m_cipherMode->ParallelProfile().ParallelBlockSize(),
		m_cipherMode->ParallelProfile().ParallelMaxDegree(), true, m_cipherMode->Engine()->StateCacheSize(), true)
{
}

ACS::~ACS()
{
	if (!m_isDestroyed)
	{
		m_authenticatorType = StreamAuthenticators::None;
		m_cipherType = BlockCiphers::None;
		m_isDestroyed = true;
		m_isEncryption = false;
		m_generatorMode = ShakeModes::None;
		m_isInitialized = false;
		m_macCounter = 0;
		m_parallelProfile.Reset();

		IntUtils::ClearVector(m_distributionCode);
		IntUtils::ClearVector(m_legalKeySizes);

		if (m_cipherMode != nullptr)
		{
			m_cipherMode.reset(nullptr);
		}
		if (m_macKey != nullptr)
		{
			m_macKey.reset(nullptr);
		}
		if (m_macAuthenticator != nullptr)
		{
			m_macAuthenticator.reset(nullptr);
		}
	}
}

//~~~Accessors~~~//

const size_t ACS::BlockSize()
{
	return BLOCK_SIZE;
}

const std::vector<byte> &ACS::DistributionCode()
{
	return m_distributionCode;
}

const size_t ACS::DistributionCodeMax()
{
	return INFO_SIZE;
}

const StreamCiphers ACS::Enumeral()
{
	return StreamCiphers::ACS;
}

const bool ACS::IsInitialized()
{
	return m_isInitialized;
}

const bool ACS::IsParallel()
{
	return m_parallelProfile.IsParallel();
}

const std::vector<SymmetricKeySize> &ACS::LegalKeySizes()
{
	return m_legalKeySizes;
}

const std::string ACS::Name()
{
	return CLASS_NAME + "-" + m_cipherMode->Engine()->Name();
}

const size_t ACS::TagSize()
{
	return m_macAuthenticator != nullptr ? m_macAuthenticator->MacSize() : 0;
}

const size_t ACS::ParallelBlockSize()
{
	return m_parallelProfile.ParallelBlockSize();
}

ParallelOptions &ACS::ParallelProfile()
{
	return m_parallelProfile;
}

void ACS::Authenticator(StreamAuthenticators AuthenticatorType)
{
	if (m_macAuthenticator != nullptr)
	{
		m_macAuthenticator.reset(nullptr);
	}

	if (AuthenticatorType != StreamAuthenticators::None)
	{
		m_macAuthenticator.reset(Helper::MacFromName::GetInstance(AuthenticatorType));
	}

	m_authenticatorType = AuthenticatorType;
}

void ACS::Finalize(std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	if (!m_isInitialized)
	{
		throw CryptoSymmetricCipherException("ACS:Finalize", "The cipher has not been initialized!");
	}
	if (m_macAuthenticator == nullptr)
	{
		throw CryptoSymmetricCipherException("ACS:Finalize", "The cipher has not been configured for authentication!");
	}

	// generate the mac code
	std::vector<byte> code(m_macAuthenticator->MacSize());
	m_macAuthenticator->Finalize(code, 0);
	MemUtils::Copy(code, 0, Output, OutOffset, code.size() < Length ? code.size() : Length);

	// customization string is CSX256+counter
	std::vector<byte> cst(CSHAKE_CUST.size() + sizeof(ulong));
	MemUtils::Copy(CSHAKE_CUST, 0, cst, 0, CSHAKE_CUST.size());
	IntUtils::Le64ToBytes(m_macCounter, cst, CSHAKE_CUST.size());

	// extract the new mac key
	Kdf::SHAKE gen(m_generatorMode);
	gen.Initialize(m_macKey->Key(), cst);
	std::vector<byte> mack(m_macAuthenticator->LegalKeySizes()[1].KeySize());
	gen.Generate(mack);
	m_macKey.reset(new SymmetricSecureKey(mack));

	// reset the generator with the new key
	m_macAuthenticator->Initialize(*m_macKey.get());
}

void ACS::Initialize(bool Encryption, ISymmetricKey &KeyParams)
{
	if (!SymmetricKeySize::Contains(LegalKeySizes(), KeyParams.Key().size()))
	{
		throw CryptoSymmetricCipherException("ACS:Initialize", "Invalid key size! Key must be one of the LegalKeySizes() in length.");
	}
	if (KeyParams.Nonce().size() != m_cipherMode->BlockSize())
	{
		throw CryptoSymmetricCipherException("ACS:Initialize", "Requires a nonce equal in size to the ciphers block size!");
	}
	if (m_parallelProfile.IsParallel() && m_parallelProfile.ParallelBlockSize() < m_parallelProfile.ParallelMinimumSize() || m_parallelProfile.ParallelBlockSize() > m_parallelProfile.ParallelMaximumSize())
	{
		throw CryptoSymmetricCipherException("ACS:Initialize", "The parallel block size is out of bounds!");
	}
	if (m_parallelProfile.IsParallel() && m_parallelProfile.ParallelBlockSize() % m_parallelProfile.ParallelMinimumSize() != 0)
	{
		throw CryptoSymmetricCipherException("ACS:Initialize", "The parallel block size must be evenly aligned to the ParallelMinimumSize!");
	}

	// reset for a new key
	Reset();

	if (KeyParams.Info().size() != 0)
	{
		// custom code
		m_distributionCode.resize(KeyParams.Info().size());
		MemUtils::Copy(KeyParams.Info(), 0, m_distributionCode, 0, m_distributionCode.size());
	}
	else
	{
		// standard
		m_distributionCode.assign(OMEGA_INFO.begin(), OMEGA_INFO.end());
	}

	if (m_authenticatorType == StreamAuthenticators::None)
	{
		// key the cipher directly
		Key::Symmetric::SymmetricKey kp(KeyParams.Key(), KeyParams.Nonce(), m_distributionCode);
		m_cipherMode->Initialize(true, kp);
	}
	else
	{
		// set the initial counter value
		m_macCounter = 1;

		// create the cSHAKE customization string
		std::vector<byte> cust(CSHAKE_CUST.size() + sizeof(ulong));
		MemUtils::Copy(CSHAKE_CUST, 0, cust, 0, CSHAKE_CUST.size());
		IntUtils::Le64ToBytes(m_macCounter, cust, CSHAKE_CUST.size());

		// initialize cSHAKE with k,c
		Kdf::SHAKE kdf(m_generatorMode);
		kdf.Initialize(KeyParams.Key(), cust);

		// generate the cipher key
		std::vector<byte> cprk(KeyParams.Key().size());
		kdf.Generate(cprk);

		// initialize the cipher k=14,223 n=255,254 c=65,67
		Key::Symmetric::SymmetricKey kp(cprk, KeyParams.Nonce(), m_distributionCode);
		m_cipherMode->Initialize(true, kp);

		// generate the mac key
		std::vector<byte> mack(m_macAuthenticator->LegalKeySizes()[1].KeySize());
		kdf.Generate(mack);

		// initailize the mac
		m_macKey.reset(new SymmetricSecureKey(mack));
		m_macAuthenticator->Initialize(*m_macKey.get());
	}

	m_isEncryption = Encryption;
	m_isInitialized = true;
}

void ACS::ParallelMaxDegree(size_t Degree)
{
	CexAssert(Degree != 0, "parallel degree can not be zero");
	CexAssert(Degree % 2 == 0, "parallel degree must be an even number");
	CexAssert(Degree <= m_parallelProfile.ProcessorCount(), "parallel degree can not exceed processor count");

	m_parallelProfile.SetMaxDegree(Degree);
}

void ACS::Reset()
{
	switch (m_authenticatorType)
	{
		case StreamAuthenticators::KMAC256:
		case StreamAuthenticators::HMACSHA256:
		{
			m_generatorMode = ShakeModes::SHAKE256;
			break;
		}
		case StreamAuthenticators::KMAC512:
		case StreamAuthenticators::HMACSHA512:
		{
			m_generatorMode = ShakeModes::SHAKE512;
			break;
		}
		case StreamAuthenticators::KMAC1024:
		{
			m_generatorMode = ShakeModes::SHAKE1024;
			break;
		}
		default:
		{
			m_generatorMode = ShakeModes::None;
		}
	}

	m_cipherMode->ParallelProfile().Calculate(m_parallelProfile.IsParallel(), m_parallelProfile.ParallelBlockSize(), m_parallelProfile.ParallelMaxDegree());
	m_isInitialized = false;
}

void ACS::SetAssociatedData(const std::vector<byte> &Input, const size_t Offset, const size_t Length)
{
	if (!m_isInitialized)
	{
		throw CryptoSymmetricCipherException("ACS:Finalize", "The cipher has not been initialized!");
	}
	if (m_macAuthenticator == nullptr)
	{
		throw CryptoSymmetricCipherException("ACS:Finalize", "The cipher has not been configured for authentication!");
	}

	// update the authenticator
	m_macAuthenticator->Update(Input, Offset, Length);
}

void ACS::TransformBlock(const std::vector<byte>& Input, std::vector<byte>& Output)
{
	Transform(Input, 0, Output, 0, BLOCK_SIZE);
}

void ACS::TransformBlock(const std::vector<byte>& Input, size_t InOffset, std::vector<byte>& Output, size_t OutOffset)
{
	Transform(Input, InOffset, Output, OutOffset, BLOCK_SIZE);
}

void ACS::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	CexAssert(m_isInitialized, "The cipher mode has not been initialized!");
	CexAssert(IntUtils::Min(Input.size() - InOffset, Output.size() - OutOffset) >= Length, "The data arrays are smaller than the the block-size!");

	if (m_isEncryption)
	{
		m_cipherMode->Transform(Input, InOffset, Output, OutOffset, Length);

		if (m_authenticatorType != StreamAuthenticators::None)
		{
			m_macAuthenticator->Update(Output, OutOffset, Length);
		}
	}
	else
	{
		if (m_authenticatorType != StreamAuthenticators::None)
		{
			m_macAuthenticator->Update(Input, InOffset, Length);
		}

		m_cipherMode->Transform(Input, InOffset, Output, OutOffset, Length);
	}

	m_macCounter += Length;
}

NAMESPACE_STREAMEND
