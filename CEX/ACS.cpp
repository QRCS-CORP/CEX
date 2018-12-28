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

const std::string ACS::CLASS_NAME("ACS");
const std::vector<byte> ACS::OMEGA_INFO = { 0x41, 0x43, 0x53, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, 0x20, 0x31, 0x2E, 0x30, 0x62 };

//~~~Constructor~~~//

ACS::ACS(BlockCiphers CipherType, BlockCipherExtensions CipherExtensionType, StreamAuthenticators AuthenticatorType)
	:
	m_authenticatorType(AuthenticatorType),
	m_cipherMode(CipherType != BlockCiphers::None ? new CTR(CipherType, CipherExtensionType) :
		throw CryptoSymmetricCipherException("ACS:CTor", "The Cipher type can not be none!")),
	m_cipherType(CipherType),
	m_cShakeCustom(0),
	m_expansionMode(ShakeModes::SHAKE512),
	m_isAuthenticated(AuthenticatorType != StreamAuthenticators::None),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_legalKeySizes(m_cipherMode->LegalKeySizes()),
	m_macAuthenticator(AuthenticatorType == StreamAuthenticators::None ? nullptr :
		Helper::MacFromName::GetInstance(AuthenticatorType)),
	m_macCounter(0),
	m_macKey(nullptr),
	m_macTag(0),
	m_parallelProfile(BLOCK_SIZE, m_cipherMode->ParallelProfile().IsParallel(), m_cipherMode->ParallelProfile().ParallelBlockSize(),
		m_cipherMode->ParallelProfile().ParallelMaxDegree(), true, m_cipherMode->Engine()->StateCacheSize(), true)
{
}

ACS::~ACS()
{
	if (!m_isDestroyed)
	{
		m_authenticatorType = StreamAuthenticators::None;
		m_isAuthenticated = false;
		m_cipherType = BlockCiphers::None;
		m_expansionMode = ShakeModes::None;
		m_isDestroyed = true;
		m_isEncryption = false;
		m_isInitialized = false;
		m_macCounter = 0;
		m_parallelProfile.Reset();

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

		IntUtils::ClearVector(m_cShakeCustom);
		IntUtils::ClearVector(m_legalKeySizes);
		IntUtils::ClearVector(m_macTag);
	}
}

//~~~Accessors~~~//

const size_t ACS::BlockSize()
{
	return BLOCK_SIZE;
}

const size_t ACS::DistributionCodeMax()
{
	return INFO_SIZE;
}

const StreamCiphers ACS::Enumeral()
{
	return StreamCiphers::ACS;
}

const bool ACS::IsAuthenticator()
{
	return m_isAuthenticated;
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
	std::string tmp = CLASS_NAME  + "-" + m_cipherMode->Engine()->Name();

	switch (m_authenticatorType)
	{
		case StreamAuthenticators::HMACSHA256:
		{
			tmp += "+HMAC-SHA256";
			break;
		}
		case StreamAuthenticators::HMACSHA512:
		{
			tmp += "+HMAC-SHA512";
			break;
		}
		case StreamAuthenticators::KMAC256:
		{
			tmp += "+KMAC-256";
			break;
		}
		case StreamAuthenticators::KMAC512:
		{
			tmp += "+KMAC-512";
			break;
		}
		default:
		{
			tmp += "+KMAC-1024";
			break;
		}
	}

	return tmp;
}

const size_t ACS::ParallelBlockSize()
{
	return m_parallelProfile.ParallelBlockSize();
}

ParallelOptions &ACS::ParallelProfile()
{
	return m_parallelProfile;
}

const std::vector<byte> &ACS::Tag()
{
	return m_macTag;
}

const size_t ACS::TagSize()
{
	return m_macAuthenticator != nullptr ? m_macAuthenticator->MacSize() : 0;
}

//~~~Public Functions~~~//

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
	if (KeyParams.Info().size() != 0 && KeyParams.Info().size() != INFO_SIZE)
	{
		throw CryptoSymmetricCipherException("ACS:Initialize", "The info parameter size is invalid, must be 16 bytes!");
	}

	// reset for a new key
	Reset();

	std::vector<byte> code(INFO_SIZE);

	if (KeyParams.Info().size() != 0)
	{
		// custom code
		MemUtils::Copy(KeyParams.Info(), 0, code, 0, code.size());
	}
	else
	{
		// standard
		MemUtils::Copy(OMEGA_INFO, 0, code, 0, code.size());
	}

	if (m_authenticatorType == StreamAuthenticators::None)
	{
		// key the cipher directly
		Key::Symmetric::SymmetricKey kp(KeyParams.Key(), KeyParams.Nonce(), code);
		m_cipherMode->Initialize(true, kp);
	}
	else
	{
		// set the initial counter value
		m_macCounter = 1;

		// create the cSHAKE customization string
		m_cShakeCustom.resize(sizeof(ulong) + Name().size());
		// add mac counter and algorithm name to customization string
		IntUtils::Le64ToBytes(m_macCounter, m_cShakeCustom, 0);
		MemUtils::Copy(Name(), 0, m_cShakeCustom, sizeof(ulong), Name().size());

		// initialize cSHAKE with k,c
		m_expansionMode = (KeyParams.Key().size() == 64) ? ShakeModes::SHAKE512 : (KeyParams.Key().size() == 32) ? ShakeModes::SHAKE256 : ShakeModes::SHAKE1024;
		Kdf::SHAKE gen(m_expansionMode);
		gen.Initialize(KeyParams.Key(), m_cShakeCustom);

		// generate the cipher key
		std::vector<byte> cprk(KeyParams.Key().size());
		gen.Generate(cprk);

		// initialize the cipher
		Key::Symmetric::SymmetricKey kp(cprk, KeyParams.Nonce(), code);
		m_cipherMode->Initialize(true, kp);

		// generate the mac key
		std::vector<byte> mack(m_macAuthenticator->LegalKeySizes()[1].KeySize());
		gen.Generate(mack);

		// initailize the mac
		m_macKey.reset(new SymmetricSecureKey(mack));
		m_macAuthenticator->Initialize(*m_macKey.get());
	}

	m_isEncryption = Encryption;
	m_isInitialized = true;
}

void ACS::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0 || Degree % 2 != 0 || Degree > m_parallelProfile.ProcessorCount())
	{
		throw CryptoSymmetricCipherException("ACS:ParallelMaxDegree", "Degree setting is invalid!");
	}

	m_parallelProfile.SetMaxDegree(Degree);
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

void ACS::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	CexAssert(m_isInitialized, "The cipher mode has not been initialized!");
	CexAssert(IntUtils::Min(Input.size() - InOffset, Output.size() - OutOffset) >= Length, "The data arrays are smaller than the the block-size!");

	m_cipherMode->Transform(Input, InOffset, Output, OutOffset, Length);

	if (m_isAuthenticated)
	{
		m_macCounter += Length;

		if (m_isEncryption)
		{
			m_macAuthenticator->Update(Output, OutOffset, Length);
			m_macAuthenticator->Update(m_cipherMode->Nonce(), 0, BLOCK_SIZE);

			Finalize(m_macTag, 0, m_macTag.size());
			MemUtils::Copy(m_macTag, 0, Output, OutOffset + Length, m_macTag.size());
		}
		else
		{
			m_macAuthenticator->Update(Input, InOffset, Length);
			m_macAuthenticator->Update(m_cipherMode->Nonce(), 0, BLOCK_SIZE);

			Finalize(m_macTag, 0, m_macTag.size());

			if (!IntUtils::Compare(Input, InOffset + Length, m_macTag, 0, m_macTag.size()))
			{
				throw CryptoAuthenticationFailure("Threefish256:Process", "The authentication tag does not match!");
			}
		}
	}
}

//~~~Private Functions~~~//

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
	if (Length > m_macAuthenticator->MacSize())
	{
		throw CryptoSymmetricCipherException("ACS:Finalize", "The MAC code specified is longer than the maximum length!");
	}

	// generate the mac code
	std::vector<byte> code(m_macAuthenticator->MacSize());
	m_macAuthenticator->Finalize(code, 0);
	MemUtils::Copy(code, 0, Output, OutOffset, code.size() < Length ? code.size() : Length);

	// customization string is: mac counter + algorithm name
	IntUtils::Le64ToBytes(m_macCounter, m_cShakeCustom, 0);

	// extract the new mac key
	Kdf::SHAKE gen(m_expansionMode);
	gen.Initialize(m_macKey->Key(), m_cShakeCustom);
	std::vector<byte> mack(m_macAuthenticator->LegalKeySizes()[1].KeySize());
	gen.Generate(mack);
	m_macKey.reset(new SymmetricSecureKey(mack));

	// reset the generator with the new key
	m_macAuthenticator->Initialize(*m_macKey.get());
}

void ACS::Reset()
{
	if (m_macAuthenticator != nullptr)
	{
		m_macAuthenticator->Reset();
		m_macTag.resize(m_macAuthenticator->MacSize());
	}

	m_cipherMode->ParallelProfile().Calculate(m_parallelProfile.IsParallel(), m_parallelProfile.ParallelBlockSize(), m_parallelProfile.ParallelMaxDegree());
	m_isInitialized = false;
}

NAMESPACE_STREAMEND
