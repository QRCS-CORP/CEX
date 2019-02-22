#include "ACS.h"
#include "IntegerTools.h"
#include "MacFromName.h"
#include "MemoryTools.h"
#include "SHAKE.h"
#include "SymmetricKey.h"

NAMESPACE_STREAM

using Utility::IntegerTools;
using Utility::MemoryTools;
using Cipher::SymmetricKey;

const std::string ACS::CLASS_NAME("ACS");
const std::vector<byte> ACS::OMEGA_INFO = { 0x41, 0x43, 0x53, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, 0x20, 0x31, 0x2E, 0x30, 0x62 };

//~~~Constructor~~~//

ACS::ACS(BlockCiphers CipherType, StreamAuthenticators AuthenticatorType)
	:
	m_authenticatorType(AuthenticatorType),
	m_cipherMode(CipherType != BlockCiphers::None ? new CTR(CipherType) :
		throw CryptoSymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The Cipher type can not be none!"), ErrorCodes::InvalidParam)),
	m_cipherType(CipherType),
	m_shakeCustom(0),
	m_expansionMode(ShakeModes::SHAKE512),
	m_isAuthenticated(AuthenticatorType != StreamAuthenticators::None),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_legalKeySizes(m_cipherMode->LegalKeySizes()),
	m_macAuthenticator(AuthenticatorType == StreamAuthenticators::None ? nullptr :
		Helper::MacFromName::GetInstance(AuthenticatorType)),
	m_macCounter(0),
	m_macKey(0),
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

		if (m_cipherMode != nullptr)
		{
			m_cipherMode.reset(nullptr);
		}
		if (m_macAuthenticator != nullptr)
		{
			m_macAuthenticator.reset(nullptr);
		}

		IntegerTools::Clear(m_shakeCustom);
		IntegerTools::Clear(m_legalKeySizes);
		IntegerTools::Clear(m_macKey);
		IntegerTools::Clear(m_macTag);
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
	std::string name = CLASS_NAME  + "-" + m_cipherMode->Engine()->Name();

	switch (m_authenticatorType)
	{
		case StreamAuthenticators::HMACSHA256:
		{
			name += "-HMAC-SHA256";
			break;
		}
		case StreamAuthenticators::HMACSHA512:
		{
			name += "-HMAC-SHA512";
			break;
		}
		case StreamAuthenticators::KMAC256:
		{
			name += "-KMAC256";
			break;
		}
		case StreamAuthenticators::KMAC512:
		{
			name += "-KMAC512";
			break;
		}
		default:
		{
			name += "-KMAC1024";
			break;
		}
	}

	return name;
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
	return m_macAuthenticator != nullptr ? m_macAuthenticator->TagSize() : 0;
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

void ACS::Initialize(bool Encryption, ISymmetricKey &Parameters)
{
	if (!SymmetricKeySize::Contains(LegalKeySizes(), Parameters.Key().size()))
	{
		throw CryptoSymmetricException(Name(), std::string("Initialize"), std::string("Invalid key size; key must be one of the LegalKeySizes in length."), ErrorCodes::InvalidKey);
	}
	if (Parameters.Nonce().size() != m_cipherMode->BlockSize())
	{
		throw CryptoSymmetricException(Name(), std::string("Initialize"), std::string("Requires a nonce equal in size to the ciphers block size!"), ErrorCodes::InvalidNonce);
	}
	if (Parameters.Info().size() != 0 && Parameters.Info().size() != INFO_SIZE)
	{
		throw CryptoSymmetricException(Name(), std::string("Initialize"), std::string("The info parameter size is invalid, must be 16 bytes!"), ErrorCodes::InvalidInfo);
	}

	if (m_parallelProfile.IsParallel())
	{
		if (m_parallelProfile.IsParallel() && m_parallelProfile.ParallelBlockSize() < m_parallelProfile.ParallelMinimumSize() || m_parallelProfile.ParallelBlockSize() > m_parallelProfile.ParallelMaximumSize())
		{
			throw CryptoSymmetricException(Name(), std::string("Initialize"), std::string("The parallel block size is out of bounds!"), ErrorCodes::InvalidSize);
		}
		if (m_parallelProfile.IsParallel() && m_parallelProfile.ParallelBlockSize() % m_parallelProfile.ParallelMinimumSize() != 0)
		{
			throw CryptoSymmetricException(Name(), std::string("Initialize"), std::string("The parallel block size must be evenly aligned to the ParallelMinimumSize!"), ErrorCodes::InvalidParam);
		}
	}

	// reset for a new key
	Reset();

	std::vector<byte> code(INFO_SIZE);

	if (Parameters.Info().size() != 0)
	{
		// custom code
		MemoryTools::Copy(Parameters.Info(), 0, code, 0, code.size());
	}
	else
	{
		// standard
		MemoryTools::Copy(OMEGA_INFO, 0, code, 0, code.size());
	}

	if (m_authenticatorType == StreamAuthenticators::None)
	{
		// key the cipher directly
		Cipher::SymmetricKey kp(Parameters.Key(), Parameters.Nonce(), code);
		m_cipherMode->Initialize(true, kp);
	}
	else
	{
		// set the initial counter value
		m_macCounter = 1;

		// create the cSHAKE customization string
		m_shakeCustom.resize(sizeof(ulong) + Name().size());
		// add mac counter and algorithm name to customization string
		IntegerTools::Le64ToBytes(m_macCounter, m_shakeCustom, 0);
		MemoryTools::Copy(Name(), 0, m_shakeCustom, sizeof(ulong), Name().size());

		// initialize cSHAKE with k,c
		m_expansionMode = (Parameters.Key().size() == 64) ? ShakeModes::SHAKE512 : (Parameters.Key().size() == 32) ? ShakeModes::SHAKE256 : ShakeModes::SHAKE1024;
		Kdf::SHAKE gen(m_expansionMode);
		gen.Initialize(Parameters.Key(), m_shakeCustom);

		// generate the cipher key
		std::vector<byte> cprk(Parameters.Key().size());
		gen.Generate(cprk);

		// initialize the cipher
		Cipher::SymmetricKey kp(cprk, Parameters.Nonce(), code);
		m_cipherMode->Initialize(true, kp);

		// generate the mac key
		std::vector<byte> mack(m_macAuthenticator->LegalKeySizes()[1].KeySize());
		gen.Generate(mack);
		// initailize the mac
		m_macAuthenticator->Initialize(SymmetricKey(mack));
		// store the key
		m_macKey = LockClear(mack);
	}

	m_isEncryption = Encryption;
	m_isInitialized = true;
}

void ACS::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0 || Degree % 2 != 0 || Degree > m_parallelProfile.ProcessorCount())
	{
		throw CryptoSymmetricException(Name(), std::string("ParallelMaxDegree"), std::string("Degree setting is invalid!"), ErrorCodes::NotSupported);
	}

	m_parallelProfile.SetMaxDegree(Degree);
}

void ACS::SetAssociatedData(const std::vector<byte> &Input, const size_t Offset, const size_t Length)
{
	if (!m_isInitialized)
	{
		throw CryptoSymmetricException(Name(), std::string("SetAssociatedData"), std::string("The cipher has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (m_macAuthenticator == nullptr)
	{
		throw CryptoSymmetricException(Name(), std::string("SetAssociatedData"), std::string("The cipher has not been configured for authentication!"), ErrorCodes::IllegalOperation);
	}

	// update the authenticator
	m_macAuthenticator->Update(Input, Offset, Length);
}

void ACS::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	CEXASSERT(m_isInitialized, "The cipher mode has not been initialized!");
	CEXASSERT(IntegerTools::Min(Input.size() - InOffset, Output.size() - OutOffset) >= Length, "The data arrays are smaller than the the block-size!");

	if (m_isEncryption)
	{
		if (m_isAuthenticated)
		{
			// add the starting position of the nonce
			m_macAuthenticator->Update(m_cipherMode->Nonce(), 0, BLOCK_SIZE);
			// encrypt the stream
			m_cipherMode->Transform(Input, InOffset, Output, OutOffset, Length);
			// update the mac with the ciphertext
			m_macAuthenticator->Update(Output, OutOffset, Length);
			// update the mac counter
			m_macCounter += Length;
			// finalize the mac and add the tag to the stream
			Finalize(m_macTag, 0, m_macTag.size());
			MemoryTools::Copy(m_macTag, 0, Output, OutOffset + Length, m_macTag.size());
		}
		else
		{
			// encrypt the stream
			m_cipherMode->Transform(Input, InOffset, Output, OutOffset, Length);
		}
	}
	else
	{
		if (m_isAuthenticated)
		{
			// add the starting position of the nonce
			m_macAuthenticator->Update(m_cipherMode->Nonce(), 0, BLOCK_SIZE);
			// update the mac with the ciphertext
			m_macAuthenticator->Update(Input, InOffset, Length);
			// update the mac counter
			m_macCounter += Length;
			// finalize the mac and verify
			Finalize(m_macTag, 0, m_macTag.size());

			if (!IntegerTools::Compare(Input, InOffset + Length, m_macTag, 0, m_macTag.size()))
			{
				throw CryptoAuthenticationFailure(Name(), std::string("Transform"), std::string("The authentication tag does not match!"), ErrorCodes::AuthenticationFailure);
			}
		}

		// decrypt the stream
		m_cipherMode->Transform(Input, InOffset, Output, OutOffset, Length);
	}
}

//~~~Private Functions~~~//

void ACS::Finalize(std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	if (!m_isInitialized)
	{
		throw CryptoSymmetricException(Name(), std::string("Finalize"), std::string("The cipher has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (m_macAuthenticator == nullptr)
	{
		throw CryptoSymmetricException(Name(), std::string("Finalize"), std::string("The cipher has not been configured for authentication!"), ErrorCodes::IllegalOperation);
	}
	if (Length > m_macAuthenticator->TagSize())
	{
		throw CryptoSymmetricException(Name(), std::string("Finalize"), std::string("The MAC code specified is longer than the maximum length!"), ErrorCodes::InvalidParam);
	}

	// generate the mac code
	std::vector<byte> code(m_macAuthenticator->TagSize());
	m_macAuthenticator->Finalize(code, 0);
	MemoryTools::Copy(code, 0, Output, OutOffset, code.size() < Length ? code.size() : Length);

	// customization string is: mac counter + algorithm name
	IntegerTools::Le64ToBytes(m_macCounter, m_shakeCustom, 0);

	// extract the new mac key
	Kdf::SHAKE gen(m_expansionMode);
	gen.Initialize(UnlockClear(m_macKey), m_shakeCustom);
	std::vector<byte> mack(m_macAuthenticator->LegalKeySizes()[1].KeySize());
	gen.Generate(mack);
	// reset the generator with the new key
	m_macAuthenticator->Initialize(SymmetricKey(mack));
	// store the key
	m_macKey = LockClear(mack);
}

void ACS::Reset()
{
	if (m_macAuthenticator != nullptr)
	{
		m_macAuthenticator->Reset();
		m_macTag.resize(m_macAuthenticator->TagSize());
	}

	m_cipherMode->ParallelProfile().Calculate(m_parallelProfile.IsParallel(), m_parallelProfile.ParallelBlockSize(), m_parallelProfile.ParallelMaxDegree());
	m_isInitialized = false;
}

NAMESPACE_STREAMEND
