#include "MCS.h"
#include "IntegerTools.h"
#include "MacFromName.h"
#include "MemoryTools.h"
#include "SHAKE.h"

NAMESPACE_STREAM

using Utility::IntegerTools;
using Utility::MemoryTools;
using Enumeration::StreamCipherConvert;

const std::string MCS::CLASS_NAME("MCS");
const std::vector<byte> MCS::OMEGA_INFO = { 0x41, 0x43, 0x53, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, 0x20, 0x31, 0x2E, 0x30, 0x62 };

class MCS::McsState
{
public:

	SecureVector<byte> Custom;
	SecureVector<byte> MacKey;
	SecureVector<byte> MacTag;
	ulong Counter;
	ShakeModes Mode;
	bool Encryption;
	bool Initialized;

	McsState(StreamAuthenticators AuthenticatorType)
		:
		Custom(0),
		MacKey(0),
		MacTag(0),
		Counter(0),
		Mode(ShakeModes::None),
		Encryption(false),
		Initialized(false)
	{
	}

	~McsState()
	{
		MemoryTools::Clear(Custom, 0, Custom.size());
		MemoryTools::Clear(MacKey, 0, MacKey.size());
		MemoryTools::Clear(MacTag, 0, MacTag.size());
		Counter = 0;
		Mode = ShakeModes::None;
		Encryption = false;
		Initialized = false;
	}

	void Reset()
	{
		MemoryTools::Clear(Custom, 0, Custom.size());
		MemoryTools::Clear(MacKey, 0, MacKey.size());
		MemoryTools::Clear(MacTag, 0, MacTag.size());
		Counter = 0;
		Encryption = false;
		Initialized = false;
	}
};

//~~~Constructor~~~//

MCS::MCS(BlockCiphers CipherType, StreamAuthenticators AuthenticatorType)
	:
	m_mcsState(new McsState(AuthenticatorType)),
	m_cipherMode(CipherType != BlockCiphers::None ? new CTR(CipherType) :
		throw CryptoSymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The Cipher type can not be none!"), ErrorCodes::InvalidParam)),
	m_macAuthenticator(AuthenticatorType == StreamAuthenticators::None ? nullptr :
		Helper::MacFromName::GetInstance(AuthenticatorType)),
	m_parallelProfile(BLOCK_SIZE, m_cipherMode->ParallelProfile().IsParallel(), m_cipherMode->ParallelProfile().ParallelBlockSize(),
		m_cipherMode->ParallelProfile().ParallelMaxDegree(), true, m_cipherMode->Engine()->StateCacheSize(), true)
{
}

MCS::~MCS()
{
	if (m_cipherMode != nullptr)
	{
		m_cipherMode.reset(nullptr);
	}
	if (m_macAuthenticator != nullptr)
	{
		m_macAuthenticator.reset(nullptr);
	}
}

//~~~Accessors~~~//

const StreamCiphers MCS::Enumeral()
{
	StreamAuthenticators auth;
	StreamCiphers tmpn;

	auth = IsAuthenticator() ? static_cast<StreamAuthenticators>(m_macAuthenticator->Enumeral()) : StreamAuthenticators::None;

	switch (m_cipherMode->Engine()->Enumeral())
	{
		case BlockCiphers::AES:
		case BlockCiphers::RHXH256:
		case BlockCiphers::RHXH512:
		case BlockCiphers::RHXS256:
		case BlockCiphers::RHXS512:
		case BlockCiphers::RHXS1024:
		{
			tmpn = StreamCipherConvert::FromDescription(StreamCiphers::MCSR, auth);
			break;
		}
		default:
		{
			tmpn = StreamCipherConvert::FromDescription(StreamCiphers::MCSS, auth);
		}
	}

	return tmpn;
}

const bool MCS::IsAuthenticator()
{
	return (m_macAuthenticator != nullptr);
}

const bool MCS::IsEncryption()
{
	return m_mcsState->Encryption;
}

const bool MCS::IsInitialized()
{
	return m_mcsState->Initialized;
}

const bool MCS::IsParallel()
{
	return m_parallelProfile.IsParallel();
}

const std::vector<SymmetricKeySize> &MCS::LegalKeySizes() 
{
	return m_cipherMode->LegalKeySizes();
}

const std::string MCS::Name()
{
	std::string name;

	name = StreamCipherConvert::ToName(Enumeral());

	return name;
}

const std::vector<byte> MCS::Nonce()
{
	return m_cipherMode->Nonce();
}

const size_t MCS::ParallelBlockSize()
{
	return m_parallelProfile.ParallelBlockSize();
}

ParallelOptions &MCS::ParallelProfile()
{
	return m_parallelProfile;
}

const std::vector<byte> MCS::Tag()
{
	return SecureUnlock(m_mcsState->MacTag);
}

const void MCS::Tag(SecureVector<byte> &Output)
{
	SecureCopy(m_mcsState->MacTag, 0, Output, 0, m_mcsState->MacTag.size());
}

const size_t MCS::TagSize()
{
	return IsAuthenticator() ? m_macAuthenticator->TagSize() : 0;
}

//~~~Public Functions~~~//

void MCS::Initialize(bool Encryption, ISymmetricKey &Parameters)
{
	if (!SymmetricKeySize::Contains(LegalKeySizes(), Parameters.KeySizes().KeySize()))
	{
		throw CryptoSymmetricException(Name(), std::string("Initialize"), std::string("Invalid key size; key must be one of the LegalKeySizes in length."), ErrorCodes::InvalidKey);
	}
	if (Parameters.KeySizes().NonceSize() != m_cipherMode->BlockSize())
	{
		throw CryptoSymmetricException(Name(), std::string("Initialize"), std::string("Requires a nonce equal in size to the ciphers block size!"), ErrorCodes::InvalidNonce);
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
	if (IsInitialized())
	{
		Reset();
	}

	SecureVector<byte> code(0);

	if (Parameters.KeySizes().InfoSize() != 0)
	{
		// custom code
		code.resize(Parameters.KeySizes().InfoSize());
		MemoryTools::Copy(Parameters.Info(), 0, code, 0, code.size());
	}
	else
	{
		// standard
		code.resize(OMEGA_INFO.size());
		MemoryTools::Copy(OMEGA_INFO, 0, code, 0, code.size());
	}

	if (!IsAuthenticator())
	{
		// key the cipher directly 
		Cipher::SymmetricKey kp(Parameters.SecureKey(), Parameters.SecureNonce(), code);
		m_cipherMode->Initialize(true, kp);
	}
	else
	{
		// set the initial counter value
		m_mcsState->Counter = 1;

		// create the cSHAKE customization string
		std::string tmpn = Name();
		m_mcsState->Custom.resize(sizeof(ulong) + tmpn.size());
		// add mac counter and algorithm name to customization string
		IntegerTools::Le64ToBytes(m_mcsState->Counter, m_mcsState->Custom, 0);
		MemoryTools::CopyFromObject(tmpn.data(), m_mcsState->Custom, sizeof(ulong), tmpn.size());

		// initialize cSHAKE with k,c
		m_mcsState->Mode = (Parameters.KeySizes().KeySize() == 64) ? ShakeModes::SHAKE512 : (Parameters.KeySizes().KeySize() == 32) ? ShakeModes::SHAKE256 : ShakeModes::SHAKE1024;
		Kdf::SHAKE gen(m_mcsState->Mode);
		gen.Initialize(Parameters.SecureKey(), m_mcsState->Custom);

		// generate the cipher key
		SecureVector<byte> cprk(Parameters.KeySizes().KeySize());
		gen.Generate(cprk);

		// initialize the cipher
		Cipher::SymmetricKey kp(cprk, Parameters.SecureNonce(), code);
		m_cipherMode->Initialize(true, kp);

		// generate the mac key
		SymmetricKeySize ks = m_macAuthenticator->LegalKeySizes()[1];
		SecureVector<byte> mack(ks.KeySize());
		gen.Generate(mack);
		// initailize the mac
		SymmetricKey kpm(mack);
		m_macAuthenticator->Initialize(kpm);
		// store the key
		m_mcsState->MacKey.resize(mack.size());
		SecureMove(mack, m_mcsState->MacKey, 0);
		m_mcsState->MacTag.resize(TagSize());
	}

	m_mcsState->Encryption = Encryption;
	m_mcsState->Initialized = true;
}

void MCS::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0 || Degree % 2 != 0 || Degree > m_parallelProfile.ProcessorCount())
	{
		throw CryptoSymmetricException(Name(), std::string("ParallelMaxDegree"), std::string("Degree setting is invalid!"), ErrorCodes::NotSupported);
	}

	m_parallelProfile.SetMaxDegree(Degree);
}

void MCS::SetAssociatedData(const std::vector<byte> &Input, size_t Offset, size_t Length)
{
	if (!IsInitialized())
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

void MCS::Transform(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");
	CEXASSERT(IntegerTools::Min(Input.size() - InOffset, Output.size() - OutOffset) >= Length, "The data arrays are smaller than the block-size!");

	if (IsEncryption())
	{
		if (IsAuthenticator())
		{
			if (Output.size() < Length + OutOffset + m_macAuthenticator->TagSize())
			{
				throw CryptoSymmetricException(Name(), std::string("Transform"), std::string("The vector is not long enough to add the MAC code!"), ErrorCodes::InvalidSize);
			}

			// add the starting position of the nonce
			m_macAuthenticator->Update(m_cipherMode->Nonce(), 0, BLOCK_SIZE);
			// encrypt the stream
			m_cipherMode->Transform(Input, InOffset, Output, OutOffset, Length);
			// update the mac with the ciphertext
			m_macAuthenticator->Update(Output, OutOffset, Length);
			// update the mac counter
			m_mcsState->Counter += Length;
			// finalize the mac and add the tag to the stream
			Finalize(m_mcsState, m_macAuthenticator);
			MemoryTools::Copy(m_mcsState->MacTag, 0, Output, OutOffset + Length, m_mcsState->MacTag.size());
		}
		else
		{
			// encrypt the stream
			m_cipherMode->Transform(Input, InOffset, Output, OutOffset, Length);
		}
	}
	else
	{
		if (IsAuthenticator())
		{
			// add the starting position of the nonce
			m_macAuthenticator->Update(m_cipherMode->Nonce(), 0, BLOCK_SIZE);
			// update the mac with the ciphertext
			m_macAuthenticator->Update(Input, InOffset, Length);
			// update the mac counter
			m_mcsState->Counter += Length;
			// finalize the mac and verify
			Finalize(m_mcsState, m_macAuthenticator);

			if (!IntegerTools::Compare(Input, InOffset + Length, m_mcsState->MacTag, 0, m_mcsState->MacTag.size()))
			{
				throw CryptoAuthenticationFailure(Name(), std::string("Transform"), std::string("The authentication tag does not match!"), ErrorCodes::AuthenticationFailure);
			}
		}

		// decrypt the stream
		m_cipherMode->Transform(Input, InOffset, Output, OutOffset, Length);
	}
}

//~~~Private Functions~~~//

void MCS::Finalize(std::unique_ptr<McsState> &State, std::unique_ptr<IMac> &Authenticator)
{
	// generate the mac code
	Authenticator->Finalize(State->MacTag, 0);

	// customization string is: mac counter + algorithm name
	IntegerTools::Le64ToBytes(State->Counter, State->Custom, 0);

	// extract the new mac key
	Kdf::SHAKE gen(State->Mode);
	gen.Initialize(State->MacKey, State->Custom);
	SymmetricKeySize ks = Authenticator->LegalKeySizes()[1];
	SecureVector<byte> mack(ks.KeySize());
	gen.Generate(mack);

	// reset the generator with the new key
	SymmetricKey kpm(mack);
	Authenticator->Initialize(kpm);
	// store the new key and erase the temporary key
	SecureMove(mack, State->MacKey, 0);
}

void MCS::Reset()
{
	m_mcsState->Reset();

	if (IsAuthenticator())
	{
		m_macAuthenticator->Reset();
	}

	m_cipherMode->ParallelProfile().Calculate(m_parallelProfile.IsParallel(), m_parallelProfile.ParallelBlockSize(), m_parallelProfile.ParallelMaxDegree());
}

NAMESPACE_STREAMEND
