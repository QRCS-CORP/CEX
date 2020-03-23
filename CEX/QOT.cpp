#include "QOT.h"
#include "CpuDetect.h"
#include "IntegerTools.h"
#include "MacFromName.h"
#include "MemoryTools.h"
#include "Rijndael.h"
#include "SHAKE.h"

/*
* Notes
* 2 keys? 512/1024.. using SHAKE and KMAC 512/1024
* Decide on a new rounds shuffle matrix for ShiftRows512
* Should a new SBox be calculated? No, because AES-NI not possible if sbox changed
* Change SHAKE/KMAC-1024 to a fixed 36-byte rate and double rounds (CEX_SHAKE_STRONG)
* Rounds count: 256=40, 512=80, 1024=120
* Remove offset in counter
* Examine authentication and key generation for improvements
* 
* 
* ...
*/

NAMESPACE_STREAM

// Quia Omni Tempore - 'for all of time' 
// JGU, Feb 07 2020

using namespace Cipher::Block::RijndaelBase;
using Utility::IntegerTools;
using Utility::MemoryTools;
using Enumeration::ShakeModes;
using Enumeration::StreamCipherConvert;

const std::vector<byte> QOT::QOT_INFO =
{
	0x52, 0x43, 0x53, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, 0x20, 0x31, 0x2E, 0x30, 0x63
};

class QOT::QotState
{
public:

	SecureVector<uint> RoundKeys;
	SecureVector<byte> Associated;
	SecureVector<byte> Custom;
	SecureVector<byte> MacKey;
	SecureVector<byte> MacTag;
	SecureVector<byte> Name;
	std::vector<byte> Nonce;
	ulong Counter;
	ushort Rounds;
	StreamAuthenticators Authenticator;
	ShakeModes Mode;
	bool Encryption;
	bool Initialized;

	QotState()
		:
		RoundKeys(0),
		Associated(0),
		Custom(0),
		MacKey(0),
		MacTag(0),
		Name(0),
		Nonce(BLOCK_SIZE, 0x00),
		Counter(0),
		Rounds(0),
		Authenticator(StreamAuthenticators::None),
		Mode(ShakeModes::None),
		Encryption(false),
		Initialized(false)
	{
	}

	QotState(SecureVector<byte> &State)
		:
		RoundKeys(0),
		Associated(0),
		Custom(0),
		MacKey(0),
		MacTag(0),
		Name(0),
		Nonce(BLOCK_SIZE, 0x00),
		Counter(0),
		Rounds(0),
		Authenticator(StreamAuthenticators::None),
		Mode(ShakeModes::None),
		Encryption(false),
		Initialized(false)
	{
		DeSerialize(State);
	}

	~QotState()
	{
		MemoryTools::Clear(RoundKeys, 0, RoundKeys.size() * sizeof(uint));
		MemoryTools::Clear(Associated, 0, Associated.size());
		MemoryTools::Clear(Custom, 0, Custom.size());
		MemoryTools::Clear(MacKey, 0, MacKey.size());
		MemoryTools::Clear(MacTag, 0, MacTag.size());
		MemoryTools::Clear(Name, 0, Name.size());
		MemoryTools::Clear(Nonce, 0, Nonce.size());

		Counter = 0;
		Rounds = 0;
		Authenticator = StreamAuthenticators::None;
		Mode = ShakeModes::None;
		Encryption = false;
		Initialized = false;
	}

	void DeSerialize(SecureVector<byte> &SecureState)
	{
		size_t soff;
		ushort vlen;

		soff = 0;

		MemoryTools::CopyToObject(SecureState, soff, &vlen, sizeof(ushort));
		RoundKeys.resize(vlen / sizeof(uint));
		soff += sizeof(ushort);
		MemoryTools::Copy(SecureState, soff, RoundKeys, 0, vlen);
		soff += vlen;

		MemoryTools::CopyToObject(SecureState, soff, &vlen, sizeof(ushort));
		Associated.resize(vlen);
		soff += sizeof(ushort);
		MemoryTools::Copy(SecureState, soff, Associated, 0, Associated.size());
		soff += vlen;

		MemoryTools::CopyToObject(SecureState, soff, &vlen, sizeof(ushort));
		Custom.resize(vlen);
		soff += sizeof(ushort);
		MemoryTools::Copy(SecureState, soff, Custom, 0, Custom.size());
		soff += vlen;

		MemoryTools::CopyToObject(SecureState, soff, &vlen, sizeof(ushort));
		MacKey.resize(vlen);
		soff += sizeof(ushort);
		MemoryTools::Copy(SecureState, soff, MacKey, 0, MacKey.size());
		soff += vlen;

		MemoryTools::CopyToObject(SecureState, soff, &vlen, sizeof(ushort));
		MacTag.resize(vlen);
		soff += sizeof(ushort);
		MemoryTools::Copy(SecureState, soff, MacTag, 0, MacTag.size());
		soff += vlen;

		MemoryTools::CopyToObject(SecureState, soff, &vlen, sizeof(ushort));
		Name.resize(vlen);
		soff += sizeof(ushort);
		MemoryTools::Copy(SecureState, soff, Name, 0, Name.size());
		soff += vlen;

		MemoryTools::CopyToObject(SecureState, soff, &vlen, sizeof(ushort));
		Nonce.resize(vlen);
		soff += sizeof(ushort);
		MemoryTools::Copy(SecureState, soff, Nonce, 0, Nonce.size());
		soff += vlen;

		MemoryTools::CopyToObject(SecureState, soff, &Counter, sizeof(ulong));
		soff += sizeof(ulong);
		MemoryTools::CopyToObject(SecureState, soff, &Rounds, sizeof(ushort));
		soff += sizeof(ushort);

		MemoryTools::CopyToObject(SecureState, soff, &Authenticator, sizeof(StreamAuthenticators));
		soff += sizeof(StreamAuthenticators);
		MemoryTools::CopyToObject(SecureState, soff, &Mode, sizeof(ShakeModes));
		soff += sizeof(ShakeModes);

		MemoryTools::CopyToObject(SecureState, soff, &Encryption, sizeof(bool));
		soff += sizeof(bool);
		MemoryTools::CopyToObject(SecureState, soff, &Initialized, sizeof(bool));
	}

	void Reset()
	{
		MemoryTools::Clear(RoundKeys, 0, RoundKeys.size() * sizeof(uint));
		MemoryTools::Clear(Associated, 0, Associated.size());
		MemoryTools::Clear(Custom, 0, Custom.size());
		MemoryTools::Clear(MacKey, 0, MacKey.size());
		MemoryTools::Clear(MacTag, 0, MacTag.size());
		MemoryTools::Clear(Name, 0, Name.size());
		MemoryTools::Clear(Nonce, 0, Nonce.size());

		Counter = 0;
		Rounds = 0;
		Encryption = false;
		Initialized = false;
	}

	SecureVector<byte> Serialize()
	{
		const size_t STASZE = (RoundKeys.size() * sizeof(uint)) + Associated.size() + Custom.size() + MacKey.size() + MacTag.size() +
			Name.size() + Nonce.size() + sizeof(ulong) + sizeof(ushort) + sizeof(StreamAuthenticators) + sizeof(ShakeModes) + (2 * sizeof(bool)) + (7 * sizeof(ushort));

		size_t soff;
		ushort vlen;
		SecureVector<byte> state(STASZE);

		soff = 0;
		vlen = static_cast<ushort>(RoundKeys.size() * sizeof(uint));
		MemoryTools::CopyFromObject(&vlen, state, soff, sizeof(ushort));
		soff += sizeof(ushort);
		MemoryTools::Copy(RoundKeys, 0, state, soff, static_cast<size_t>(vlen));
		soff += vlen;

		vlen = static_cast<ushort>(Associated.size());
		MemoryTools::CopyFromObject(&vlen, state, soff, sizeof(ushort));
		soff += sizeof(ushort);
		MemoryTools::Copy(Associated, 0, state, soff, Associated.size());
		soff += Associated.size();

		vlen = static_cast<ushort>(Custom.size());
		MemoryTools::CopyFromObject(&vlen, state, soff, sizeof(ushort));
		soff += sizeof(ushort);
		MemoryTools::Copy(Custom, 0, state, soff, Custom.size());
		soff += Custom.size();

		vlen = static_cast<ushort>(MacKey.size());
		MemoryTools::CopyFromObject(&vlen, state, soff, sizeof(ushort));
		soff += sizeof(ushort);
		MemoryTools::Copy(MacKey, 0, state, soff, MacKey.size());
		soff += MacKey.size();

		vlen = static_cast<ushort>(MacTag.size());
		MemoryTools::CopyFromObject(&vlen, state, soff, sizeof(ushort));
		soff += sizeof(ushort);
		MemoryTools::Copy(MacTag, 0, state, soff, MacTag.size());
		soff += MacTag.size();

		vlen = static_cast<ushort>(Name.size());
		MemoryTools::CopyFromObject(&vlen, state, soff, sizeof(ushort));
		soff += sizeof(ushort);
		MemoryTools::Copy(Name, 0, state, soff, Name.size());
		soff += Name.size();

		vlen = static_cast<ushort>(Nonce.size());
		MemoryTools::CopyFromObject(&vlen, state, soff, sizeof(ushort));
		soff += sizeof(ushort);
		MemoryTools::Copy(Nonce, 0, state, soff, Nonce.size());
		soff += Nonce.size();

		MemoryTools::CopyFromObject(&Counter, state, soff, sizeof(ulong));
		soff += sizeof(ulong);
		MemoryTools::CopyFromObject(&Rounds, state, soff, sizeof(ushort));
		soff += sizeof(ushort);

		MemoryTools::CopyFromObject(&Authenticator, state, soff, sizeof(StreamAuthenticators));
		soff += sizeof(StreamAuthenticators);
		MemoryTools::CopyFromObject(&Mode, state, soff, sizeof(ShakeModes));
		soff += sizeof(ShakeModes);

		MemoryTools::CopyFromObject(&Encryption, state, soff, sizeof(bool));
		soff += sizeof(bool);
		MemoryTools::CopyFromObject(&Initialized, state, soff, sizeof(bool));

		return state;
	}
};

//~~~Constructor~~~//

QOT::QOT(StreamAuthenticators AuthenticatorType)
	:
	m_qotState(new QotState()),
	m_legalKeySizes{
		SymmetricKeySize(32, BLOCK_SIZE, INFO_SIZE),
		SymmetricKeySize(64, BLOCK_SIZE, INFO_SIZE),
		SymmetricKeySize(128, BLOCK_SIZE, INFO_SIZE) },
	m_macAuthenticator(AuthenticatorType == StreamAuthenticators::None ? nullptr :
		Helper::MacFromName::GetInstance(AuthenticatorType)),
	m_parallelProfile(BLOCK_SIZE, true, STATE_PRECACHED, true)
{
}

QOT::QOT(SecureVector<byte> &State)
	:
	m_qotState(State.size() > STATE_THRESHOLD ? new QotState(State) :
		throw CryptoSymmetricException(std::string("QOT"), std::string("Constructor"), std::string("The State array is invalid!"), ErrorCodes::InvalidKey)),
	m_legalKeySizes{
		SymmetricKeySize(32, BLOCK_SIZE, INFO_SIZE),
		SymmetricKeySize(64, BLOCK_SIZE, INFO_SIZE),
		SymmetricKeySize(128, BLOCK_SIZE, INFO_SIZE) },
	m_macAuthenticator(Helper::MacFromName::GetInstance(m_qotState->Authenticator)),
	m_parallelProfile(BLOCK_SIZE, true, STATE_PRECACHED, true)
{
	if (m_qotState->Authenticator != StreamAuthenticators::None)
	{
		// initialize the mac
		SymmetricKey kpm(m_qotState->MacKey);
		m_macAuthenticator->Initialize(kpm);
	}
}

QOT::~QOT()
{
	if (m_macAuthenticator != nullptr)
	{
		m_macAuthenticator.reset(nullptr);
	}
}

//~~~Accessors~~~//

const StreamCiphers QOT::Enumeral()
{
	StreamAuthenticators auth;
	StreamCiphers tmpn;

	auth = IsAuthenticator() ? static_cast<StreamAuthenticators>(m_macAuthenticator->Enumeral()) : StreamAuthenticators::None;
	tmpn = StreamCipherConvert::FromDescription(StreamCiphers::RCS, auth);

	return tmpn;
}

const bool QOT::IsAuthenticator()
{
	return (m_macAuthenticator != nullptr);
}

const bool QOT::IsEncryption()
{
	return m_qotState->Encryption;
}

const bool QOT::IsInitialized()
{
	return m_qotState->Initialized;
}

const bool QOT::IsParallel()
{
	return m_parallelProfile.IsParallel();
}

const std::vector<SymmetricKeySize> &QOT::LegalKeySizes()
{
	return m_legalKeySizes;
}

const std::string QOT::Name()
{
	std::string name;

	name = StreamCipherConvert::ToName(Enumeral());

	return name;
}

const std::vector<byte> QOT::Nonce()
{
	return m_qotState->Nonce;
}

const size_t QOT::ParallelBlockSize()
{
	return m_parallelProfile.ParallelBlockSize();
}

ParallelOptions &QOT::ParallelProfile()
{
	return m_parallelProfile;
}

const std::vector<byte> QOT::Tag()
{
	return SecureUnlock(m_qotState->MacTag);
}

const void QOT::Tag(SecureVector<byte> &Output)
{
	SecureCopy(m_qotState->MacTag, 0, Output, 0, m_qotState->MacTag.size());
}

const size_t QOT::TagSize()
{
	return IsAuthenticator() ? m_macAuthenticator->TagSize() : 0;
}

//~~~Public Functions~~~//

void QOT::Initialize(bool Encryption, ISymmetricKey &Parameters)
{
	size_t i;

	if (!SymmetricKeySize::Contains(LegalKeySizes(), Parameters.KeySizes().KeySize()))
	{
		throw CryptoSymmetricException(Name(), std::string("Initialize"), std::string("Invalid key size; key must be one of the LegalKeySizes in length."), ErrorCodes::InvalidKey);
	}
	if (Parameters.KeySizes().NonceSize() != BLOCK_SIZE)
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

	// set up the state members
	m_qotState->Authenticator = (m_macAuthenticator != nullptr) ? 
		static_cast<StreamAuthenticators>(m_macAuthenticator->Enumeral()) : 
		StreamAuthenticators::None;
	// cipher key size determines key expansion function and Mac generator type; 512 or 1024-bit
	m_qotState->Mode = (Parameters.KeySizes().KeySize() == 1024) ? 
		ShakeModes::SHAKE1024 : 
		(Parameters.KeySizes().KeySize() == 512) ? 
			ShakeModes::SHAKE512 :
			ShakeModes::SHAKE256;
	// set the number of rounds
	m_qotState->Rounds = (Parameters.KeySizes().KeySize() == 1024) ?
		QOTX3_ROUNDS :
		(Parameters.KeySizes().KeySize() == 512) ?
		QOTX2_ROUNDS :
		QOTX1_ROUNDS;
	// set the initial processed-bytes count to zero
	m_qotState->Counter = 0;

	// create the cSHAKE customization string
	m_qotState->Custom.resize(Parameters.KeySizes().InfoSize() + QOT_INFO.size());
	// copy the version string to the customization parameter
	MemoryTools::Copy(QOT_INFO, 0, m_qotState->Custom, 0, QOT_INFO.size());
	// copy the user defined string to the customization parameter
	MemoryTools::Copy(Parameters.Info(), 0, m_qotState->Custom, QOT_INFO.size(), Parameters.KeySizes().InfoSize());

	// create the cSHAKE name string
	std::string tmpn = Name();
	// add mac counter, key-size bits, and algorithm name to name string
	m_qotState->Name.resize(sizeof(ulong) + sizeof(ushort) + tmpn.size());
	// mac counter is always first 8 bytes
	IntegerTools::Le64ToBytes(m_qotState->Counter, m_qotState->Name, 0);
	// add the cipher key size in bits as an unsigned short integer
	ushort kbits = static_cast<ushort>(Parameters.KeySizes().KeySize() * 8);
	IntegerTools::Le16ToBytes(kbits, m_qotState->Name, sizeof(ulong));
	// copy the name string to state
	MemoryTools::CopyFromObject(tmpn.data(), m_qotState->Name, sizeof(ulong) + sizeof(ushort), tmpn.size());

	// copy the nonce to state
	MemoryTools::Copy(Parameters.Nonce(), 0, m_qotState->Nonce, 0, BLOCK_SIZE);

	Kdf::SHAKE gen(m_qotState->Mode);
	// initialize cSHAKE with k,c,n
	gen.Initialize(Parameters.SecureKey(), m_qotState->Custom, m_qotState->Name);

	// size the round key array
	const size_t RNKLEN = (BLOCK_SIZE / sizeof(uint)) * (m_qotState->Rounds + 1U);
	m_qotState->RoundKeys.resize(RNKLEN);
	// generate the round keys to a temporary byte array
	SecureVector<byte> tmpr(RNKLEN * sizeof(uint));
	// generate the ciphers round-keys
	gen.Generate(tmpr);

	// realign in big endian format for ACS test vectors; QOT is the fallback to the AES-NI implementation
	for (i = 0; i < tmpr.size() / sizeof(uint); ++i)
	{
		m_qotState->RoundKeys[i] = IntegerTools::BeBytesTo32(tmpr, i * sizeof(uint));
	}

	MemoryTools::Clear(tmpr, 0, tmpr.size());

	if (IsAuthenticator()) 
	{
		// generate the mac key
		SymmetricKeySize ks = m_macAuthenticator->LegalKeySizes()[1];
		SecureVector<byte> mack(ks.KeySize());
		gen.Generate(mack);
		// initialize the mac
		SymmetricKey kpm(mack);
		m_macAuthenticator->Initialize(kpm);
		// store the key
		m_qotState->MacKey.resize(mack.size());
		SecureMove(mack, m_qotState->MacKey, 0);
		m_qotState->MacTag.resize(TagSize());
	}

	m_qotState->Encryption = Encryption;
	m_qotState->Initialized = true;
}

void QOT::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0 || Degree % 2 != 0 || Degree > m_parallelProfile.ProcessorCount())
	{
		throw CryptoSymmetricException(Name(), std::string("ParallelMaxDegree"), std::string("Degree setting is invalid!"), ErrorCodes::NotSupported);
	}

	m_parallelProfile.SetMaxDegree(Degree);
}

void QOT::SetAssociatedData(const std::vector<byte> &Input, size_t Offset, size_t Length)
{
	if (!IsInitialized())
	{
		throw CryptoSymmetricException(Name(), std::string("SetAssociatedData"), std::string("The cipher has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (m_macAuthenticator == nullptr)
	{
		throw CryptoSymmetricException(Name(), std::string("SetAssociatedData"), std::string("The cipher has not been configured for authentication!"), ErrorCodes::IllegalOperation);
	}

	// store the associated data
	m_qotState->Associated.resize(Length);
	MemoryTools::Copy(Input, Offset, m_qotState->Associated, 0, Length);
}

void QOT::Transform(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length)
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
			m_macAuthenticator->Update(m_qotState->Nonce, 0, BLOCK_SIZE);
			// encrypt the stream
			Process(Input, InOffset, Output, OutOffset, Length);
			// update the mac with the ciphertext
			m_macAuthenticator->Update(Output, OutOffset, Length);
			// update the processed bytes counter
			m_qotState->Counter += Length;
			// finalize the mac and copy the tag to the end of the output stream
			Finalize(m_qotState, m_macAuthenticator);
			MemoryTools::Copy(m_qotState->MacTag, 0, Output, OutOffset + Length, m_qotState->MacTag.size());
		}
		else
		{
			// encrypt the stream
			Process(Input, InOffset, Output, OutOffset, Length);
		}
	}
	else
	{
		if (IsAuthenticator())
		{
			// add the starting position of the nonce
			m_macAuthenticator->Update(m_qotState->Nonce, 0, BLOCK_SIZE);
			// update the mac with the ciphertext
			m_macAuthenticator->Update(Input, InOffset, Length);
			// update the processed bytes counter
			m_qotState->Counter += Length;
			// finalize the mac and verify
			Finalize(m_qotState, m_macAuthenticator);

			if (!IntegerTools::Compare(Input, InOffset + Length, m_qotState->MacTag, 0, m_qotState->MacTag.size()))
			{
				throw CryptoAuthenticationFailure(Name(), std::string("Transform"), std::string("The authentication tag does not match!"), ErrorCodes::AuthenticationFailure);
			}
		}

		// decrypt the stream
		Process(Input, InOffset, Output, OutOffset, Length);
	}
}

//~~~Private Functions~~~//

void QOT::Finalize(std::unique_ptr<QotState> &State, std::unique_ptr<IMac> &Authenticator)
{
	std::vector<byte> mctr(sizeof(ulong));
	ulong mlen;

	// 1.0c: add the total number of bytes processed by the mac, including this terminating string
	mlen = State->Counter + State->Nonce.size() + State->Associated.size() + mctr.size();
	IntegerTools::LeIncrease8(mctr, mlen);

	// 1.0c: add the associated data to the mac
	if (State->Associated.size() != 0)
	{
		Authenticator->Update(SecureUnlock(State->Associated), 0, State->Associated.size());
		// clear the associated data, reset for each transformation, 
		// assignable with a call to SetAssociatedData before each transform call
		SecureClear(State->Associated);
	}

	// add the termination string to the mac
	Authenticator->Update(mctr, 0, mctr.size());

	// finalize the mac code to state
	Authenticator->Finalize(State->MacTag, 0);

	// re-initialize the mac function
	// name string is an unsigned 64-bit bytes counter + key-size + cipher-name
	// the state counter is the total number of bytes processed by the cipher
	IntegerTools::Le64ToBytes(State->Counter, State->Name, 0);

	// extract the new mac key: cSHAKE(k,c,n)
	Kdf::SHAKE gen(State->Mode);
	gen.Initialize(State->MacKey, State->Custom, State->Name);
	SymmetricKeySize ks = Authenticator->LegalKeySizes()[1];
	SecureVector<byte> mack(ks.KeySize());
	// generate the new key
	gen.Generate(mack);

	// re-initialize the mac generator with the new key
	SymmetricKey kpm(mack);
	Authenticator->Initialize(kpm);
	// store the new key and erase the temporary key
	SecureMove(mack, State->MacKey, 0);
}

void QOT::Generate(std::vector<byte> &Output, size_t OutOffset, size_t Length, std::vector<byte> &Counter)
{
	size_t bctr;

	bctr = 0;

#if defined(__AVX512__)

	const size_t AVX512BLK = 16 * BLOCK_SIZE;

	if (Length >= AVX512BLK)
	{
		const size_t PBKALN = Length - (Length % AVX512BLK);
		std::vector<byte> tmpc(AVX512BLK);

		// stagger counters and process 8 blocks with avx512
		while (bctr != PBKALN)
		{
			MemoryTools::Copy(Counter, 0, tmpc, 0, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 32, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 64, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 96, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 128, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 160, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 192, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 224, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 256, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 288, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 320, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 352, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 384, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 416, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 448, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 480, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			Transform4096(tmpc, 0, Output, OutOffset + bctr);
			bctr += AVX512BLK;
		}
	}

#elif defined(__AVX2__)

	const size_t AVX2BLK = 8 * BLOCK_SIZE;

	if (Length >= AVX2BLK)
	{
		const size_t PBKALN = Length - (Length % AVX2BLK);
		std::vector<byte> tmpc(AVX2BLK);

		// stagger counters and process 8 blocks with avx2
		while (bctr != PBKALN)
		{
			MemoryTools::Copy(Counter, 0, tmpc, 0, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 32, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 64, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 96, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 128, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 160, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 192, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 224, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			Transform2048(tmpc, 0, Output, OutOffset + bctr);
			bctr += AVX2BLK;
		}
	}

#elif defined(__AVX__)

	const size_t AVXBLK = 4 * BLOCK_SIZE;

	if (Length >= AVXBLK)
	{
		const size_t PBKALN = Length - (Length % AVXBLK);
		std::vector<byte> tmpc(AVXBLK);

		// 4 blocks with avx
		while (bctr != PBKALN)
		{
			MemoryTools::Copy(Counter, 0, tmpc, 0, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 32, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 64, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 96, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			Transform1024(tmpc, 0, Output, OutOffset + bctr);
			bctr += AVXBLK;
		}
	}

#endif

	const size_t BLKALN = Length - (Length % BLOCK_SIZE);

	while (bctr != BLKALN)
	{
		Transform512(Counter, 0, Output, OutOffset + bctr);
		IntegerTools::LeIncrement(Counter, 16);
		bctr += BLOCK_SIZE;
	}

	if (bctr != Length)
	{
		std::vector<byte> otp(BLOCK_SIZE);
		Transform512(Counter, 0, otp, 0);
		IntegerTools::LeIncrement(Counter, 16);
		const size_t RMDLEN = Length % BLOCK_SIZE;
		MemoryTools::Copy(otp, 0, Output, OutOffset + (Length - RMDLEN), RMDLEN);
	}
}

CEX_OPTIMIZE_IGNORE
void QOT::PrefetchRoundKey(const SecureVector<uint> &Rkey)
{
	// timing defence: pre-load the round-key array into l1 cache
	MemoryTools::PrefetchL1(Rkey, 0, Rkey.size() * sizeof(uint));
}
CEX_OPTIMIZE_RESUME

CEX_OPTIMIZE_IGNORE
void QOT::PrefetchSbox()
{
	// timing defence: pre-load sbox into l1 cache
	MemoryTools::PrefetchL1(SBox, 0, SBox.size());
}
CEX_OPTIMIZE_RESUME

void QOT::Process(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	size_t i;

	const size_t PRLBLK = m_parallelProfile.ParallelBlockSize();

	if (m_parallelProfile.IsParallel() && Length >= PRLBLK)
	{
		const size_t BLKCNT = Length / PRLBLK;

		for (i = 0; i < BLKCNT; ++i)
		{
			ProcessParallel(Input, InOffset + (i * PRLBLK), Output, OutOffset + (i * PRLBLK), PRLBLK);
		}

		const size_t RMDLEN = Length - (PRLBLK * BLKCNT);

		if (RMDLEN != 0)
		{
			const size_t BLKOFT = (PRLBLK * BLKCNT);
			ProcessSequential(Input, InOffset + BLKOFT, Output, OutOffset + BLKOFT, RMDLEN);
		}
	}
	else
	{
		ProcessSequential(Input, InOffset, Output, OutOffset, Length);
	}
}

void QOT::ProcessParallel(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	const size_t OUTLEN = Output.size() - OutOffset < Length ? Output.size() - OutOffset : Length;
	const size_t CNKLEN = m_parallelProfile.ParallelBlockSize() / m_parallelProfile.ParallelMaxDegree();
	const size_t CTRLEN = (CNKLEN / BLOCK_SIZE);
	std::vector<byte> tmpc(BLOCK_SIZE);

	Utility::ParallelTools::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Input, InOffset, &Output, OutOffset, &tmpc, CNKLEN, CTRLEN](size_t i)
		{
			// thread level counter
			std::vector<byte> thdc(BLOCK_SIZE);
			// offset counter by chunk size / block size  
			IntegerTools::LeIncrease8(m_qotState->Nonce, thdc, static_cast<uint>(CTRLEN * i));
			const size_t STMPOS = i * CNKLEN;
			// generate random at output offset
			this->Generate(Output, OutOffset + STMPOS, CNKLEN, thdc);
			// xor with input at offsets
			MemoryTools::XOR(Input, InOffset + STMPOS, Output, OutOffset + STMPOS, CNKLEN);

			// store last counter
			if (i == m_parallelProfile.ParallelMaxDegree() - 1)
			{
				MemoryTools::Copy(thdc, 0, tmpc, 0, BLOCK_SIZE);
			}
		});

	// copy last counter to class variable
	MemoryTools::Copy(tmpc, 0, m_qotState->Nonce, 0, BLOCK_SIZE);

	// last block processing
	const size_t ALNLEN = CNKLEN * m_parallelProfile.ParallelMaxDegree();
	if (ALNLEN < OUTLEN)
	{
		const size_t FNLLEN = (Output.size() - OutOffset) % ALNLEN;
		Generate(Output, ALNLEN, FNLLEN, m_qotState->Nonce);

		for (size_t i = ALNLEN; i < OUTLEN; i++)
		{
			Output[i] ^= Input[i];
		}
	}
}

void QOT::ProcessSequential(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	// get block aligned
	const size_t ALNLEN = Length - (Length % BLOCK_SIZE);
	size_t i;

	// generate random
	Generate(Output, OutOffset, Length, m_qotState->Nonce);

	if (ALNLEN != 0)
	{
		MemoryTools::XOR(Input, InOffset, Output, OutOffset, ALNLEN);
	}

	// get the remaining bytes
	if (ALNLEN != Length)
	{
		for (i = ALNLEN; i < Length; ++i)
		{
			Output[i + OutOffset] ^= Input[i + InOffset];
		}
	}
}

void QOT::Reset()
{
	m_qotState->Reset();

	if (IsAuthenticator())
	{
		m_macAuthenticator->Reset();
	}

	m_parallelProfile.Calculate(m_parallelProfile.IsParallel(), m_parallelProfile.ParallelBlockSize(), m_parallelProfile.ParallelMaxDegree());
}

SecureVector<byte> QOT::Serialize()
{
	SecureVector<byte> tmps = m_qotState->Serialize();

	return tmps;
}

void QOT::Transform512(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	SecureVector<byte> state(BLOCK_SIZE, 0x00);
	size_t i;

	MemoryTools::Copy(Input, InOffset, state, 0, BLOCK_SIZE);
	KeyAddition(state, m_qotState->RoundKeys, 0);

	// pre-load the s-box into L1 cache
#if defined(CEX_PREFETCH_RHX_TABLES)
	PrefetchSbox();
#endif

	for (i = 1; i < m_qotState->Rounds; ++i)
	{
		Substitution(state);
		ShiftRows512(state); // TODO
		MixColumns(state);
		KeyAddition(state, m_qotState->RoundKeys, (i << 4));
	}

	Substitution(state);
	ShiftRows512(state);
	KeyAddition(state, m_qotState->RoundKeys, (m_qotState->Rounds << 4));

	MemoryTools::Copy(state, 0, Output, OutOffset, BLOCK_SIZE);
}

void QOT::Transform1024(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	Transform512(Input, InOffset, Output, OutOffset);
	Transform512(Input, InOffset + 64, Output, OutOffset + 64);
}

void QOT::Transform2048(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	Transform1024(Input, InOffset, Output, OutOffset);
	Transform1024(Input, InOffset + 128, Output, OutOffset + 128);
}

void QOT::Transform4096(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	Transform2048(Input, InOffset, Output, OutOffset);
	Transform2048(Input, InOffset + 256, Output, OutOffset + 256);
}

NAMESPACE_STREAMEND
