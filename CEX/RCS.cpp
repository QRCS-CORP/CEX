#include "RCS.h"
#include "CpuDetect.h"
#include "IntegerTools.h"
#include "MacFromName.h"
#include "MemoryTools.h"
#include "Rijndael.h"
#include "SHAKE.h"
#include "SymmetricKey.h"
#if defined(__AVX__)
#	include <wmmintrin.h>
#endif


NAMESPACE_STREAM

using namespace Cipher::Block::RijndaelBase;
using Enumeration::BlockCipherConvert;
using Utility::IntegerTools;
using Utility::MemoryTools;
using Enumeration::ShakeModes;
using Enumeration::StreamAuthenticatorConvert;
using Cipher::SymmetricKey;

const std::vector<byte> RCS::OMEGA_INFO = { 0x52, 0x43, 0x53, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, 0x20, 0x31, 0x2E, 0x30, 0x61 };

class RCS::RcsState
{
public:

	SecureVector<uint> RoundKeys;
	SecureVector<byte> Custom;
	std::vector<byte> Nonce;
	SecureVector<byte> MacKey;
	SecureVector<byte> MacTag;
	ulong Counter;
	size_t Rounds;
	ShakeModes Mode;
	bool Encryption;
	bool Initialized;

	RcsState(StreamAuthenticators AuthenticatorType)
		:
		RoundKeys(0),
		Custom(0),
		MacKey(0),
		MacTag(0),
		Nonce(BLOCK_SIZE, 0x00),
		Counter(0),
		Rounds(0),
		Mode(ShakeModes::None),
		Encryption(false),
		Initialized(false)
	{
	}

	~RcsState()
	{
		MemoryTools::Clear(RoundKeys, 0, RoundKeys.size() * sizeof(uint));
		MemoryTools::Clear(Custom, 0, Custom.size());
		MemoryTools::Clear(MacKey, 0, MacKey.size());
		MemoryTools::Clear(MacTag, 0, MacTag.size());
		MemoryTools::Clear(Nonce, 0, Nonce.size());
		Counter = 0;
		Rounds = 0;
		Mode = ShakeModes::None;
		Encryption = false;
		Initialized = false;
	}

	void Reset()
	{
		MemoryTools::Clear(RoundKeys, 0, RoundKeys.size() * sizeof(uint));
		MemoryTools::Clear(Custom, 0, Custom.size());
		MemoryTools::Clear(MacKey, 0, MacKey.size());
		MemoryTools::Clear(MacTag, 0, MacTag.size());
		MemoryTools::Clear(Nonce, 0, Nonce.size());
		Counter = 0;
		Encryption = false;
		Initialized = false;
	}
};

//~~~Constructor~~~//

RCS::RCS(StreamAuthenticators AuthenticatorType)
	:
	m_rcsState(new RcsState(AuthenticatorType)),
	m_legalKeySizes { 
		SymmetricKeySize(32, BLOCK_SIZE, INFO_SIZE),
		SymmetricKeySize(64, BLOCK_SIZE, INFO_SIZE),
		SymmetricKeySize(128, BLOCK_SIZE, INFO_SIZE)},
	m_macAuthenticator(AuthenticatorType == StreamAuthenticators::None ? nullptr :
		Helper::MacFromName::GetInstance(AuthenticatorType)),
	m_parallelProfile(BLOCK_SIZE, true, STATE_PRECACHED, true)
{
}

RCS::~RCS()
{
	if (m_macAuthenticator != nullptr)
	{
		m_macAuthenticator.reset(nullptr);
	}
}

//~~~Accessors~~~//

const StreamCiphers RCS::Enumeral()
{
	StreamAuthenticators auth;
	StreamCiphers tmpn;

	auth = IsAuthenticator() ? static_cast<StreamAuthenticators>(m_macAuthenticator->Enumeral()) : StreamAuthenticators::None;
	tmpn = Enumeration::StreamCipherConvert::FromDescription(StreamCiphers::RCS, auth);

	return tmpn;
}

const bool RCS::IsAuthenticator()
{
	return (m_macAuthenticator != nullptr);
}

const bool RCS::IsEncryption()
{
	return m_rcsState->Encryption;
}

const bool RCS::IsInitialized()
{
	return m_rcsState->Initialized;
}

const bool RCS::IsParallel()
{
	return m_parallelProfile.IsParallel();
}

const std::vector<SymmetricKeySize> &RCS::LegalKeySizes()
{
	return m_legalKeySizes;
}

const std::string RCS::Name()
{
	std::string name;

	name = Enumeration::StreamCipherConvert::ToName(Enumeral());

	return name;
}

const size_t RCS::ParallelBlockSize()
{
	return m_parallelProfile.ParallelBlockSize();
}

ParallelOptions &RCS::ParallelProfile()
{
	return m_parallelProfile;
}

const std::vector<byte> RCS::Tag()
{
	return Unlock(m_rcsState->MacTag);
}

const void RCS::Tag(SecureVector<byte> &Output)
{
	Copy(m_rcsState->MacTag, 0, Output, 0, m_rcsState->MacTag.size());
}

const size_t RCS::TagSize()
{
	return IsAuthenticator() ? m_macAuthenticator->TagSize() : 0;
}

//~~~Public Functions~~~//

void RCS::Initialize(bool Encryption, ISymmetricKey &Parameters)
{
	size_t i;
	uint tmpbk;

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

	// set the initial counter value
	m_rcsState->Counter = 1;
	m_rcsState->Rounds = Parameters.KeySizes().KeySize() != 128 ? (Parameters.KeySizes().KeySize() / 4) + 14 : 38;
	// create the cSHAKE customization string
	std::string tmpn = Name();
	m_rcsState->Custom.resize(sizeof(ulong) + sizeof(ushort) + tmpn.size());
	// add mac counter, key-size bits, and algorithm name to customization string
	IntegerTools::Le64ToBytes(m_rcsState->Counter, m_rcsState->Custom, 0);
	ushort kbits = static_cast<ushort>(Parameters.KeySizes().KeySize() * 8);
	IntegerTools::Le16ToBytes(kbits, m_rcsState->Custom, sizeof(ulong));
	MemoryTools::CopyFromObject(tmpn.data(), m_rcsState->Custom, sizeof(ulong) + sizeof(ushort), tmpn.size());
	// copy the nonce to state
	MemoryTools::Copy(Parameters.Nonce(), 0, m_rcsState->Nonce, 0, BLOCK_SIZE);
	// initialize cSHAKE with k,c
	m_rcsState->Mode = (Parameters.KeySizes().KeySize() == 64) ? ShakeModes::SHAKE512 : (Parameters.KeySizes().KeySize() == 32) ? ShakeModes::SHAKE256 : ShakeModes::SHAKE1024;
	Kdf::SHAKE gen(m_rcsState->Mode);
	gen.Initialize(Parameters.SecureKey(), m_rcsState->Custom);

	// generate the cipher round-keys
	const size_t RNKLEN = ((BLOCK_SIZE / 4) * (m_rcsState->Rounds + 1));
	m_rcsState->RoundKeys.resize(RNKLEN);
	SecureVector<byte> tmpr(RNKLEN * sizeof(uint));
	gen.Generate(tmpr);

	// big endian format to align with test vectors
	for (i = 0; i < tmpr.size(); i += sizeof(uint))
	{
		tmpbk = IntegerTools::BeBytesTo32(tmpr, i);
		IntegerTools::Le32ToBytes(tmpbk, tmpr, i);
	}

	// copy bytes to working key
#if defined(CEX_IS_LITTLE_ENDIAN)
	MemoryTools::Copy(tmpr, 0, m_rcsState->RoundKeys, 0, tmpr.size());
#else
	for (size_t i = 0; i < RNKLEN; ++i)
	{
		m_rcsState->RoundKeys[i] = IntegerTools::LeBytesTo32(tmpr, i * sizeof(uint));
	}
#endif

	MemoryTools::Clear(tmpr, 0, tmpr.size());

	if (IsAuthenticator())
	{
		// generate the mac key
		SymmetricKeySize ks = m_macAuthenticator->LegalKeySizes()[1];
		SecureVector<byte> mack(ks.KeySize());
		gen.Generate(mack);
		// initailize the mac
		SymmetricKey kpm(mack);
		m_macAuthenticator->Initialize(kpm);
		// store the key
		m_rcsState->MacKey.resize(mack.size());
		Move(mack, m_rcsState->MacKey, 0);
		m_rcsState->MacTag.resize(TagSize());
	}

	// pre-load the s-box and multiplication tables into l2 as a timing defence
#if defined(CEX_PREFETCH_RHX_TABLES)
	Prefetch();
#endif

	m_rcsState->Encryption = Encryption;
	m_rcsState->Initialized = true;
}

void RCS::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0 || Degree % 2 != 0 || Degree > m_parallelProfile.ProcessorCount())
	{
		throw CryptoSymmetricException(Name(), std::string("ParallelMaxDegree"), std::string("Degree setting is invalid!"), ErrorCodes::NotSupported);
	}

	m_parallelProfile.SetMaxDegree(Degree);
}

void RCS::SetAssociatedData(const std::vector<byte> &Input, size_t Offset, size_t Length)
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

void RCS::Transform(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");
	CEXASSERT(IntegerTools::Min(Input.size() - InOffset, Output.size() - OutOffset) >= Length, "The data arrays are smaller than the the block-size!");

	if (IsEncryption())
	{
		if (IsAuthenticator())
		{
			if (Output.size() < Length + OutOffset + m_macAuthenticator->TagSize())
			{
				throw CryptoSymmetricException(Name(), std::string("Transform"), std::string("The vector is not long enough to add the MAC code!"), ErrorCodes::InvalidSize);
			}

			// add the starting position of the nonce
			m_macAuthenticator->Update(m_rcsState->Nonce, 0, BLOCK_SIZE);
			// encrypt the stream
			Process(Input, InOffset, Output, OutOffset, Length);
			// update the mac with the ciphertext
			m_macAuthenticator->Update(Output, OutOffset, Length);
			// update the mac counter
			m_rcsState->Counter += Length;
			// finalize the mac and add the tag to the stream
			Finalize(m_rcsState, m_macAuthenticator);
			MemoryTools::Copy(m_rcsState->MacTag, 0, Output, OutOffset + Length, m_rcsState->MacTag.size());
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
			m_macAuthenticator->Update(m_rcsState->Nonce, 0, BLOCK_SIZE);
			// update the mac with the ciphertext
			m_macAuthenticator->Update(Input, InOffset, Length);
			// update the mac counter
			m_rcsState->Counter += Length;
			// finalize the mac and verify
			Finalize(m_rcsState, m_macAuthenticator);

			if (!IntegerTools::Compare(Input, InOffset + Length, m_rcsState->MacTag, 0, m_rcsState->MacTag.size()))
			{
				throw CryptoAuthenticationFailure(Name(), std::string("Transform"), std::string("The authentication tag does not match!"), ErrorCodes::AuthenticationFailure);
			}
		}

		// decrypt the stream
		Process(Input, InOffset, Output, OutOffset, Length);
	}
}

//~~~Private Functions~~~//

void RCS::Finalize(std::unique_ptr<RcsState> &State, std::unique_ptr<IMac> &Authenticator)
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
	Move(mack, State->MacKey, 0);
}

void RCS::Generate(std::vector<byte> &Output, size_t OutOffset, size_t Length, std::vector<byte> &Counter)
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
			IntegerTools::LeIncrease8(Counter, tmpc, 0, 32);
			IntegerTools::LeIncrease8(Counter, tmpc, 32, 64);
			IntegerTools::LeIncrease8(Counter, tmpc, 64, 96);
			IntegerTools::LeIncrease8(Counter, tmpc, 96, 128);
			IntegerTools::LeIncrease8(Counter, tmpc, 128, 160);
			IntegerTools::LeIncrease8(Counter, tmpc, 160, 192);
			IntegerTools::LeIncrease8(Counter, tmpc, 192, 224);
			IntegerTools::LeIncrease8(Counter, tmpc, 224, 256);
			IntegerTools::LeIncrease8(Counter, tmpc, 256, 288);
			IntegerTools::LeIncrease8(Counter, tmpc, 288, 320);
			IntegerTools::LeIncrease8(Counter, tmpc, 320, 352);
			IntegerTools::LeIncrease8(Counter, tmpc, 352, 384);
			IntegerTools::LeIncrease8(Counter, tmpc, 384, 416);
			IntegerTools::LeIncrease8(Counter, tmpc, 416, 448);
			IntegerTools::LeIncrease8(Counter, tmpc, 448, 480);
			IntegerTools::LeIncrease8(Counter, tmpc, 480, 512);
			Transform4096(tmpc, 0, Output, OutOffset + bctr);
			IntegerTools::LeIncrease8(Counter, static_cast<uint>(AVX512BLK));
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
			IntegerTools::LeIncrease8(Counter, tmpc, 0, 32);
			IntegerTools::LeIncrease8(Counter, tmpc, 32, 64);
			IntegerTools::LeIncrease8(Counter, tmpc, 64, 96);
			IntegerTools::LeIncrease8(Counter, tmpc, 96, 128);
			IntegerTools::LeIncrease8(Counter, tmpc, 128, 160);
			IntegerTools::LeIncrease8(Counter, tmpc, 160, 192);
			IntegerTools::LeIncrease8(Counter, tmpc, 192, 224);
			IntegerTools::LeIncrease8(Counter, tmpc, 224, 256);
			Transform2048(tmpc, 0, Output, OutOffset + bctr);
			IntegerTools::LeIncrease8(Counter, static_cast<uint>(AVX2BLK));
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
			IntegerTools::LeIncrease8(Counter, tmpc, 0, 32);
			IntegerTools::LeIncrease8(Counter, tmpc, 32, 64);
			IntegerTools::LeIncrease8(Counter, tmpc, 64, 96);
			IntegerTools::LeIncrease8(Counter, tmpc, 96, 128);
			Transform1024(tmpc, 0, Output, OutOffset + bctr);
			IntegerTools::LeIncrease8(Counter, static_cast<uint>(AVXBLK));
			bctr += AVXBLK;
		}
	}
#endif

	const size_t BLKALN = Length - (Length % BLOCK_SIZE);
	while (bctr != BLKALN)
	{
		IntegerTools::LeIncrease8(Counter, static_cast<uint>(BLOCK_SIZE));
		Transform256(Counter, 0, Output, OutOffset + bctr);
		bctr += BLOCK_SIZE;
	}

	if (bctr != Length)
	{
		std::vector<byte> otp(BLOCK_SIZE);
		IntegerTools::LeIncrease8(Counter, static_cast<uint>(BLOCK_SIZE));
		Transform256(Counter, 0, otp, 0);
		const size_t RMDLEN = Length % BLOCK_SIZE;
		MemoryTools::Copy(otp, 0, Output, OutOffset + (Length - RMDLEN), RMDLEN);
	}
}

CEX_OPTIMIZE_IGNORE
void RCS::Prefetch()
{
	// timing defence: pre-load tables into cache
	MemoryTools::PrefetchL2(SBox, 0, 256);
	MemoryTools::PrefetchL2(T0, 0, 1024);
	MemoryTools::PrefetchL2(T1, 0, 1024);
	MemoryTools::PrefetchL2(T2, 0, 1024);
	MemoryTools::PrefetchL2(T3, 0, 1024);

}
CEX_OPTIMIZE_RESUME

void RCS::Process(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length)
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

void RCS::ProcessParallel(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	const size_t OTPLEN = Output.size() - OutOffset < Length ? Output.size() - OutOffset : Length;
	const size_t CNKLEN = m_parallelProfile.ParallelBlockSize() / m_parallelProfile.ParallelMaxDegree();
	std::vector<byte> tmpc(m_rcsState->Nonce.size());

	Utility::ParallelTools::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Input, InOffset, &Output, OutOffset, &tmpc, CNKLEN](size_t i)
	{
		// thread level counter
		std::vector<byte> thdc(m_rcsState->Nonce.size());
		// offset counter by chunk size / block size  
		IntegerTools::LeIncrease8(m_rcsState->Nonce, thdc, static_cast<uint>(CNKLEN * i));
		// generate random at output offset
		this->Generate(Output, OutOffset + (i * CNKLEN), CNKLEN, thdc);
		// xor with input at offsets
		MemoryTools::XOR(Input, InOffset + (i * CNKLEN), Output, OutOffset + (i * CNKLEN), CNKLEN);

		// store last counter
		if (i == m_parallelProfile.ParallelMaxDegree() - 1)
		{
			MemoryTools::Copy(thdc, 0, tmpc, 0, BLOCK_SIZE);
		}
	});

	// copy last counter to class variable
	MemoryTools::Copy(tmpc, 0, m_rcsState->Nonce, 0, BLOCK_SIZE);

	// last block processing
	const size_t ALNLEN = CNKLEN * m_parallelProfile.ParallelMaxDegree();
	if (ALNLEN < OTPLEN)
	{
		const size_t RMDLEN = (Output.size() - OutOffset) % ALNLEN;
		Generate(Output, ALNLEN, RMDLEN, m_rcsState->Nonce);

		for (size_t i = ALNLEN; i < OTPLEN; i++)
		{
			Output[i] ^= Input[i];
		}
	}
}

void RCS::ProcessSequential(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	// get block aligned
	const size_t ALNLEN = Length - (Length % BLOCK_SIZE);
	size_t i;

	// generate random
	Generate(Output, OutOffset, Length, m_rcsState->Nonce);

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

void RCS::Reset()
{
	m_rcsState->Reset();

	if (IsAuthenticator())
	{
		m_macAuthenticator->Reset();
	}

	m_parallelProfile.Calculate(m_parallelProfile.IsParallel(), m_parallelProfile.ParallelBlockSize(), m_parallelProfile.ParallelMaxDegree());
}

void RCS::Transform256(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	const size_t RNDCNT = m_rcsState->RoundKeys.size() - 8;
	size_t kctr;
	uint X0;
	uint X1;
	uint X2;
	uint X3;
	uint X4;
	uint X5;
	uint X6;
	uint X7;
	uint Y0;
	uint Y1;
	uint Y2;
	uint Y3;
	uint Y4;
	uint Y5;
	uint Y6;
	uint Y7;

	// round 0
	X0 = IntegerTools::BeBytesTo32(Input, InOffset) ^ m_rcsState->RoundKeys[0];
	X1 = IntegerTools::BeBytesTo32(Input, InOffset + 4) ^ m_rcsState->RoundKeys[1];
	X2 = IntegerTools::BeBytesTo32(Input, InOffset + 8) ^ m_rcsState->RoundKeys[2];
	X3 = IntegerTools::BeBytesTo32(Input, InOffset + 12) ^ m_rcsState->RoundKeys[3];
	X4 = IntegerTools::BeBytesTo32(Input, InOffset + 16) ^ m_rcsState->RoundKeys[4];
	X5 = IntegerTools::BeBytesTo32(Input, InOffset + 20) ^ m_rcsState->RoundKeys[5];
	X6 = IntegerTools::BeBytesTo32(Input, InOffset + 24) ^ m_rcsState->RoundKeys[6];
	X7 = IntegerTools::BeBytesTo32(Input, InOffset + 28) ^ m_rcsState->RoundKeys[7];

	// round 1
	Y0 = T0[static_cast<byte>(X0 >> 24)] ^ T1[static_cast<byte>(X1 >> 16)] ^ T2[static_cast<byte>(X3 >> 8)] ^ T3[static_cast<byte>(X4)] ^ m_rcsState->RoundKeys[8];
	Y1 = T0[static_cast<byte>(X1 >> 24)] ^ T1[static_cast<byte>(X2 >> 16)] ^ T2[static_cast<byte>(X4 >> 8)] ^ T3[static_cast<byte>(X5)] ^ m_rcsState->RoundKeys[9];
	Y2 = T0[static_cast<byte>(X2 >> 24)] ^ T1[static_cast<byte>(X3 >> 16)] ^ T2[static_cast<byte>(X5 >> 8)] ^ T3[static_cast<byte>(X6)] ^ m_rcsState->RoundKeys[10];
	Y3 = T0[static_cast<byte>(X3 >> 24)] ^ T1[static_cast<byte>(X4 >> 16)] ^ T2[static_cast<byte>(X6 >> 8)] ^ T3[static_cast<byte>(X7)] ^ m_rcsState->RoundKeys[11];
	Y4 = T0[static_cast<byte>(X4 >> 24)] ^ T1[static_cast<byte>(X5 >> 16)] ^ T2[static_cast<byte>(X7 >> 8)] ^ T3[static_cast<byte>(X0)] ^ m_rcsState->RoundKeys[12];
	Y5 = T0[static_cast<byte>(X5 >> 24)] ^ T1[static_cast<byte>(X6 >> 16)] ^ T2[static_cast<byte>(X0 >> 8)] ^ T3[static_cast<byte>(X1)] ^ m_rcsState->RoundKeys[13];
	Y6 = T0[static_cast<byte>(X6 >> 24)] ^ T1[static_cast<byte>(X7 >> 16)] ^ T2[static_cast<byte>(X1 >> 8)] ^ T3[static_cast<byte>(X2)] ^ m_rcsState->RoundKeys[14];
	Y7 = T0[static_cast<byte>(X7 >> 24)] ^ T1[static_cast<byte>(X0 >> 16)] ^ T2[static_cast<byte>(X2 >> 8)] ^ T3[static_cast<byte>(X3)] ^ m_rcsState->RoundKeys[15];

	kctr = 16;
	while (kctr != RNDCNT)
	{
		X0 = T0[static_cast<byte>(Y0 >> 24)] ^ T1[static_cast<byte>(Y1 >> 16)] ^ T2[static_cast<byte>(Y3 >> 8)] ^ T3[static_cast<byte>(Y4)] ^ m_rcsState->RoundKeys[kctr];
		++kctr;
		X1 = T0[static_cast<byte>(Y1 >> 24)] ^ T1[static_cast<byte>(Y2 >> 16)] ^ T2[static_cast<byte>(Y4 >> 8)] ^ T3[static_cast<byte>(Y5)] ^ m_rcsState->RoundKeys[kctr];
		++kctr;
		X2 = T0[static_cast<byte>(Y2 >> 24)] ^ T1[static_cast<byte>(Y3 >> 16)] ^ T2[static_cast<byte>(Y5 >> 8)] ^ T3[static_cast<byte>(Y6)] ^ m_rcsState->RoundKeys[kctr];
		++kctr;
		X3 = T0[static_cast<byte>(Y3 >> 24)] ^ T1[static_cast<byte>(Y4 >> 16)] ^ T2[static_cast<byte>(Y6 >> 8)] ^ T3[static_cast<byte>(Y7)] ^ m_rcsState->RoundKeys[kctr];
		++kctr;
		X4 = T0[static_cast<byte>(Y4 >> 24)] ^ T1[static_cast<byte>(Y5 >> 16)] ^ T2[static_cast<byte>(Y7 >> 8)] ^ T3[static_cast<byte>(Y0)] ^ m_rcsState->RoundKeys[kctr];
		++kctr;
		X5 = T0[static_cast<byte>(Y5 >> 24)] ^ T1[static_cast<byte>(Y6 >> 16)] ^ T2[static_cast<byte>(Y0 >> 8)] ^ T3[static_cast<byte>(Y1)] ^ m_rcsState->RoundKeys[kctr];
		++kctr;
		X6 = T0[static_cast<byte>(Y6 >> 24)] ^ T1[static_cast<byte>(Y7 >> 16)] ^ T2[static_cast<byte>(Y1 >> 8)] ^ T3[static_cast<byte>(Y2)] ^ m_rcsState->RoundKeys[kctr];
		++kctr;
		X7 = T0[static_cast<byte>(Y7 >> 24)] ^ T1[static_cast<byte>(Y0 >> 16)] ^ T2[static_cast<byte>(Y2 >> 8)] ^ T3[static_cast<byte>(Y3)] ^ m_rcsState->RoundKeys[kctr];
		++kctr;
		Y0 = T0[static_cast<byte>(X0 >> 24)] ^ T1[static_cast<byte>(X1 >> 16)] ^ T2[static_cast<byte>(X3 >> 8)] ^ T3[static_cast<byte>(X4)] ^ m_rcsState->RoundKeys[kctr];
		++kctr;
		Y1 = T0[static_cast<byte>(X1 >> 24)] ^ T1[static_cast<byte>(X2 >> 16)] ^ T2[static_cast<byte>(X4 >> 8)] ^ T3[static_cast<byte>(X5)] ^ m_rcsState->RoundKeys[kctr];
		++kctr;
		Y2 = T0[static_cast<byte>(X2 >> 24)] ^ T1[static_cast<byte>(X3 >> 16)] ^ T2[static_cast<byte>(X5 >> 8)] ^ T3[static_cast<byte>(X6)] ^ m_rcsState->RoundKeys[kctr];
		++kctr;
		Y3 = T0[static_cast<byte>(X3 >> 24)] ^ T1[static_cast<byte>(X4 >> 16)] ^ T2[static_cast<byte>(X6 >> 8)] ^ T3[static_cast<byte>(X7)] ^ m_rcsState->RoundKeys[kctr];
		++kctr;
		Y4 = T0[static_cast<byte>(X4 >> 24)] ^ T1[static_cast<byte>(X5 >> 16)] ^ T2[static_cast<byte>(X7 >> 8)] ^ T3[static_cast<byte>(X0)] ^ m_rcsState->RoundKeys[kctr];
		++kctr;
		Y5 = T0[static_cast<byte>(X5 >> 24)] ^ T1[static_cast<byte>(X6 >> 16)] ^ T2[static_cast<byte>(X0 >> 8)] ^ T3[static_cast<byte>(X1)] ^ m_rcsState->RoundKeys[kctr];
		++kctr;
		Y6 = T0[static_cast<byte>(X6 >> 24)] ^ T1[static_cast<byte>(X7 >> 16)] ^ T2[static_cast<byte>(X1 >> 8)] ^ T3[static_cast<byte>(X2)] ^ m_rcsState->RoundKeys[kctr];
		++kctr;
		Y7 = T0[static_cast<byte>(X7 >> 24)] ^ T1[static_cast<byte>(X0 >> 16)] ^ T2[static_cast<byte>(X2 >> 8)] ^ T3[static_cast<byte>(X3)] ^ m_rcsState->RoundKeys[kctr];
		++kctr;
	}

	// final round
	Output[OutOffset] = static_cast<byte>(SBox[static_cast<byte>(Y0 >> 24)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr] >> 24));
	Output[OutOffset + 1] = static_cast<byte>(SBox[static_cast<byte>(Y1 >> 16)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr] >> 16));
	Output[OutOffset + 2] = static_cast<byte>(SBox[static_cast<byte>(Y3 >> 8)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr] >> 8));
	Output[OutOffset + 3] = static_cast<byte>(SBox[static_cast<byte>(Y4)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr]));
	++kctr;
	Output[OutOffset + 4] = static_cast<byte>(SBox[static_cast<byte>(Y1 >> 24)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr] >> 24));
	Output[OutOffset + 5] = static_cast<byte>(SBox[static_cast<byte>(Y2 >> 16)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr] >> 16));
	Output[OutOffset + 6] = static_cast<byte>(SBox[static_cast<byte>(Y4 >> 8)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr] >> 8));
	Output[OutOffset + 7] = static_cast<byte>(SBox[static_cast<byte>(Y5)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr]));
	++kctr;
	Output[OutOffset + 8] = static_cast<byte>(SBox[static_cast<byte>(Y2 >> 24)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr] >> 24));
	Output[OutOffset + 9] = static_cast<byte>(SBox[static_cast<byte>(Y3 >> 16)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr] >> 16));
	Output[OutOffset + 10] = static_cast<byte>(SBox[static_cast<byte>(Y5 >> 8)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr] >> 8));
	Output[OutOffset + 11] = static_cast<byte>(SBox[static_cast<byte>(Y6)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr]));
	++kctr;
	Output[OutOffset + 12] = static_cast<byte>(SBox[static_cast<byte>(Y3 >> 24)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr] >> 24));
	Output[OutOffset + 13] = static_cast<byte>(SBox[static_cast<byte>(Y4 >> 16)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr] >> 16));
	Output[OutOffset + 14] = static_cast<byte>(SBox[static_cast<byte>(Y6 >> 8)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr] >> 8));
	Output[OutOffset + 15] = static_cast<byte>(SBox[static_cast<byte>(Y7)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr]));
	++kctr;
	Output[OutOffset + 16] = static_cast<byte>(SBox[static_cast<byte>(Y4 >> 24)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr] >> 24));
	Output[OutOffset + 17] = static_cast<byte>(SBox[static_cast<byte>(Y5 >> 16)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr] >> 16));
	Output[OutOffset + 18] = static_cast<byte>(SBox[static_cast<byte>(Y7 >> 8)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr] >> 8));
	Output[OutOffset + 19] = static_cast<byte>(SBox[static_cast<byte>(Y0)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr]));
	++kctr;
	Output[OutOffset + 20] = static_cast<byte>(SBox[static_cast<byte>(Y5 >> 24)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr] >> 24));
	Output[OutOffset + 21] = static_cast<byte>(SBox[static_cast<byte>(Y6 >> 16)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr] >> 16));
	Output[OutOffset + 22] = static_cast<byte>(SBox[static_cast<byte>(Y0 >> 8)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr] >> 8));
	Output[OutOffset + 23] = static_cast<byte>(SBox[static_cast<byte>(Y1)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr]));
	++kctr;
	Output[OutOffset + 24] = static_cast<byte>(SBox[static_cast<byte>(Y6 >> 24)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr] >> 24));
	Output[OutOffset + 25] = static_cast<byte>(SBox[static_cast<byte>(Y7 >> 16)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr] >> 16));
	Output[OutOffset + 26] = static_cast<byte>(SBox[static_cast<byte>(Y1 >> 8)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr] >> 8));
	Output[OutOffset + 27] = static_cast<byte>(SBox[static_cast<byte>(Y2)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr]));
	++kctr;
	Output[OutOffset + 28] = static_cast<byte>(SBox[static_cast<byte>(Y7 >> 24)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr] >> 24));
	Output[OutOffset + 29] = static_cast<byte>(SBox[static_cast<byte>(Y0 >> 16)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr] >> 16));
	Output[OutOffset + 30] = static_cast<byte>(SBox[static_cast<byte>(Y2 >> 8)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr] >> 8));
	Output[OutOffset + 31] = static_cast<byte>(SBox[static_cast<byte>(Y3)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr]));
}

void RCS::Transform1024(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	Transform256(Input, InOffset, Output, OutOffset);
	Transform256(Input, InOffset + 32, Output, OutOffset + 32);
	Transform256(Input, InOffset + 64, Output, OutOffset + 64);
	Transform256(Input, InOffset + 96, Output, OutOffset + 96);
}

void RCS::Transform2048(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	Transform1024(Input, InOffset, Output, OutOffset);
	Transform1024(Input, InOffset + 128, Output, OutOffset + 128);
}

void RCS::Transform4096(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	Transform2048(Input, InOffset, Output, OutOffset);
	Transform2048(Input, InOffset + 256, Output, OutOffset + 256);
}

NAMESPACE_STREAMEND
