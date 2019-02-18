#include "ChaCha512.h"
#include "ChaCha.h"
#include "IntegerTools.h"
#include "MacFromName.h"
#include "MemoryTools.h"
#include "ParallelTools.h"
#include "SHAKE.h"
#include "SymmetricKey.h"

#if defined(__AVX2__)
#	include "UInt256.h"
#elif defined(__AVX__)
#	include "UInt128.h"
#endif

NAMESPACE_STREAM

using Utility::IntegerTools;
using Utility::MemoryTools;
using Utility::ParallelTools;

struct ChaCha512::ChaCha512State
{
	// counter
	std::array<uint, 2> C;
	// state
	std::array<uint, 14> S;

	ChaCha512State()
	{
		Reset();
	}

	void Reset()
	{
		// 128 bits of counter
		C[0] = 0;
		C[1] = 0;
		MemoryTools::Clear(C, 0, C.size() * sizeof(uint));
		MemoryTools::Clear(S, 0, S.size() * sizeof(uint));
	}
};

const std::string ChaCha512::CLASS_NAME("ChaCha512");
const std::vector<byte> ChaCha512::SIGMA_INFO = { 0x65, 0x78, 0x70, 0x61, 0x6E, 0x64, 0x20, 0x36, 0x34, 0x2D, 0x62, 0x79, 0x74, 0x65, 0x20, 0x6B };

//~~~Constructor~~~//

ChaCha512::ChaCha512(StreamAuthenticators AuthenticatorType)
	:
	m_authenticatorType(AuthenticatorType != StreamAuthenticators::KMAC1024 ? AuthenticatorType : 
		throw CryptoSymmetricCipherException(CLASS_NAME, std::string("Constructor"), std::string("The authenticator must be a 256 or 512-bit MAC function!"), ErrorCodes::IllegalOperation)),
	m_cipherState(new ChaCha512State),
	m_shakeCustom(0),
	m_isAuthenticated(AuthenticatorType != StreamAuthenticators::None),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_legalKeySizes{ SymmetricKeySize(KEY_SIZE, 0, INFO_SIZE) },
	m_macAuthenticator(m_authenticatorType == StreamAuthenticators::None ? nullptr :
		Helper::MacFromName::GetInstance(AuthenticatorType)),
	m_macCounter(0),
	m_macKey(0),
	m_macTag(0),
	m_parallelProfile(BLOCK_SIZE, true, STATE_PRECACHED, true)
{
}

ChaCha512::~ChaCha512()
{
	if (!m_isDestroyed)
	{
		m_authenticatorType = StreamAuthenticators::None;
		m_isAuthenticated = false;
		m_isDestroyed = true;
		m_isEncryption = false;
		m_isInitialized = false;
		m_macCounter = 0;

		if (m_cipherState != nullptr)
		{
			m_cipherState->Reset();
			m_cipherState.reset(nullptr);
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

const size_t ChaCha512::BlockSize()
{
	return BLOCK_SIZE;
}

const size_t ChaCha512::DistributionCodeMax()
{
	return INFO_SIZE;
}

const StreamCiphers ChaCha512::Enumeral()
{
	return StreamCiphers::ChaCha512;
}

const bool ChaCha512::IsAuthenticator()
{
	return m_isAuthenticated;
}

const bool ChaCha512::IsInitialized()
{
	return m_isInitialized;
}

const bool ChaCha512::IsParallel()
{
	return m_parallelProfile.IsParallel();
}

const std::vector<SymmetricKeySize> &ChaCha512::LegalKeySizes()
{
	return m_legalKeySizes;
}

const std::string ChaCha512::Name()
{
	std::string name = CLASS_NAME;

#if defined(CEX_CHACHA512_STRONG)
	name += "P80";
#else
	name += "P40";
#endif

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

const size_t ChaCha512::ParallelBlockSize()
{
	return m_parallelProfile.ParallelBlockSize();
}

ParallelOptions &ChaCha512::ParallelProfile()
{
	return m_parallelProfile;
}

const std::vector<byte> &ChaCha512::Tag()
{
	return m_macTag;
}

const size_t ChaCha512::TagSize()
{
	return m_macAuthenticator != nullptr ? m_macAuthenticator->TagSize() : 0;
}

//~~~Public Functions~~~//

void ChaCha512::Authenticator(StreamAuthenticators AuthenticatorType)
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

void ChaCha512::Initialize(bool Encryption, ISymmetricKey &Parameters)
{
	if (Parameters.Key().size() != KEY_SIZE)
	{
		throw CryptoSymmetricCipherException(Name(), std::string("Initialize"), std::string("Invalid key size; key must be one of the LegalKeySizes in length!"), ErrorCodes::InvalidKey);
	}
	if (Parameters.Nonce().size() != 0)
	{
		throw CryptoSymmetricCipherException(Name(), std::string("Initialize"), std::string("The nonce is not required with ChaCha512!"), ErrorCodes::InvalidNonce);
	}
	if (Parameters.Info().size() > 0 && Parameters.Info().size() != INFO_SIZE)
	{
		throw CryptoSymmetricCipherException(Name(), std::string("Initialize"), std::string("The distribution code must be no larger than DistributionCodeMax!"), ErrorCodes::InvalidInfo);
	}

	if (m_parallelProfile.IsParallel())
	{
		if (m_parallelProfile.ParallelBlockSize() < m_parallelProfile.ParallelMinimumSize() || m_parallelProfile.ParallelBlockSize() > m_parallelProfile.ParallelMaximumSize())
		{
			throw CryptoSymmetricCipherException(Name(), std::string("Initialize"), std::string("The parallel block size is out of bounds!"), ErrorCodes::InvalidSize);
		}
		if (m_parallelProfile.ParallelBlockSize() % m_parallelProfile.ParallelMinimumSize() != 0)
		{
			throw CryptoSymmetricCipherException(Name(), std::string("Initialize"), std::string("The parallel block size must be evenly aligned to the ParallelMinimumSize!"), ErrorCodes::InvalidParam);
		}
	}

	// reset the counter and mac
	Reset();

	std::vector<byte> code(INFO_SIZE);

	if (Parameters.Info().size() != 0)
	{
		// custom code
		MemoryTools::Copy(Parameters.Info(), 0, code, 0, Parameters.Info().size());
	}
	else
	{
		// standard
		MemoryTools::Copy(SIGMA_INFO, 0, code, 0, SIGMA_INFO.size());
	}

	if (m_authenticatorType == StreamAuthenticators::None)
	{
		// add key and nonce to state
		Expand(Parameters.Key(), code);
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

		// initialize cSHAKE
		Kdf::SHAKE gen(ShakeModes::SHAKE512);
		gen.Initialize(Parameters.Key(), m_shakeCustom);

		// generate the new cipher key
		std::vector<byte> ck(KEY_SIZE);
		gen.Generate(ck);

		// expand round keys
		Expand(ck, code);

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

void ChaCha512::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0 || Degree % 2 != 0 || Degree > m_parallelProfile.ProcessorCount())
	{
		throw CryptoSymmetricCipherException(Name(), std::string("ParallelMaxDegree"), std::string("Degree setting is invalid!"), ErrorCodes::NotSupported);
	}

	m_parallelProfile.SetMaxDegree(Degree);
}

void ChaCha512::SetAssociatedData(const std::vector<byte> &Input, const size_t Offset, const size_t Length)
{
	if (!m_isInitialized)
	{
		throw CryptoSymmetricCipherException(Name(), std::string("SetAssociatedData"), std::string("The cipher has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (m_macAuthenticator == nullptr)
	{
		throw CryptoSymmetricCipherException(Name(), std::string("SetAssociatedData"), std::string("The cipher has not been configured for authentication!"), ErrorCodes::IllegalOperation);
	}

	// update the authenticator
	m_macAuthenticator->Update(Input, Offset, Length);
}

void ChaCha512::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	if (m_isEncryption)
	{
		if (m_isAuthenticated)
		{
			// add the starting position of the nonce
			m_macAuthenticator->Update(IntegerTools::Le32ToBytes<std::vector<byte>>(m_cipherState->C[0]), 0, sizeof(uint));
			m_macAuthenticator->Update(IntegerTools::Le32ToBytes<std::vector<byte>>(m_cipherState->C[1]), 0, sizeof(uint));
			// encrypt the stream
			Process(Input, InOffset, Output, OutOffset, Length);
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
			Process(Input, InOffset, Output, OutOffset, Length);
		}
	}
	else
	{
		if (m_isAuthenticated)
		{
			// add the starting position of the nonce
			m_macAuthenticator->Update(IntegerTools::Le32ToBytes<std::vector<byte>>(m_cipherState->C[0]), 0, sizeof(uint));
			m_macAuthenticator->Update(IntegerTools::Le32ToBytes<std::vector<byte>>(m_cipherState->C[1]), 0, sizeof(uint));
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
		Process(Input, InOffset, Output, OutOffset, Length);
	}
}

//~~~Private Functions~~~//

void ChaCha512::Expand(const std::vector<byte> &Key, const std::vector<byte> &Code)
{
#if defined(CEX_IS_LITTLE_ENDIAN)
	MemoryTools::Copy(Key, 0, m_cipherState->S, 0, STATE_SIZE * sizeof(uint));
	MemoryTools::Copy(Key, STATE_SIZE * sizeof(uint), m_cipherState->C, 0, NONCE_SIZE * sizeof(uint));
#else
	m_cipherState->S[0] = IntegerTools::LeBytesTo32(Key, 0);
	m_cipherState->S[1] = IntegerTools::LeBytesTo32(Key, 4);
	m_cipherState->S[2] = IntegerTools::LeBytesTo32(Key, 8);
	m_cipherState->S[3] = IntegerTools::LeBytesTo32(Key, 12);
	m_cipherState->S[4] = IntegerTools::LeBytesTo32(Key, 16);
	m_cipherState->S[5] = IntegerTools::LeBytesTo32(Key, 20);
	m_cipherState->S[6] = IntegerTools::LeBytesTo32(Key, 24);
	m_cipherState->S[7] = IntegerTools::LeBytesTo32(Key, 28);
	m_cipherState->S[8] = IntegerTools::LeBytesTo32(Key, 32);
	m_cipherState->S[9] = IntegerTools::LeBytesTo32(Key, 36);
	m_cipherState->S[10] = IntegerTools::LeBytesTo32(Key, 40);
	m_cipherState->S[11] = IntegerTools::LeBytesTo32(Key, 44);
	m_cipherState->S[12] = IntegerTools::LeBytesTo32(Key, 48);
	m_cipherState->S[13] = IntegerTools::LeBytesTo32(Key, 52);
	m_cipherState->C[0] = IntegerTools::LeBytesTo32(Key, 56);
	m_cipherState->C[1] = IntegerTools::LeBytesTo32(Key, 60);
#endif

	m_cipherState->S[4] += IntegerTools::LeBytesTo32(Code, 0);
	m_cipherState->S[5] += IntegerTools::LeBytesTo32(Code, 4);
	m_cipherState->S[6] += IntegerTools::LeBytesTo32(Code, 8);
	m_cipherState->S[7] += IntegerTools::LeBytesTo32(Code, 12);
}

void ChaCha512::Finalize(std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	if (!m_isInitialized)
	{
		throw CryptoSymmetricCipherException(Name(), std::string("Finalize"), std::string("The cipher has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (m_macAuthenticator == nullptr)
	{
		throw CryptoSymmetricCipherException(Name(), std::string("Finalize"), std::string("The cipher has not been configured for authentication!"), ErrorCodes::IllegalOperation);
	}
	if (Length > m_macAuthenticator->TagSize())
	{
		throw CryptoSymmetricCipherException(Name(), std::string("Finalize"), std::string("The MAC code specified is longer than the maximum length!"), ErrorCodes::InvalidParam);
	}

	// generate the mac code
	std::vector<byte> code(m_macAuthenticator->TagSize());
	m_macAuthenticator->Finalize(code, 0);
	MemoryTools::Copy(code, 0, Output, OutOffset, code.size() < Length ? code.size() : Length);

	// customization string is: mac counter + algorithm name
	IntegerTools::Le64ToBytes(m_macCounter, m_shakeCustom, 0);

	// extract the new mac key
	Kdf::SHAKE gen(ShakeModes::SHAKE512);
	gen.Initialize(UnlockClear(m_macKey), m_shakeCustom);
	std::vector<byte> mack(m_macAuthenticator->LegalKeySizes()[1].KeySize());
	gen.Generate(mack);
	// reset the generator with the new key
	m_macAuthenticator->Initialize(SymmetricKey(mack));
	// store the key
	m_macKey = LockClear(mack);
}

void ChaCha512::Generate(std::vector<byte> &Output, const size_t OutOffset, std::array<uint, 2> &Counter, const size_t Length)
{
	size_t ctr;

	ctr = 0;

#if defined(__AVX512__)

	const size_t AVX512BLK = 16 * BLOCK_SIZE;

	if (Length >= AVX512BLK)
	{
		const size_t SEGALN = Length - (Length % AVX512BLK);
		std::array<uint, 32> ctrBlk;

		// process 8 blocks (uses avx if available)
		while (ctr != SEGALN)
		{
			MemoryTools::Copy(Counter, 0, ctrBlk, 0, 4);
			MemoryTools::Copy(Counter, 1, ctrBlk, 16, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, ctrBlk, 1, 4);
			MemoryTools::Copy(Counter, 1, ctrBlk, 17, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, ctrBlk, 2, 4);
			MemoryTools::Copy(Counter, 1, ctrBlk, 18, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, ctrBlk, 3, 4);
			MemoryTools::Copy(Counter, 1, ctrBlk, 19, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, ctrBlk, 4, 4);
			MemoryTools::Copy(Counter, 1, ctrBlk, 20, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, ctrBlk, 5, 4);
			MemoryTools::Copy(Counter, 1, ctrBlk, 21, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, ctrBlk, 6, 4);
			MemoryTools::Copy(Counter, 1, ctrBlk, 22, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, ctrBlk, 7, 4);
			MemoryTools::Copy(Counter, 1, ctrBlk, 23, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, ctrBlk, 8, 4);
			MemoryTools::Copy(Counter, 1, ctrBlk, 24, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, ctrBlk, 9, 4);
			MemoryTools::Copy(Counter, 1, ctrBlk, 25, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, ctrBlk, 10, 4);
			MemoryTools::Copy(Counter, 1, ctrBlk, 26, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, ctrBlk, 11, 4);
			MemoryTools::Copy(Counter, 1, ctrBlk, 27, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, ctrBlk, 12, 4);
			MemoryTools::Copy(Counter, 1, ctrBlk, 28, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, ctrBlk, 13, 4);
			MemoryTools::Copy(Counter, 1, ctrBlk, 29, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, ctrBlk, 14, 4);
			MemoryTools::Copy(Counter, 1, ctrBlk, 30, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, ctrBlk, 15, 4);
			MemoryTools::Copy(Counter, 1, ctrBlk, 31, 4);
			IntegerTools::LeIncrementW(Counter);
			ChaCha::PermuteP16x512H(Output, OutOffset + ctr, ctrBlk, m_cipherState->S, ROUND_COUNT);
			ctr += AVX512BLK;
		}
	}

#elif defined(__AVX2__)

	const size_t AVX2BLK = 8 * BLOCK_SIZE;

	if (Length >= AVX2BLK)
	{
		const size_t SEGALN = Length - (Length % AVX2BLK);
		std::array<uint, 16> ctrBlk;

		// process 8 blocks (uses avx if available)
		while (ctr != SEGALN)
		{
			MemoryTools::Copy(Counter, 0, ctrBlk, 0, 4);
			MemoryTools::Copy(Counter, 1, ctrBlk, 8, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, ctrBlk, 1, 4);
			MemoryTools::Copy(Counter, 1, ctrBlk, 9, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, ctrBlk, 2, 4);
			MemoryTools::Copy(Counter, 1, ctrBlk, 10, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, ctrBlk, 3, 4);
			MemoryTools::Copy(Counter, 1, ctrBlk, 11, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, ctrBlk, 4, 4);
			MemoryTools::Copy(Counter, 1, ctrBlk, 12, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, ctrBlk, 5, 4);
			MemoryTools::Copy(Counter, 1, ctrBlk, 13, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, ctrBlk, 6, 4);
			MemoryTools::Copy(Counter, 1, ctrBlk, 14, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, ctrBlk, 7, 4);
			MemoryTools::Copy(Counter, 1, ctrBlk, 15, 4);
			IntegerTools::LeIncrementW(Counter);
			ChaCha::PermuteP8x512H(Output, OutOffset + ctr, ctrBlk, m_cipherState->S, ROUND_COUNT);
			ctr += AVX2BLK;
		}
	}

#elif defined(__AVX__)

	const size_t AVXBLK = 4 * BLOCK_SIZE;

	if (Length >= AVXBLK)
	{
		const size_t SEGALN = Length - (Length % AVXBLK);
		std::array<uint, 8> ctrBlk;

		// process 4 blocks (uses sse intrinsics if available)
		while (ctr != SEGALN)
		{
			MemoryTools::Copy(Counter, 0, ctrBlk, 0, 4);
			MemoryTools::Copy(Counter, 1, ctrBlk, 4, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, ctrBlk, 1, 4);
			MemoryTools::Copy(Counter, 1, ctrBlk, 5, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, ctrBlk, 2, 4);
			MemoryTools::Copy(Counter, 1, ctrBlk, 6, 4);
			IntegerTools::LeIncrementW(Counter);
			MemoryTools::Copy(Counter, 0, ctrBlk, 3, 4);
			MemoryTools::Copy(Counter, 1, ctrBlk, 7, 4);
			IntegerTools::LeIncrementW(Counter);
			ChaCha::PermuteP4x512H(Output, OutOffset + ctr, ctrBlk, m_cipherState->S, ROUND_COUNT);
			ctr += AVXBLK;
		}
	}
#endif

	const size_t ALNLEN = Length - (Length % BLOCK_SIZE);
	while (ctr != ALNLEN)
	{
		ChaCha::PermuteP512C(Output, OutOffset + ctr, Counter, m_cipherState->S, ROUND_COUNT);
		IntegerTools::LeIncrementW(Counter);
		ctr += BLOCK_SIZE;
	}

	if (ctr != Length)
	{
		std::vector<byte> otp(BLOCK_SIZE, 0);
		ChaCha::PermuteP512C(otp, 0, Counter, m_cipherState->S, ROUND_COUNT);
		const size_t FNLLEN = Length % BLOCK_SIZE;
		MemoryTools::Copy(otp, 0, Output, OutOffset + (Length - FNLLEN), FNLLEN);
		IntegerTools::LeIncrementW(Counter);
	}
}

void ChaCha512::Process(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	const size_t PRCLEN = (Length >= Input.size() - InOffset) && Length >= Output.size() - OutOffset ? IntegerTools::Min(Input.size() - InOffset, Output.size() - OutOffset) : Length;

	if (!m_parallelProfile.IsParallel() || PRCLEN < m_parallelProfile.ParallelMinimumSize())
	{
		// generate random
		Generate(Output, OutOffset, m_cipherState->C, PRCLEN);
		// output is input xor random
		const size_t ALNLEN = PRCLEN - (PRCLEN % BLOCK_SIZE);

		if (ALNLEN != 0)
		{
			MemoryTools::XOR(Input, InOffset, Output, OutOffset, ALNLEN);
		}

		// get the remaining bytes
		if (ALNLEN != PRCLEN)
		{
			for (size_t i = ALNLEN; i < PRCLEN; ++i)
			{
				Output[i + OutOffset] ^= Input[i + InOffset];
			}
		}
	}
	else
	{
		// parallel CTR processing //
		const size_t CNKLEN = (PRCLEN / BLOCK_SIZE / m_parallelProfile.ParallelMaxDegree()) * BLOCK_SIZE;
		const size_t RNDLEN = CNKLEN * m_parallelProfile.ParallelMaxDegree();
		const size_t CTRLEN = (CNKLEN / BLOCK_SIZE);
		std::vector<uint> tmpCtr(NONCE_SIZE);

		ParallelTools::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Input, InOffset, &Output, OutOffset, &tmpCtr, CNKLEN, CTRLEN](size_t i)
		{
			// thread level counter
			std::array<uint, 2> thdCtr;
			// offset counter by chunk size / block size
			IntegerTools::LeIncreaseW(m_cipherState->C, thdCtr, CTRLEN * i);
			// create random at offset position
			this->Generate(Output, OutOffset + (i * CNKLEN), thdCtr, CNKLEN);
			// xor with input at offset
			MemoryTools::XOR(Input, InOffset + (i * CNKLEN), Output, OutOffset + (i * CNKLEN), CNKLEN);
			// store last counter
			if (i == m_parallelProfile.ParallelMaxDegree() - 1)
			{
				MemoryTools::Copy(thdCtr, 0, tmpCtr, 0, NONCE_SIZE * sizeof(uint));
			}
		});

		// copy last counter to class variable
		MemoryTools::Copy(tmpCtr, 0, m_cipherState->C, 0, NONCE_SIZE * sizeof(uint));

		// last block processing
		if (RNDLEN < PRCLEN)
		{
			const size_t FNLLEN = PRCLEN % RNDLEN;
			Generate(Output, RNDLEN, m_cipherState->C, FNLLEN);

			for (size_t i = 0; i < FNLLEN; ++i)
			{
				Output[i + OutOffset + RNDLEN] ^= static_cast<byte>(Input[i + InOffset + RNDLEN]);
			}
		}
	}
}

void ChaCha512::Reset()
{
	if (m_macAuthenticator != nullptr)
	{
		m_macAuthenticator->Reset();
		m_macTag.resize(m_macAuthenticator->TagSize());
	}

	m_isInitialized = false;
	m_cipherState->Reset();
}

NAMESPACE_STREAMEND
