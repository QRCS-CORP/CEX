#include "BCG.h"
#include "BlockCipherFromName.h"
#include "IntegerTools.h"
#include "MemoryTools.h"
#include "ParallelTools.h"
#include "ProviderFromName.h"
#include "Rijndael.h"
#include "SHA2Digests.h"
#include "SHAKE.h"
#include "ShakeModes.h"

NAMESPACE_DRBG

using namespace Cipher::Block::RijndaelBase;
using Enumeration::BlockCipherConvert;
using Enumeration::DrbgConvert;
using Tools::IntegerTools;
using Tools::MemoryTools;
using Tools::ParallelTools;
using Enumeration::ProviderConvert;
using Enumeration::ShakeModes;

const std::vector<uint8_t> BCG::BCG_INFO =
{
	0x42, 0x43, 0x47, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, 0x20, 0x31, 0x2E, 0x30, 0x62
};

class BCG::BcgState
{
public:
	
	SecureVector<uint32_t> RoundKeys;
	SecureVector<uint8_t> Custom;
	SecureVector<uint8_t> Name;
	SecureVector<uint8_t> Nonce;
	uint64_t Counter = 0;
	size_t KeySize = 0;
	size_t Reseed = 0;
	size_t Threshold;
	uint32_t Rounds = 0;
	bool IsDestroyed;
	bool IsInitialized = false;
	bool IsParallel;

	BcgState(size_t ReseedMax, bool Destroyed, bool Parallel)
		:
		RoundKeys(0),
		Custom(0),
		Name(0),
		Nonce(BLOCK_SIZE, 0x00),
		Threshold(ReseedMax),
		IsDestroyed(Destroyed),
		IsParallel(Parallel)
	{
	}

	~BcgState()
	{
		MemoryTools::Clear(RoundKeys, 0, RoundKeys.size() * sizeof(uint32_t));
		MemoryTools::Clear(Custom, 0, Custom.size());
		MemoryTools::Clear(Name, 0, Name.size());
		MemoryTools::Clear(Nonce, 0, Nonce.size());

		Counter = 0;
		KeySize = 0;
		Reseed = 0;
		Rounds = 0;
		Threshold = 0;
		IsDestroyed = false;
		IsInitialized = false;
		IsParallel = false;
	}

	void Reset()
	{
		MemoryTools::Clear(RoundKeys, 0, RoundKeys.size() * sizeof(uint32_t));
		MemoryTools::Clear(Custom, 0, Custom.size());
		MemoryTools::Clear(Name, 0, Name.size());
		MemoryTools::Clear(Nonce, 0, Nonce.size());

		Counter = 0;
		KeySize = 0;
		Rounds = 0;
		IsDestroyed = false;
		IsInitialized = false;
	}
};

//~~~Constructor~~~//

BCG::BCG(Providers ProviderType, bool Parallel)
	:
	DrbgBase(
		Drbgs::BCG, 
		DrbgConvert::ToName(Drbgs::BCG),
		std::vector<SymmetricKeySize> {
			SymmetricKeySize(32, BLOCK_SIZE, 16),
			SymmetricKeySize(64, BLOCK_SIZE, 16),
			SymmetricKeySize(128, BLOCK_SIZE, 16)},
		MAX_OUTPUT,
		MAX_REQUEST,
		MAX_THRESHOLD),
	m_bcgProvider(ProviderType == Providers::None ? 
		nullptr : 
		Helper::ProviderFromName::GetInstance(ProviderType)),
	m_bcgState(new BcgState(DEF_RESEED, true, Parallel)),
	m_parallelProfile(BLOCK_SIZE, true, RESERVE_CACHE, false)
{
}

BCG::BCG(IProvider* Provider, bool Parallel)
	:
	DrbgBase(
		Drbgs::BCG,
		DrbgConvert::ToName(Drbgs::BCG),
		std::vector<SymmetricKeySize> {
			SymmetricKeySize(32, BLOCK_SIZE, 16),
			SymmetricKeySize(64, BLOCK_SIZE, 16),
			SymmetricKeySize(128, BLOCK_SIZE, 16)},
		MAX_OUTPUT,
		MAX_REQUEST,
		MAX_THRESHOLD),
	m_bcgProvider(Provider != nullptr ? 
		Provider :
		throw CryptoGeneratorException(DrbgConvert::ToName(Drbgs::BCG), std::string("Constructor"), std::string("The provider can not be null!"), ErrorCodes::IllegalOperation)),
	m_bcgState(new BcgState(DEF_RESEED, true, Parallel)),
	m_parallelProfile(BLOCK_SIZE, true, RESERVE_CACHE, false)
{
}

BCG::~BCG()
{
	if (m_bcgProvider != nullptr)
	{
		if (m_bcgState->IsDestroyed)
		{
			m_bcgProvider.reset(nullptr);
		}
		else
		{
			m_bcgProvider.release();
		}
	}

	if (m_bcgState != nullptr)
	{
		m_bcgState.reset(nullptr);
	}
}

//~~~Accessors~~~//

const bool BCG::IsInitialized() 
{ 
	return m_bcgState->IsInitialized;
}

const bool BCG::IsParallel()
{
	return m_parallelProfile.IsParallel();
}

const size_t BCG::ParallelBlockSize()
{
	return m_parallelProfile.ParallelBlockSize();
}

ParallelOptions &BCG::ParallelProfile()
{
	return m_parallelProfile;
}

size_t &BCG::ReseedThreshold()
{
	return m_bcgState->Threshold;
}

const size_t BCG::SecurityStrength()
{
	return m_bcgState->KeySize * 8;
}

//~~~Public Functions~~~//

void BCG::Generate(std::vector<uint8_t> &Output)
{
	Generate(Output, 0, Output.size());
}

void BCG::Generate(SecureVector<uint8_t> &Output)
{
	Generate(Output, 0, Output.size());
}

void BCG::Generate(SecureVector<uint8_t> &Output, size_t OutOffset, size_t Length)
{
	if (IsInitialized() == false)
	{
		throw CryptoGeneratorException(Name(), std::string("Generate"), std::string("The generator must be initialized before use!"), ErrorCodes::NotInitialized);
	}
	if ((Output.size() - OutOffset) < Length)
	{
		throw CryptoGeneratorException(Name(), std::string("Generate"), std::string("The output buffer is too small!"), ErrorCodes::InvalidSize);
	}
	if (Length > MaxRequestSize())
	{
		throw CryptoGeneratorException(Name(), std::string("Generate"), std::string("The output buffer is too large, max request is 64KB!"), ErrorCodes::MaxExceeded);
	}

	// fill the output vector with pseudo-random bytes
	Process(Output, OutOffset, Length);

	if (m_bcgProvider != nullptr)
	{
		m_bcgState->Counter += Length;

		// generator must be re-seeded
		if (m_bcgState->Counter >= ReseedThreshold() || CyclicReseed() == true)
		{
			// increment the reseed count
			++m_bcgState->Reseed;

			// if re-seeded more than legal maximum, throw an exception
			if (m_bcgState->Reseed > MaxReseedCount())
			{
				throw CryptoGeneratorException(Name(), std::string("Generate"), std::string("The maximum reseed requests can not be exceeded, re-initialize the generator!"), ErrorCodes::MaxExceeded);
			}

			// the next unused block of output is key material
			SecureVector<uint8_t> tmpk(GEN_STRENGTH / 8);
			// fill the key with pseudo-random
			Process(tmpk, 0, tmpk.size());
			// re-initialize the generator
			Update(tmpk);
			// reset the reseed counter
			m_bcgState->Counter = 0;
		}
	}
}

void BCG::Generate(std::vector<uint8_t> &Output, size_t OutOffset, size_t Length)
{
	if (IsInitialized() == false)
	{
		throw CryptoGeneratorException(Name(), std::string("Generate"), std::string("The generator must be initialized before use!"), ErrorCodes::NotInitialized);
	}
	if ((Output.size() - OutOffset) < Length)
	{
		throw CryptoGeneratorException(Name(), std::string("Generate"), std::string("The output buffer is too small!"), ErrorCodes::InvalidSize);
	}
	if (Length > MaxRequestSize())
	{
		throw CryptoGeneratorException(Name(), std::string("Generate"), std::string("The output buffer is too large, max request is 64KB!"), ErrorCodes::MaxExceeded);
	}

	SecureVector<uint8_t> tmpr(Length);
	Generate(tmpr, 0, Length);
	SecureMove(tmpr, 0, Output, OutOffset, Length);
}

void BCG::Initialize(ISymmetricKey &Parameters)
{
	size_t i;

	if (!SymmetricKeySize::Contains(LegalKeySizes(), Parameters.KeySizes().KeySize()))
	{
		throw CryptoGeneratorException(Name(), std::string("Initialize"), std::string("Invalid key size; key must be one of the LegalKeySizes in length."), ErrorCodes::InvalidKey);
	}
	if (Parameters.KeySizes().IVSize() != BLOCK_SIZE)
	{
		throw CryptoGeneratorException(Name(), std::string("Initialize"), std::string("Requires a nonce equal in size to the ciphers block size!"), ErrorCodes::InvalidNonce);
	}

	// reset for a new key
	if (IsInitialized() == true)
	{
		m_bcgState->Reset();
	}

	m_bcgState->KeySize = Parameters.KeySizes().KeySize() > 256 ? 256 : Parameters.KeySizes().KeySize();
	// set the number of rounds
	m_bcgState->Rounds = Parameters.KeySizes().KeySize() != 128 ? static_cast<uint16_t>((Parameters.KeySizes().KeySize() / 4)) + 14 : 38;
	// create the cSHAKE customization string
	m_bcgState->Custom.resize(Parameters.KeySizes().InfoSize() + BCG_INFO.size());
	// copy the version string to the customization parameter
	MemoryTools::Copy(BCG_INFO, 0, m_bcgState->Custom, 0, BCG_INFO.size());
	// copy the user defined string to the customization parameter
	MemoryTools::Copy(Parameters.Info(), 0, m_bcgState->Custom, BCG_INFO.size(), Parameters.KeySizes().InfoSize());

	// create the cSHAKE name string
	std::string tmpn = Name();
	// add key-size bits, and algorithm name to name string
	m_bcgState->Name.resize(sizeof(uint16_t) + tmpn.size());
	// add the cipher key size in bits as an unsigned int16_t integer
	uint16_t kbits = static_cast<uint16_t>(Parameters.KeySizes().KeySize() * 8);
	IntegerTools::Le16ToBytes(kbits, m_bcgState->Name, 0);
	// copy the name string to state
	MemoryTools::CopyFromObject(tmpn.data(), m_bcgState->Name, sizeof(uint16_t), tmpn.size());
	// copy the nonce to state
	MemoryTools::Copy(Parameters.IV(), 0, m_bcgState->Nonce, 0, BLOCK_SIZE);

	// initialize cSHAKE with k,c,n
	Kdf::SHAKE gen(ShakeModes::SHAKE256);
	gen.Initialize(Parameters.SecureKey(), m_bcgState->Custom, m_bcgState->Name);

	// size the round key array
	const size_t RNKLEN = (BLOCK_SIZE / sizeof(uint32_t)) * (static_cast<size_t>(m_bcgState->Rounds) + 1UL);
	m_bcgState->RoundKeys.resize(RNKLEN);
	// generate the round keys to a temporary uint8_t array
	SecureVector<uint8_t> tmpr(RNKLEN * sizeof(uint32_t));
	// generate the ciphers round-keys
	gen.Generate(tmpr);

	// realign in big endian format
	for (i = 0; i < tmpr.size() / sizeof(uint32_t); ++i)
	{
		m_bcgState->RoundKeys[i] = IntegerTools::BeBytesTo32(tmpr, i * sizeof(uint32_t));
	}

	MemoryTools::Clear(tmpr, 0, tmpr.size());
	m_bcgState->IsInitialized = true;
}

void BCG::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0 || Degree % 2 != 0 || Degree > m_parallelProfile.ProcessorCount())
	{
		throw CryptoGeneratorException(Name(), std::string("ParallelMaxDegree"), std::string("Degree setting is invalid!"), ErrorCodes::IllegalOperation);
	}

	m_parallelProfile.SetMaxDegree(Degree);
}

void BCG::Update(const std::vector<uint8_t> &Key)
{
	SecureVector<uint8_t> tmpk(Key.size());
	MemoryTools::Copy(Key, 0, tmpk, 0, tmpk.size());
	Update(tmpk);
	MemoryTools::Clear(tmpk, 0, tmpk.size());
}

void BCG::Update(const SecureVector<uint8_t> &Key)
{
#if defined(CEX_ENFORCE_LEGALKEY)
	if (!SymmetricKeySize::Contains(LegalKeySizes(), Key.size()))
	{
		throw CryptoGeneratorException(Name(), std::string("Update"), std::string("Invalid key size, the key length must be one of the LegalKeySizes in length!"), ErrorCodes::InvalidKey);
	}
#else
	if (Key.size() < MINKEY_LENGTH)
	{
		throw CryptoGeneratorException(Name(), std::string("Update"), std::string("Key size is invalid; check the key property for accepted value!"), ErrorCodes::InvalidKey);
	}
#endif

	// increment the reseed count
	++m_bcgState->Reseed;

	if (m_bcgState->Reseed > MaxReseedCount())
	{
		throw CryptoGeneratorException(Name(), std::string("Update"), std::string("The maximum reseed requests can not be exceeded, re-initialize the generator!"), ErrorCodes::MaxExceeded);
	}

	// create the new key; this new key is combined with entropy from the provider to create the next key
	SecureVector<uint8_t> tmpk(Key.size());
	MemoryTools::Copy(Key, 0, tmpk, 0, tmpk.size());

	// add new entropy to the key state with the random provider
	if (m_bcgProvider != nullptr)
	{
		Derive(tmpk, m_bcgProvider);
	}

	// reinitialize the generator with the nonce and distribution codes preserved
	SymmetricKey kp(tmpk, m_bcgState->Nonce, m_bcgState->Custom);
	Initialize(kp);
	// reset the reseed counter
	m_bcgState->Counter = 0;
}

//~~~Private Functions~~~//

void BCG::Derive(SecureVector<uint8_t> &Key, std::unique_ptr<IProvider> &Provider)
{
	Kdf::SHAKE gen(ShakeModes::SHAKE256);
	SecureVector<uint8_t> tmpc(GEN_STRENGTH / 8);

	// use random provider to pre-initialize shake to random values: cSHAKE
	Provider->Generate(tmpc);
	// the last unused output from the generator is the key, this preserves some entropy from the previous keyed states
	SymmetricKey kp(Key, tmpc);
	gen.Initialize(kp);
	gen.Generate(Key);
}

CEX_OPTIMIZE_IGNORE
void BCG::PrefetchSbox()
{
	// timing defence: pre-load sbox into l1 cache
	MemoryTools::PrefetchL1(SBox, 0, SBox.size());
}
CEX_OPTIMIZE_RESUME

void BCG::Transform(SecureVector<uint8_t> &Output, size_t OutOffset, size_t Length, SecureVector<uint8_t> &Counter)
{
	size_t bctr;

	bctr = 0;

	// Note: The counter length passed into LEIncrement, only processes the first 16 bytes
	// as the full counter length. This is because this cipher is not expected to encrypt
	// more that 2^128 bytes of data with a single key.

#if defined(CEX_HAS_AVX512)

	const size_t AVX512BLK = 16 * BLOCK_SIZE;

	if (Length >= AVX512BLK)
	{
		const size_t PBKALN = Length - (Length % AVX512BLK);
		SecureVector<uint8_t> tmpc(AVX512BLK);

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

#elif defined(CEX_HAS_AVX2)

	const size_t AVX2BLK = 8 * BLOCK_SIZE;

	if (Length >= AVX2BLK)
	{
		const size_t PBKALN = Length - (Length % AVX2BLK);
		SecureVector<uint8_t> tmpc(AVX2BLK);

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

#elif defined(CEX_HAS_AVX)

	const size_t AVXBLK = 4 * BLOCK_SIZE;

	if (Length >= AVXBLK)
	{
		const size_t PBKALN = Length - (Length % AVXBLK);
		SecureVector<uint8_t> tmpc(AVXBLK);

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
		Transform256(Counter, 0, Output, OutOffset + bctr);
		IntegerTools::LeIncrement(Counter, 16);
		bctr += BLOCK_SIZE;
	}

	if (bctr != Length)
	{
		SecureVector<uint8_t> otp(BLOCK_SIZE);
		Transform256(Counter, 0, otp, 0);
		IntegerTools::LeIncrement(Counter, 16);
		const size_t RMDLEN = Length % BLOCK_SIZE;
		MemoryTools::Copy(otp, 0, Output, OutOffset + (Length - RMDLEN), RMDLEN);
	}
}

void BCG::Process(SecureVector<uint8_t> &Output, size_t OutOffset, size_t Length)
{
	if (!IsParallel() || Length < ParallelBlockSize())
	{
		// not parallel or too small; generate pseudo-random directly to output
		Transform(Output, OutOffset, Length, m_bcgState->Nonce);
	}
	else
	{
		const size_t CNKLEN = ParallelBlockSize() / m_parallelProfile.ParallelMaxDegree();
		const size_t CTRLEN = (CNKLEN / BLOCK_SIZE);
		std::vector<uint8_t> tmpc(BLOCK_SIZE);

		ParallelTools::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Output, OutOffset, &tmpc, CNKLEN, CTRLEN](size_t i)
		{
			// thread level counter
			SecureVector<uint8_t> thdCtr(BLOCK_SIZE);
			// offset counter by chunk size / block size  
			IntegerTools::BeIncrease8(m_bcgState->Nonce, thdCtr, static_cast<uint32_t>(CTRLEN * i));
			// generate random at output offset
			this->Transform(Output, OutOffset + (i * CNKLEN), CNKLEN, thdCtr);
			// store last counter
			if (i == m_parallelProfile.ParallelMaxDegree() - 1)
			{
				MemoryTools::Copy(thdCtr, 0, tmpc, 0, tmpc.size());
			}
		});

		// copy last counter to class variable
		MemoryTools::Copy(tmpc, 0, m_bcgState->Nonce, 0, m_bcgState->Nonce.size());
		// last block processing
		const size_t ALNLEN = CNKLEN * m_parallelProfile.ParallelMaxDegree();

		if (ALNLEN < Length)
		{
			const size_t FNLLEN = Length - ALNLEN;
			OutOffset += ALNLEN;
			Transform(Output, OutOffset, FNLLEN, m_bcgState->Nonce);
		}
	}
}

void BCG::Transform256(const SecureVector<uint8_t> &Input, size_t InOffset, SecureVector<uint8_t> &Output, size_t OutOffset)
{
	SecureVector<uint8_t> state(BLOCK_SIZE, 0x00);
	size_t i;

	MemoryTools::Copy(Input, InOffset, state, 0, BLOCK_SIZE);
	KeyAddition(state, m_bcgState->RoundKeys, 0);

	// pre-load the s-box into L1 cache
#if defined(CEX_PREFETCH_RIJNDAEL_TABLES)
	PrefetchSbox();
#endif

	for (i = 1; i < m_bcgState->Rounds; ++i)
	{
		Substitution(state);
		ShiftRows256(state);
		MixColumns(state);
		KeyAddition(state, m_bcgState->RoundKeys, (i << 3UL));
	}

	Substitution(state);
	ShiftRows256(state);
	KeyAddition(state, m_bcgState->RoundKeys, static_cast<size_t>(m_bcgState->Rounds) << 3UL);

	MemoryTools::Copy(state, 0, Output, OutOffset, BLOCK_SIZE);
}

void BCG::Transform1024(const SecureVector<uint8_t> &Input, size_t InOffset, SecureVector<uint8_t> &Output, size_t OutOffset)
{
	Transform256(Input, InOffset, Output, OutOffset);
	Transform256(Input, InOffset + 32, Output, OutOffset + 32);
	Transform256(Input, InOffset + 64, Output, OutOffset + 64);
	Transform256(Input, InOffset + 96, Output, OutOffset + 96);
}

void BCG::Transform2048(const SecureVector<uint8_t> &Input, size_t InOffset, SecureVector<uint8_t> &Output, size_t OutOffset)
{
	Transform1024(Input, InOffset, Output, OutOffset);
	Transform1024(Input, InOffset + 128, Output, OutOffset + 128);
}

void BCG::Transform4096(const SecureVector<uint8_t> &Input, size_t InOffset, SecureVector<uint8_t> &Output, size_t OutOffset)
{
	Transform2048(Input, InOffset, Output, OutOffset);
	Transform2048(Input, InOffset + 256, Output, OutOffset + 256);
}

NAMESPACE_DRBGEND
