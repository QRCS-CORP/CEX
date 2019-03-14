#include "BCG.h"
#include "ArrayTools.h"
#include "BlockCipherFromName.h"
#include "IntegerTools.h"
#include "ParallelTools.h"
#include "ProviderFromName.h"
#include "SHA2Digests.h"
#include "SHAKE.h"
#include "ShakeModes.h"

NAMESPACE_DRBG

using Enumeration::BlockCipherConvert;
using Enumeration::DrbgConvert;
using Utility::ArrayTools;
using Utility::IntegerTools;
using Utility::MemoryTools;
using Enumeration::ProviderConvert;
using Enumeration::ShakeModes;

class BCG::BcgState
{
public:
	
	std::vector<byte> Code;
	std::vector<byte> Nonce;
	size_t Counter;
	size_t KeySize;
	size_t Reseed;
	size_t Threshold;
	ushort Strength;
	bool IsParallel;

	BcgState(size_t ReseedMax, bool Parallel)
		:
		Nonce(BLOCK_SIZE),
		Counter(0),
		KeySize(0),
		Reseed(0),
		Threshold(ReseedMax),
		Strength(0),
		IsParallel(Parallel)
	{
	}

	~BcgState()
	{
		MemoryTools::Clear(Nonce, 0, Nonce.size());
		Counter = 0;
		KeySize = 0;
		Reseed = 0;
		Threshold = 0;
		Strength = 0;
		IsParallel = false;
	}

	void Reset()
	{
		MemoryTools::Clear(Nonce, 0, Nonce.size());
		Counter = 0;
		KeySize = 0;
		Reseed = 0;
		Strength = 0;
	}
};

//~~~Constructor~~~//

BCG::BCG(BlockCiphers CipherType, Providers ProviderType, bool Parallel)
	:
	DrbgBase(
		Drbgs::BCG, 
		(DrbgConvert::ToName(Drbgs::BCG) + std::string("-") + BlockCipherConvert::ToName(CipherType)),
		((CipherType == BlockCiphers::AES || CipherType == BlockCiphers::Serpent) ?
			std::vector<SymmetricKeySize> {
				SymmetricKeySize(16, BLOCK_SIZE, 0),
				SymmetricKeySize(24, BLOCK_SIZE, 0),
				SymmetricKeySize(32, BLOCK_SIZE, 0)} :
			std::vector<SymmetricKeySize> {
				SymmetricKeySize(32, BLOCK_SIZE, 16),
				SymmetricKeySize(64, BLOCK_SIZE, 16),
				SymmetricKeySize(128, BLOCK_SIZE, 16)}),
		MAX_OUTPUT,
		MAX_REQUEST,
		MAX_THRESHOLD),
	m_bcgCipher(CipherType != BlockCiphers::None ? Helper::BlockCipherFromName::GetInstance(CipherType) :
		throw CryptoGeneratorException(DrbgConvert::ToName(Drbgs::BCG), std::string("Constructor"), std::string("The Cipher type can not be none!"), ErrorCodes::InvalidParam)),
	m_bcgProvider(ProviderType == Providers::None ? nullptr : Helper::ProviderFromName::GetInstance(ProviderType)),
	m_bcgState(new BcgState(DEF_RESEED, Parallel)),
	m_isDestroyed(true),
	m_isInitialized(false),
	m_parallelProfile(BLOCK_SIZE, true, m_bcgCipher->StateCacheSize(), false)
{
}

BCG::BCG(IBlockCipher* Cipher, IProvider* Provider, bool Parallel)
	:
	DrbgBase(
		Drbgs::BCG,
		(Cipher != nullptr ? DrbgConvert::ToName(Drbgs::BCG) + std::string("-") + BlockCipherConvert::ToName(Cipher->Enumeral()) :
			throw CryptoGeneratorException(DrbgConvert::ToName(Drbgs::BCG), std::string("Constructor"), std::string("The Cipher can not be null!"), ErrorCodes::InvalidParam)),
		(Cipher != nullptr ? (Cipher->Enumeral() == BlockCiphers::AES || Cipher->Enumeral() == BlockCiphers::Serpent) ?
			std::vector<SymmetricKeySize> {
				SymmetricKeySize(16, BLOCK_SIZE, 0),
				SymmetricKeySize(24, BLOCK_SIZE, 0),
				SymmetricKeySize(32, BLOCK_SIZE, 0)} :
			std::vector<SymmetricKeySize>{
				SymmetricKeySize(32, BLOCK_SIZE, 16),
				SymmetricKeySize(64, BLOCK_SIZE, 16),
				SymmetricKeySize(128, BLOCK_SIZE, 16)} :
					throw CryptoGeneratorException(DrbgConvert::ToName(Drbgs::BCG), std::string("Constructor"), std::string("The Cipher can not be null!"), ErrorCodes::InvalidParam)),
		MAX_OUTPUT,
		MAX_REQUEST,
		MAX_THRESHOLD),
	m_bcgCipher(Cipher),
	m_bcgProvider(Provider),
	m_bcgState(new BcgState(DEF_RESEED, Parallel)),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_parallelProfile(BLOCK_SIZE, true, m_bcgCipher->StateCacheSize(), false)
{
}

BCG::~BCG()
{
	m_isInitialized = false;

	if (m_isDestroyed)
	{
		m_isDestroyed = false;

		if (m_bcgCipher != nullptr)
		{
			m_bcgCipher.reset(nullptr);
		}

		if (m_bcgProvider != nullptr)
		{
			m_bcgProvider.reset(nullptr);
		}
	}
	else
	{
		if (m_bcgCipher != nullptr)
		{
			m_bcgCipher.release();
		}

		if (m_bcgProvider != nullptr)
		{
			m_bcgProvider.release();
		}
	}
}

//~~~Accessors~~~//

const size_t BCG::DistributionCodeMax()
{ 
	SymmetricKeySize ks = m_bcgCipher->LegalKeySizes()[2];
	return ks.InfoSize();
}

const bool BCG::IsInitialized() 
{ 
	return m_isInitialized; 
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
	return static_cast<size_t>(m_bcgState->Strength);
}

//~~~Public Functions~~~//

void BCG::Generate(std::vector<byte> &Output)
{
	Generate(Output, 0, Output.size());
}

void BCG::Generate(SecureVector<byte> &Output)
{
	Generate(Output, 0, Output.size());
}

void BCG::Generate(std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	if (!IsInitialized())
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
	Expand(Output, OutOffset, Length);

	if (m_bcgProvider != nullptr)
	{
		m_bcgState->Counter += Length;

		// generator must be re-seeded
		if (m_bcgState->Counter >= ReseedThreshold())
		{
			// increment the reseed count
			++m_bcgState->Reseed;

			// if re-seeded more than legal maximum, throw an exception
			if (m_bcgState->Reseed > MaxReseedCount())
			{
				throw CryptoGeneratorException(Name(), std::string("Generate"), std::string("The maximum reseed requests can not be exceeded, re-initialize the generator!"), ErrorCodes::MaxExceeded);
			}

			// the next unused block of output is key material
			std::vector<byte> tmpk(m_bcgState->KeySize);
			// fill the key with pseudo-random
			Expand(tmpk, 0, tmpk.size());
			// create the new key; this new key is combined with entropy from the provider to create the next key
			Derive(tmpk, m_bcgState, m_bcgProvider);
			// re-initialize the generator, the nonce and distribution codes are preserved
			Update(tmpk);
			// reset the reseed counter
			m_bcgState->Counter = 0;
		}
	}
}

void BCG::Generate(SecureVector<byte> &Output, size_t OutOffset, size_t Length)
{
	std::vector<byte> tmpr(Length);
	Generate(tmpr, 0, Length);
	Move(tmpr, Output, OutOffset);
}

void BCG::Initialize(ISymmetricKey &Parameters)
{
#if defined(CEX_ENFORCE_LEGALKEY)
	if (!SymmetricKeySize::Contains(LegalKeySizes(), Parameters.KeySizes().KeySize(), Parameters.Nonce.KeySizes()))
	{
		throw CryptoGeneratorException(Name(), std::string("Initialize"), std::string("Invalid key size, the key length must be one of the LegalKeySizes in length!"), ErrorCodes::InvalidKey);
	}
#else
	if (Parameters.KeySizes().KeySize() < MINKEY_LENGTH)
	{
		throw CryptoGeneratorException(Name(), std::string("Initialize"), std::string("Key size is invalid; check LegalKeySizes for accepted values!"), ErrorCodes::InvalidNonce);
	}
	if (Parameters.KeySizes().NonceSize() != BLOCK_SIZE)
	{
		throw CryptoGeneratorException(Name(), std::string("Initialize"), std::string("Nonce size is invalid; check LegalKeySizes for accepted values!"), ErrorCodes::InvalidNonce);
	}
#endif

	// set state initialization values
	m_bcgState->Reset();
	m_parallelProfile.IsParallel() = m_bcgState->IsParallel;
	m_bcgState->KeySize = Parameters.KeySizes().KeySize();
	m_bcgState->Strength = static_cast<ushort>(Parameters.KeySizes().KeySize()) * 8;

	if (m_bcgCipher->Enumeral() == BlockCiphers::AES || m_bcgCipher->Enumeral() == BlockCiphers::Serpent)
	{
		// standard block-cipher initializion, generator will emit CTR(cipher) output
		SymmetricKey kp(Parameters.Key());
		m_bcgCipher->Initialize(true, kp);
	}
	else
	{
		// using extended cipher version and custom distribution-code
		// add the library prefix
		ArrayTools::AppendVector(CEX_LIBRARY_PREFIX, m_bcgState->Code);
		// assign the formal class name, and the security-strength to the distribution code parameter
		ArrayTools::AppendString(Name(), m_bcgState->Code);
		ArrayTools::AppendValue(static_cast<ushort>(SecurityStrength()), m_bcgState->Code);
		// add the optional custom distribution code
		ArrayTools::AppendVector(Parameters.Info(), m_bcgState->Code);
		// initialize the block cipher
		SymmetricKey kp(Parameters.Key(), Parameters.Nonce(), m_bcgState->Code);
		m_bcgCipher->Initialize(true, kp);
	}

	// copy the nonce to state
	MemoryTools::Copy(Parameters.Nonce(), 0, m_bcgState->Nonce, 0, BLOCK_SIZE);
	m_isInitialized = true;
}

void BCG::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0 || Degree % 2 != 0 || Degree > m_parallelProfile.ProcessorCount())
	{
		throw CryptoGeneratorException(Name(), std::string("ParallelMaxDegree"), std::string("Degree setting is invalid!"), ErrorCodes::IllegalOperation);
	}

	m_parallelProfile.SetMaxDegree(Degree);
}

void BCG::Update(const std::vector<byte> &Key)
{
#if defined(CEX_ENFORCE_LEGALKEY)
	if (!SymmetricKeySize::Contains(LegalKeySizes(), Key.size()))
	{
		throw CryptoGeneratorException(Name(), std::string("Update"), std::string("Invalid key size, the key length must be one of the LegalKeySizes in length!"), ErrorCodes::InvalidKey);
	}
#else
	if (Key.size() < MINKEY_LENGTH)
	{
		throw CryptoGeneratorException(Name(), std::string("Update"), std::string("Key size is invalid; check the legalkey property for accepted value!"), ErrorCodes::InvalidKey);
	}
#endif

	if (Key.size() < SecurityStrength() / 8)
	{
		throw CryptoGeneratorException(Name(), std::string("Update"), std::string("The key is too small; check the legalkey property for accepted value!"), ErrorCodes::InvalidKey);
	}

	// increment the reseed count
	++m_bcgState->Reseed;

	if (m_bcgState->Reseed > MaxReseedCount())
	{
		throw CryptoGeneratorException(Name(), std::string("Update"), std::string("The maximum reseed requests can not be exceeded, re-initialize the generator!"), ErrorCodes::MaxExceeded);
	}

	// create the new key; this new key is combined with entropy from the provider to create the next key
	std::vector<byte> tmpk(Key.size());
	MemoryTools::Copy(Key, 0, tmpk, 0, tmpk.size());

	// add new entropy to the key state with the random provider
	if (m_bcgProvider != nullptr)
	{
		Derive(tmpk, m_bcgState, m_bcgProvider);
	}

	// reinitialize the generator with the nonce and distribution codes preserved
	SymmetricKey kp(tmpk, m_bcgState->Nonce, m_bcgState->Code);
	m_bcgCipher->Initialize(true, kp);
	// reset the reseed counter
	m_bcgState->Counter = 0;
}

void BCG::Update(const SecureVector<byte> &Key)
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
	std::vector<byte> tmpk(Key.size());
	MemoryTools::Copy(Key, 0, tmpk, 0, tmpk.size());

	// add new entropy to the key state with the random provider
	if (m_bcgProvider != nullptr)
	{
		Derive(tmpk, m_bcgState, m_bcgProvider);
	}

	// reinitialize the generator with the nonce and distribution codes preserved
	SymmetricKey kp(tmpk, m_bcgState->Nonce, m_bcgState->Code);
	m_bcgCipher->Initialize(true, kp);
	// reset the reseed counter
	m_bcgState->Counter = 0;
}

//~~~Private Functions~~~//

void BCG::Derive(std::vector<byte> &Key, std::unique_ptr<BcgState> &State, std::unique_ptr<IProvider> &Provider)
{
	ShakeModes mode;

	switch (State->Strength)
	{
	case 128:
		mode = ShakeModes::SHAKE128;
		break;
	case 256:
		mode = ShakeModes::SHAKE256;
		break;
	case 512:
		mode = ShakeModes::SHAKE512;
		break;
	case 1024:
		mode = ShakeModes::SHAKE1024;
		break;
	default:
		mode = ShakeModes::SHAKE256;
	}

	Kdf::SHAKE gen(mode);
	std::vector<byte> tmpc(State->KeySize);

	// use random provider to pre-initialize shake to random values: cSHAKE
	Provider->Generate(tmpc);
	// the last unused output from the generator is the key, this preserves some entropy from the previous keyed states
	SymmetricKey kp(Key, tmpc);
	gen.Initialize(kp);
	gen.Generate(Key);
}

void BCG::Expand(std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	if (!IsParallel() || Length < ParallelBlockSize())
	{
		// not parallel or too small; generate pseudo-random directly to output
		Permute(Output, OutOffset, Length, m_bcgState->Nonce, m_bcgCipher);
	}
	else
	{
		const size_t OUTLEN = Length;
		const size_t CNKLEN = ParallelBlockSize() / m_parallelProfile.ParallelMaxDegree();
		const size_t CTRLEN = (CNKLEN / BLOCK_SIZE);
		std::vector<byte> tmpc(BLOCK_SIZE);

		Utility::ParallelTools::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Output, OutOffset, &tmpc, CNKLEN, CTRLEN](size_t i)
		{
			// thread level counter
			std::vector<byte> thdCtr(BLOCK_SIZE);
			// offset counter by chunk size / block size  
			IntegerTools::BeIncrease8(m_bcgState->Nonce, thdCtr, static_cast<uint>(CTRLEN * i));
			// generate random at output offset
			this->Permute(Output, OutOffset + (i * CNKLEN), CNKLEN, thdCtr, m_bcgCipher);
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

		if (ALNLEN < OUTLEN)
		{
			const size_t FNLLEN = Length % ALNLEN;
			Permute(Output, ALNLEN, FNLLEN, m_bcgState->Nonce, m_bcgCipher);
		}
	}
}

void BCG::Permute(std::vector<byte> &Output, size_t OutOffset, size_t Length, std::vector<byte> &Counter, std::unique_ptr<IBlockCipher> &Cipher)
{
	size_t bctr = 0;

#if defined(__AVX512__)

	const size_t AVX512BLK = 16 * BLOCK_SIZE;

	if (Length >= AVX512BLK)
	{
		const size_t PBKALN = Length - (Length % AVX512BLK);
		std::vector<byte> tmpc(AVX512BLK);

		// stagger counters and process 8 blocks with avx512
		while (bctr != PBKALN)
		{
			MemoryTools::COPY128(Counter, 0, tmpc, 0);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 16);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 32);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 48);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 64);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 80);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 96);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 112);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 128);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 144);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 160);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 176);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 192);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 208);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 224);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 240);
			IntegerTools::BeIncrement8(Counter);
			Cipher->Transform2048(tmpc, 0, Output, OutOffset + bctr);
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
			MemoryTools::COPY128(Counter, 0, tmpc, 0);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 16);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 32);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 48);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 64);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 80);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 96);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 112);
			IntegerTools::BeIncrement8(Counter);
			Cipher->Transform1024(tmpc, 0, Output, OutOffset + bctr);
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
			MemoryTools::COPY128(Counter, 0, tmpc, 0);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 16);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 32);
			IntegerTools::BeIncrement8(Counter);
			MemoryTools::COPY128(Counter, 0, tmpc, 48);
			IntegerTools::BeIncrement8(Counter);
			Cipher->Transform512(tmpc, 0, Output, OutOffset + bctr);
			bctr += AVXBLK;
		}
	}

#endif

	const size_t BLKALN = Length - (Length % BLOCK_SIZE);

	while (bctr != BLKALN)
	{
		Cipher->EncryptBlock(Counter, 0, Output, OutOffset + bctr);
		IntegerTools::BeIncrement8(Counter);
		bctr += BLOCK_SIZE;
	}

	if (bctr != Length)
	{
		std::vector<byte> tmps(BLOCK_SIZE);
		Cipher->EncryptBlock(Counter, tmps);
		const size_t FNLLEN = Length % BLOCK_SIZE;
		MemoryTools::Copy(tmps, 0, Output, OutOffset + (Length - FNLLEN), FNLLEN);
		IntegerTools::BeIncrement8(Counter);
	}
}

NAMESPACE_DRBGEND
