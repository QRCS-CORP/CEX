#include "BCG.h"
#include "BlockCipherFromName.h"
#include "KdfFromName.h"
#include "KDF2.h"
#include "IntUtils.h"
#include "ParallelUtils.h"
#include "ProviderFromName.h"
#include "SHA2Digests.h"
#include "SymmetricKey.h"

NAMESPACE_DRBG

using Utility::IntUtils;
using Utility::MemUtils;

const std::string BCG::CLASS_NAME("BCG");

//~~~Constructor~~~//

BCG::BCG(BlockCiphers CipherType, BlockCipherExtensions CipherExtensionType, Providers ProviderType, bool Parallel)
	:
	m_blockCipher(CipherType != BlockCiphers::None ? Helper::BlockCipherFromName::GetInstance(CipherType, CipherExtensionType) :
		throw CryptoGeneratorException("BCG:CTor", "The Cipher type can not be none!")),
	m_cipherType(CipherType),
	m_ctrVector(COUNTER_SIZE),
	m_destroyEngine(true),
	m_distCode(0),
	m_distCodeMax(m_blockCipher->DistributionCodeMax()),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_kdfEngine(CipherExtensionType != BlockCipherExtensions::None ? Helper::KdfFromName::GetInstance(static_cast<Enumeration::Kdfs>(CipherExtensionType)) : nullptr),
	m_kdfEngineType(CipherExtensionType),
	m_legalKeySizes(m_blockCipher->LegalKeySizes()),
	m_parallelProfile(BLOCK_SIZE, true, m_blockCipher->StateCacheSize(), false),
	m_prdResistant(ProviderType != Providers::None),
	m_providerSource(ProviderType != Providers::None ? Helper::ProviderFromName::GetInstance(ProviderType) : nullptr),
	m_providerType(ProviderType),
	m_reseedCounter(0),
	m_reseedRequests(0),
	m_reseedThreshold(DEF_CYCTHRESH),
	m_secStrength(0),
	m_seedSize(0)
{
	m_parallelProfile.IsParallel() = Parallel;
}

BCG::BCG(IBlockCipher* Cipher, IKdf* Kdf, IProvider* Provider, bool Parallel)
	:
	m_blockCipher(Cipher != 0 ? Cipher : 
		throw CryptoGeneratorException("BCG:CTor", "The Cipher can not be null!")),
	m_cipherType(m_blockCipher->Enumeral()),
	m_ctrVector(COUNTER_SIZE),
	m_destroyEngine(false),
	m_distCode(0),
	m_distCodeMax(m_blockCipher->DistributionCodeMax()),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_kdfEngine(Kdf),
	m_kdfEngineType(m_kdfEngine != nullptr ? static_cast<BlockCipherExtensions>(m_kdfEngine->Enumeral()) : BlockCipherExtensions::None),
	m_legalKeySizes(m_blockCipher->LegalKeySizes()),
	m_parallelProfile(BLOCK_SIZE, true, m_blockCipher->StateCacheSize(), false),
	m_prdResistant(Provider != nullptr),
	m_providerSource(Provider),
	m_providerType(m_providerSource != nullptr ? m_providerSource->Enumeral() : Providers::None),
	m_reseedCounter(0),
	m_reseedRequests(0),
	m_reseedThreshold(DEF_CYCTHRESH),
	m_secStrength(0),
	m_seedSize(0)
{
	m_parallelProfile.IsParallel() = Parallel;
}

BCG::~BCG()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_cipherType = BlockCiphers::None;
		m_distCodeMax = 0;
		m_isEncryption = false;
		m_isInitialized = false;
		m_kdfEngineType = BlockCipherExtensions::None;
		m_parallelProfile.Reset();
		m_prdResistant = false;
		m_providerType = Providers::None;
		m_reseedCounter = 0;
		m_reseedRequests = 0;
		m_reseedThreshold = 0;
		m_secStrength = 0;
		m_seedSize = 0;

		IntUtils::ClearVector(m_ctrVector);
		IntUtils::ClearVector(m_distCode);
		IntUtils::ClearVector(m_distCode);
		IntUtils::ClearVector(m_legalKeySizes);

		if (m_destroyEngine)
		{
			m_destroyEngine = false;

			if (m_blockCipher != nullptr)
			{
				m_blockCipher.reset(nullptr);
			}

			if (m_kdfEngine != nullptr)
			{
				m_kdfEngine.reset(nullptr);
			}

			if (m_providerSource != nullptr)
			{
				m_providerSource.reset(nullptr);
			}
		}
		else
		{
			if (m_blockCipher != nullptr)
			{
				m_blockCipher.release();
			}

			if (m_kdfEngine != nullptr)
			{
				m_kdfEngine.release();
			}

			if (m_providerSource != nullptr)
			{
				m_providerSource.release();
			}
		}
	}
}

//~~~Accessors~~~//

std::vector<byte> &BCG::DistributionCode() 
{
	return m_distCode; 
}

const size_t BCG::DistributionCodeMax()
{ 
	return m_distCodeMax; 
}

const Drbgs BCG::Enumeral() 
{ 
	return Drbgs::BCG; 
}

const bool BCG::IsInitialized() 
{ 
	return m_isInitialized; 
}

const bool BCG::IsParallel()
{ 
	return m_parallelProfile.IsParallel();
}

std::vector<SymmetricKeySize> BCG::LegalKeySizes() const 
{ 
	return m_legalKeySizes; 
};

const ulong BCG::MaxOutputSize() 
{
	return MAX_OUTPUT; 
}

const size_t BCG::MaxRequestSize()
{ 
	return MAX_REQUEST; 
}

const size_t BCG::MaxReseedCount() 
{ 
	return MAX_RESEED;
}

const std::string BCG::Name()
{ 
	return CLASS_NAME + "-" + m_blockCipher->Name();
}

const size_t BCG::NonceSize()
{
	return COUNTER_SIZE; 
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
	return m_reseedThreshold; 
}

const size_t BCG::SecurityStrength()
{
	return m_secStrength;
}

//~~~Public Functions~~~//

size_t BCG::Generate(std::vector<byte> &Output)
{
	return Generate(Output, 0, Output.size());
}

size_t BCG::Generate(std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	if (!m_isInitialized)
	{
		throw CryptoGeneratorException("BCG:Generate", "The generator must be initialized before use!");
	}
	if ((Output.size() - OutOffset) < Length)
	{
		throw CryptoGeneratorException("BCG:Generate", "The output buffer is too small!");
	}

	GenerateBlock(Output, OutOffset, Length);

	if (m_prdResistant)
	{
		m_reseedCounter += Length;

		if (m_reseedCounter >= m_reseedThreshold)
		{
			++m_reseedRequests;

			if (m_reseedRequests > MAX_RESEED)
			{
				throw CryptoGeneratorException("BCG:Generate", "The maximum reseed requests can not be exceeded, re-initialize the generator!");
			}

			m_reseedCounter = 0;
			// use next block of state as seed material
			std::vector<byte> state(32);
			GenerateBlock(state, 0, state.size());
			// combine with salt from entropy provider, extract, and re-key
			Derive(state);
		}
	}

	return Length;
}

void BCG::Initialize(ISymmetricKey &GenParam)
{
	if (GenParam.Nonce().size() != 0)
	{
		if (GenParam.Info().size() != 0)
		{
			Initialize(GenParam.Key(), GenParam.Nonce(), GenParam.Info());
		}
		else
		{
			Initialize(GenParam.Key(), GenParam.Nonce());
		}
	}
	else
	{
		Initialize(GenParam.Key());
	}
}

void BCG::Initialize(const std::vector<byte> &Seed)
{
	if (!m_isInitialized)
	{
		if (!SymmetricKeySize::Contains(LegalKeySizes(), Seed.size() - BLOCK_SIZE, BLOCK_SIZE))
		{
			throw CryptoGeneratorException("BCG:Initialize", "Seed size is invalid! Check LegalKeySizes for accepted values.");
		}

		m_seedSize = Seed.size();
	}

	// counter is always left-most bytes
	MemUtils::Copy(Seed, 0, m_ctrVector, 0, BLOCK_SIZE);
	// initialize the block cipher
	size_t keyLen = Seed.size() - BLOCK_SIZE;
	// security upper bound is 256, could actually be more depending on cipher configuration
	m_secStrength = (keyLen >= 32) ? 256 : keyLen * 8;
	std::vector<byte> key(keyLen);
	MemUtils::Copy(Seed, BLOCK_SIZE, key, 0, keyLen);
	m_blockCipher->Initialize(true, Key::Symmetric::SymmetricKey(key));
	m_isInitialized = true;
}

void BCG::Initialize(const std::vector<byte> &Seed, const std::vector<byte> &Nonce)
{
	std::vector<byte> key(Seed.size() + Nonce.size());

	if (Nonce.size() > 0)
	{
		MemUtils::Copy(Nonce, 0, key, 0, Nonce.size());
	}
	if (Seed.size() > 0)
	{
		MemUtils::Copy(Seed, 0, key, Nonce.size(), Seed.size());
	}

	Initialize(key);
}

void BCG::Initialize(const std::vector<byte> &Seed, const std::vector<byte> &Nonce, const std::vector<byte> &Info)
{
	std::vector<byte> key(Nonce.size() + Seed.size());

	if (Nonce.size() > 0)
	{
		MemUtils::Copy(Nonce, 0, key, 0, Nonce.size());
	}

	if (Seed.size() > 0)
	{
		MemUtils::Copy(Seed, 0, key, Nonce.size(), Seed.size());
	}

	if (Info.size() > 0)
	{
		// info maps to HX ciphers HKDF Info parameter, value is ignored on a standard cipher
		if (m_cipherType != BlockCiphers::Rijndael &&
			m_cipherType != BlockCiphers::Serpent)
		{
			// extended cipher; sets info as HX cipher distribution code.
			// for best security, info should be secret, random, and DistributionCodeMax size
			if (Info.size() <= m_blockCipher->DistributionCodeMax())
			{
				m_distCode = Info;
				m_blockCipher->DistributionCode() = m_distCode;
			}
			else
			{
				// info is too large; size to optimal max, ignore remainder
				std::vector<byte> tmpInfo(m_blockCipher->DistributionCodeMax());
				MemUtils::Copy(Info, 0, tmpInfo, 0, tmpInfo.size());
				m_distCode = tmpInfo;
				m_blockCipher->DistributionCode() = m_distCode;
			}
		}
	}

	Initialize(key);
}

void BCG::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0 || Degree % 2 != 0 || Degree > m_parallelProfile.ProcessorCount())
	{
		throw CryptoGeneratorException("BCG::ParallelMaxDegree", "Degree setting is invalid!");
	}

	m_parallelProfile.SetMaxDegree(Degree);
}

void BCG::Update(const std::vector<byte> &Seed)
{
	if (Seed.size() != m_seedSize)
	{
		throw CryptoGeneratorException("BCG::Update", "Update seed size must be equal to seed size used to initialize the generator!");
	}

	Initialize(Seed);
}

//~~~Private Functions~~~//

void BCG::Derive(std::vector<byte> &Seed)
{
	// size the salt for max unpadded hash size; subtract counter and hash finalizer code lengths
	Kdf::KDF2 gen(Enumeration::SHA2Digests::SHA256);
	SymmetricKeySize ks = gen.LegalKeySizes()[1];
	size_t saltLen = ks.KeySize();
	std::vector<byte> salt(saltLen);
	// pull the rand from provider
	m_providerSource->Generate(salt);
	// extract the new key+counter
	gen.Initialize(Seed, salt);
	std::vector<byte> tmpK(m_seedSize);
	gen.Generate(tmpK);
	// reinitialize with the new key and counter
	Initialize(tmpK);
}

void BCG::GenerateBlock(std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	if (!IsParallel() || Length < ParallelBlockSize())
	{
		// not parallel or too small; generate 1 p-rand block
		Transform(Output, OutOffset, Length, m_ctrVector);
	}
	else
	{
		const size_t OUTLEN = Length;
		const size_t CNKLEN = ParallelBlockSize() / m_parallelProfile.ParallelMaxDegree();
		const size_t CTRLEN = (CNKLEN / BLOCK_SIZE);
		std::vector<byte> tmpCtr(m_ctrVector.size());

		Utility::ParallelUtils::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Output, OutOffset, &tmpCtr, CNKLEN, CTRLEN](size_t i)
		{
			// thread level counter
			std::vector<byte> thdCtr(m_ctrVector.size());
			// offset counter by chunk size / block size  
			IntUtils::BeIncrease8(m_ctrVector, thdCtr, CTRLEN * i);
			// generate random at output offset
			this->Transform(Output, OutOffset + (i * CNKLEN), CNKLEN, thdCtr);
			// store last counter
			if (i == m_parallelProfile.ParallelMaxDegree() - 1)
			{
				MemUtils::Copy(thdCtr, 0, tmpCtr, 0, tmpCtr.size());
			}
		});

		// copy last counter to class variable
		MemUtils::Copy(tmpCtr, 0, m_ctrVector, 0, m_ctrVector.size());
		// last block processing
		const size_t ALNLEN = CNKLEN * m_parallelProfile.ParallelMaxDegree();

		if (ALNLEN < OUTLEN)
		{
			const size_t FNLLEN = Length % ALNLEN;
			Transform(Output, ALNLEN, FNLLEN, m_ctrVector);
		}
	}
}

void BCG::Transform(std::vector<byte> &Output, const size_t OutOffset, const size_t Length, std::vector<byte> &Counter)
{
	size_t blkCtr = 0;

#if defined(__AVX512__)
	const size_t AVX512BLK = 16 * BLOCK_SIZE;
	if (Length >= AVX512BLK)
	{
		const size_t PBKALN = Length - (Length % AVX512BLK);
		std::vector<byte> ctrBlk(AVX512BLK);

		// stagger counters and process 8 blocks with avx
		while (blkCtr != PBKALN)
		{
			MemUtils::COPY128(Counter, 0, ctrBlk, 0);
			IntUtils::BeIncrement8(Counter);
			MemUtils::COPY128(Counter, 0, ctrBlk, 16);
			IntUtils::BeIncrement8(Counter);
			MemUtils::COPY128(Counter, 0, ctrBlk, 32);
			IntUtils::BeIncrement8(Counter);
			MemUtils::COPY128(Counter, 0, ctrBlk, 48);
			IntUtils::BeIncrement8(Counter);
			MemUtils::COPY128(Counter, 0, ctrBlk, 64);
			IntUtils::BeIncrement8(Counter);
			MemUtils::COPY128(Counter, 0, ctrBlk, 80);
			IntUtils::BeIncrement8(Counter);
			MemUtils::COPY128(Counter, 0, ctrBlk, 96);
			IntUtils::BeIncrement8(Counter);
			MemUtils::COPY128(Counter, 0, ctrBlk, 112);
			IntUtils::BeIncrement8(Counter);
			MemUtils::COPY128(Counter, 0, ctrBlk, 128);
			IntUtils::BeIncrement8(Counter);
			MemUtils::COPY128(Counter, 0, ctrBlk, 144);
			IntUtils::BeIncrement8(Counter);
			MemUtils::COPY128(Counter, 0, ctrBlk, 160);
			IntUtils::BeIncrement8(Counter);
			MemUtils::COPY128(Counter, 0, ctrBlk, 176);
			IntUtils::BeIncrement8(Counter);
			MemUtils::COPY128(Counter, 0, ctrBlk, 192);
			IntUtils::BeIncrement8(Counter);
			MemUtils::COPY128(Counter, 0, ctrBlk, 208);
			IntUtils::BeIncrement8(Counter);
			MemUtils::COPY128(Counter, 0, ctrBlk, 224);
			IntUtils::BeIncrement8(Counter);
			MemUtils::COPY128(Counter, 0, ctrBlk, 240);
			IntUtils::BeIncrement8(Counter);
			m_blockCipher->Transform2048(ctrBlk, 0, Output, OutOffset + blkCtr);
			blkCtr += AVX512BLK;
		}
	}
#elif defined(__AVX2__)
	const size_t AVX2BLK = 8 * BLOCK_SIZE;
	if (Length >= AVX2BLK)
	{
		const size_t PBKALN = Length - (Length % AVX2BLK);
		std::vector<byte> ctrBlk(AVX2BLK);

		// stagger counters and process 8 blocks with avx
		while (blkCtr != PBKALN)
		{
			MemUtils::COPY128(Counter, 0, ctrBlk, 0);
			IntUtils::BeIncrement8(Counter);
			MemUtils::COPY128(Counter, 0, ctrBlk, 16);
			IntUtils::BeIncrement8(Counter);
			MemUtils::COPY128(Counter, 0, ctrBlk, 32);
			IntUtils::BeIncrement8(Counter);
			MemUtils::COPY128(Counter, 0, ctrBlk, 48);
			IntUtils::BeIncrement8(Counter);
			MemUtils::COPY128(Counter, 0, ctrBlk, 64);
			IntUtils::BeIncrement8(Counter);
			MemUtils::COPY128(Counter, 0, ctrBlk, 80);
			IntUtils::BeIncrement8(Counter);
			MemUtils::COPY128(Counter, 0, ctrBlk, 96);
			IntUtils::BeIncrement8(Counter);
			MemUtils::COPY128(Counter, 0, ctrBlk, 112);
			IntUtils::BeIncrement8(Counter);
			m_blockCipher->Transform1024(ctrBlk, 0, Output, OutOffset + blkCtr);
			blkCtr += AVX2BLK;
		}
	}
#elif defined(__AVX__)
	const size_t AVXBLK = 4 * BLOCK_SIZE;
	if (Length >= AVXBLK)
	{
		const size_t PBKALN = Length - (Length % AVXBLK);
		std::vector<byte> ctrBlk(AVXBLK);

		// 4 blocks with sse
		while (blkCtr != PBKALN)
		{
			MemUtils::COPY128(Counter, 0, ctrBlk, 0);
			IntUtils::BeIncrement8(Counter);
			MemUtils::COPY128(Counter, 0, ctrBlk, 16);
			IntUtils::BeIncrement8(Counter);
			MemUtils::COPY128(Counter, 0, ctrBlk, 32);
			IntUtils::BeIncrement8(Counter);
			MemUtils::COPY128(Counter, 0, ctrBlk, 48);
			IntUtils::BeIncrement8(Counter);
			m_blockCipher->Transform512(ctrBlk, 0, Output, OutOffset + blkCtr);
			blkCtr += AVXBLK;
		}
	}
#endif

	const size_t BLKALN = Length - (Length % BLOCK_SIZE);
	while (blkCtr != BLKALN)
	{
		m_blockCipher->EncryptBlock(Counter, 0, Output, OutOffset + blkCtr);
		IntUtils::BeIncrement8(Counter);
		blkCtr += BLOCK_SIZE;
	}

	if (blkCtr != Length)
	{
		std::vector<byte> outputBlock(BLOCK_SIZE);
		m_blockCipher->EncryptBlock(Counter, outputBlock);
		const size_t FNLLEN = Length % BLOCK_SIZE;
		MemUtils::Copy(outputBlock, 0, Output, OutOffset + (Length - FNLLEN), FNLLEN);
		IntUtils::BeIncrement8(Counter);
	}
}

NAMESPACE_DRBGEND
