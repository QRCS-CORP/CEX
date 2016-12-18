#include "CMG.h"
#include "ArrayUtils.h"
#include "BlockCipherFromName.h"
#include "CpuDetect.h"
#include "DigestFromName.h"
#include "KDF2.h"
#include "ISymmetricKey.h"
#include "ParallelUtils.h"
#include "ProviderFromName.h"
#include "SymmetricKey.h"

NAMESPACE_DRBG

//~~~Public Methods~~~//

void CMG::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_blockSize = 0;
		m_cipherType = BlockCiphers::None;
		m_hasAVX2 = false;
		m_hasSSE = false;
		m_isEncryption = false;
		m_isInitialized = false;
		m_isParallel = false;
		m_kdfEngineType = Digests::None;
		m_prdResistant = false;
		m_processorCount = 0;
		m_parallelBlockSize = 0;
		m_parallelMaxDegree = 0;
		m_parallelMinimumSize = 0;
		m_providerType = Providers::None;
		m_reseedCounter = 0;
		m_reseedRequests = 0;
		m_reseedThreshold = 0;
		m_secStrength = 0;
		m_seedSize = 0;

		try
		{
			if (m_destroyEngine)
			{
				m_destroyEngine = false;

				if (m_blockCipher != 0)
					delete m_blockCipher;
				if (m_kdfEngine != 0)
					delete m_kdfEngine;
				if (m_providerSource != 0)
					delete m_providerSource;
			}

			Utility::ArrayUtils::ClearVector(m_ctrVector);
			Utility::ArrayUtils::ClearVector(m_kdfInfo);
			Utility::ArrayUtils::ClearVector(m_legalKeySizes);
		}
		catch(std::exception& ex)
		{
			throw CryptoGeneratorException("CMG::Destroy", "Could not clear all variables!", std::string(ex.what()));
		}
	}
}

size_t CMG::Generate(std::vector<byte> &Output)
{
	return Generate(Output, 0, Output.size());
}

size_t CMG::Generate(std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	if (!m_isInitialized)
		throw CryptoGeneratorException("CMG:Generate", "The generator must be initialized before use!");
	if ((Output.size() - Length) < OutOffset)
		throw CryptoGeneratorException("CMG:Generate", "Output buffer too small!");
	if (m_reseedRequests > MAX_RESEED)
		throw CryptoGeneratorException("DCG:Generate", "The maximum reseed requests have been exceeded!");
	if (Length > m_parallelBlockSize)
		throw CryptoGeneratorException("DCG:Generate", "The maximum request size is has been exceeded!");

	Generate(Output, OutOffset);

	// added: reseed for prediction resistance
	if (m_providerType != Providers::None)
	{
		m_reseedCounter += Length;
		if (m_reseedCounter >= m_reseedThreshold)
		{
			++m_reseedRequests;
			m_reseedCounter = 0;
			// use next block of state as seed material
			std::vector<byte> state(m_kdfEngine->BlockSize());
			Generate(state, 0);
			// combine with salt from provider, extract, and re-key
			Derive(state);
		}
	}

	return Length;
}

void CMG::Initialize(ISymmetricKey &GenParam)
{
	if (GenParam.Nonce().size() != 0)
	{
		if (GenParam.Info().size() != 0)
			Initialize(GenParam.Key(), GenParam.Nonce(), GenParam.Info());
		else
			Initialize(GenParam.Key(), GenParam.Nonce());
	}
	else
	{
		Initialize(GenParam.Key());
	}
}

void CMG::Initialize(const std::vector<byte> &Seed)
{
	// check for param changes
	Scope();

	if (!m_isInitialized)
	{
		if (!SymmetricKeySize::Contains(LegalKeySizes(), Seed.size() - m_blockSize, m_blockSize))
			throw CryptoGeneratorException("CMG:Initialize", "Seed size is invalid! Check LegalKeySizes for accepted values.");

		m_seedSize = Seed.size();
	}

	// counter is always left-most bytes
	memcpy(&m_ctrVector[0], &Seed[0], m_blockSize);

	// initialize the block cipher
	size_t keyLen = Seed.size() - m_blockSize;
	m_secStrength = keyLen * 8;
	std::vector<byte> key(keyLen);
	memcpy(&key[0], &Seed[m_blockSize], keyLen);
	m_blockCipher->Initialize(true, Key::Symmetric::SymmetricKey(key));
	m_isInitialized = true;
}

void CMG::Initialize(const std::vector<byte> &Seed, const std::vector<byte> &Nonce)
{
	std::vector<byte> key(Seed.size() + Nonce.size());
	if (Nonce.size() > 0)
		memcpy(&key[0], &Nonce[0], Nonce.size());
	if (Seed.size() > 0)
		memcpy(&key[Nonce.size()], &Seed[0], Seed.size());

	Initialize(key);
}

void CMG::Initialize(const std::vector<byte> &Seed, const std::vector<byte> &Nonce, const std::vector<byte> &Info)
{
	std::vector<byte> key(Nonce.size() + Seed.size());

	if (Nonce.size() > 0)
		memcpy(&key[0], &Nonce[0], Nonce.size());
	if (Seed.size() > 0)
		memcpy(&key[Nonce.size()], &Seed[0], Seed.size());

	if (Info.size() > 0)
	{
		// info maps to HX ciphers HKDF Info parameter, value is ignored on a standard cipher
		if (m_cipherType != BlockCiphers::Rijndael &&
			m_cipherType != BlockCiphers::Serpent &&
			m_cipherType != BlockCiphers::Twofish)
		{
			// extended cipher; sets info as HX cipher distribution code.
			// for best security, info should be secret, random, and DistributionCodeMax size
			if (Info.size() <= m_blockCipher->DistributionCodeMax())
			{
				m_distributionCode = Info;
				m_blockCipher->DistributionCode() = m_distributionCode;
			}
			else
			{
				// info is too large; size to optimal max, ignore remainder
				std::vector<byte> tmpInfo(m_blockCipher->DistributionCodeMax());
				memcpy(&tmpInfo[0], &Info[0], tmpInfo.size());
				m_distributionCode = tmpInfo;
				m_blockCipher->DistributionCode() = m_distributionCode;
			}
		}
	}

	Initialize(key);
}

void CMG::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0)
		throw CryptoGeneratorException("CMG::ParallelMaxDegree", "Parallel degree can not be zero!");
	if (Degree % 2 != 0)
		throw CryptoGeneratorException("CMG::ParallelMaxDegree", "Parallel degree must be an even number!");
	if (Degree > m_processorCount)
		throw CryptoGeneratorException("CMG::ParallelMaxDegree", "Parallel degree can not exceed processor count!");

	m_parallelMaxDegree = Degree;
	Scope();
}

void CMG::Update(const std::vector<byte> &Seed)
{
	if (Seed.size() != m_seedSize)
		throw CryptoGeneratorException("CMG::Update", "Update seed size must be equal to seed size used to initialize the generator!");

	Initialize(Seed);
}

//~~~Private Methods~~~//

void CMG::Derive(std::vector<byte> &Seed)
{
	// size the salt for max unpadded hash size; subtract counter and hash finalizer code lengths
	size_t saltLen = m_kdfEngine->BlockSize() - (Helper::DigestFromName::GetPaddingSize(m_kdfEngineType) + 4);
	std::vector<byte> salt(saltLen);
	// pull the rand from provider
	m_providerSource->GetBytes(salt);
	// extract the new key+counter
	Kdf::KDF2 kdf(m_kdfEngine);
	kdf.Initialize(Seed, salt);
	std::vector<byte> tmpK(m_seedSize);
	kdf.Generate(tmpK);
	// reinitialize with the new key and counter
	Initialize(tmpK);
}

void CMG::Detect()
{
	try
	{
		Common::CpuDetect detect;
		m_processorCount = detect.VirtualCores();
		if (m_processorCount > 1 && m_processorCount % 2 != 0)
			m_processorCount--;

		m_parallelBlockSize = detect.L1DataCacheTotal();
		if (m_parallelBlockSize == 0 || m_processorCount == 0)
			throw std::exception();

		m_hasSSE = detect.SSE();
		m_hasAVX2 = detect.AVX2();
	}
	catch(...)
	{
		m_processorCount = Utility::ParallelUtils::ProcessorCount();

		if (m_processorCount == 0)
			m_processorCount = 1;
		if (m_processorCount > 1 && m_processorCount % 2 != 0)
			m_processorCount--;

		m_hasSSE = false;
		m_hasAVX2 = false;
		m_parallelBlockSize = m_processorCount * PRC_DATACACHE;
	}
}

void CMG::Generate(std::vector<byte> &Output, size_t OutOffset)
{
	size_t outSize = Output.size() - OutOffset;

	if (!m_isParallel || outSize < m_parallelBlockSize)
	{
		// not parallel or too small; generate p-rand block
		Transform(Output, OutOffset, outSize, m_ctrVector);
	}
	else
	{
		const size_t OUTSZE = outSize;
		const size_t CNKSZE = m_parallelBlockSize / m_parallelMaxDegree;
		const size_t CTRLEN = (CNKSZE / m_blockSize);
		std::vector<byte> tmpCtr(m_ctrVector.size());

		Utility::ParallelUtils::ParallelFor(0, m_parallelMaxDegree, [this, &Output, OutOffset, &tmpCtr, CNKSZE, CTRLEN](size_t i)
		{
			// thread level counter
			std::vector<byte> thdCtr(m_ctrVector.size());
			// offset counter by chunk size / block size  
			this->Increase(m_ctrVector, thdCtr, CTRLEN * i);
			// generate random at output offset
			this->Transform(Output, OutOffset + (i * CNKSZE), CNKSZE, thdCtr);
			// store last counter
			if (i == m_parallelMaxDegree - 1)
				memcpy(&tmpCtr[0], &thdCtr[0], tmpCtr.size());
		});

		// copy last counter to class variable
		memcpy(&m_ctrVector[0], &tmpCtr[0], m_ctrVector.size());
		// last block processing
		const size_t ALNSZE = CNKSZE * m_parallelMaxDegree;

		if (ALNSZE < OUTSZE)
		{
			size_t fnlSize = Output.size() % ALNSZE;
			Transform(Output, ALNSZE, fnlSize, m_ctrVector);
		}
	}
}

void CMG::Increase(const std::vector<byte> &Input, std::vector<byte> &Output, const size_t Value)
{
	const size_t CTRSZE = Output.size() - 1;
	std::vector<byte> ctrInc(sizeof(Value));
	memcpy(&ctrInc[0], &Value, ctrInc.size());
	memcpy(&Output[0], &Input[0], Input.size());
	byte carry = 0;

	for (size_t i = CTRSZE; i > 0; --i)
	{
		byte odst = Output[i];
		byte osrc = CTRSZE - i < ctrInc.size() ? ctrInc[CTRSZE - i] : (byte)0;
		byte ndst = (byte)(odst + osrc + carry);
		carry = ndst < odst ? 1 : 0;
		Output[i] = ndst;
	}
}

void CMG::Increment(std::vector<byte> &Counter)
{
	size_t i = Counter.size();
	while (--i >= 0 && ++Counter[i] == 0) {}
}

IBlockCipher* CMG::LoadCipher(BlockCiphers CipherType, Digests KdfEngineType)
{
	try
	{
		Digests dgt = KdfEngineType;
		if (CipherType == BlockCiphers::Rijndael || CipherType == BlockCiphers::Serpent || CipherType == BlockCiphers::Twofish)
			dgt = Digests::None;

		return Helper::BlockCipherFromName::GetInstance(CipherType, dgt);
	}
	catch(std::exception& ex)
	{
		throw CryptoGeneratorException("CMG:LoadCipher", "The block cipher could not be instantiated!", std::string(ex.what()));
	}
}

IDigest* CMG::LoadDigest(Digests DigestType)
{
	try
	{
		return Helper::DigestFromName::GetInstance(DigestType);
	}
	catch (std::exception& ex)
	{
		throw CryptoGeneratorException("CMG:LoadDigest", "The message digest could not be instantiated!", std::string(ex.what()));
	}
}

IProvider* CMG::LoadProvider(Providers ProviderType)
{
	try
	{
		return Helper::ProviderFromName::GetInstance(ProviderType);
	}
	catch (std::exception& ex)
	{
		throw CryptoGeneratorException("CMG:LoadProvider", "The entropy provider could not be instantiated!", std::string(ex.what()));
	}
}

void CMG::LoadState()
{
	if (m_blockCipher == 0)
		m_blockCipher = LoadCipher(m_cipherType, m_kdfEngineType);
	if (m_kdfEngineType != Digests::None && m_kdfEngine == 0)
		m_kdfEngine = LoadDigest(m_kdfEngineType);
	if (m_providerType != Providers::None && m_providerSource == 0)
		m_providerSource = LoadProvider(m_providerType);

	m_blockSize = m_blockCipher->BlockSize();
	m_ctrVector.resize(m_blockSize);
	m_prdResistant = m_providerType != Providers::None;
	m_reseedThreshold = DEF_CYCTHRESH;
	m_distributionCodeMax = m_blockCipher->DistributionCodeMax();
	m_legalKeySizes = m_blockCipher->LegalKeySizes();

	Detect();
	Scope();
}

void CMG::Scope()
{
	if (m_parallelMaxDegree == 1 || m_processorCount == 1)
		m_isParallel = false;

	if (m_parallelMaxDegree == 0)
		m_parallelMaxDegree = m_processorCount;

	m_parallelMinimumSize = m_parallelMaxDegree * m_blockCipher->BlockSize();

	if (m_hasAVX2)
		m_parallelMinimumSize *= 8;
	else if (m_hasSSE)
		m_parallelMinimumSize *= 4;

	// 16 kb minimum
	if (m_parallelBlockSize == 0 || m_parallelBlockSize < PRC_DATACACHE)
		m_parallelBlockSize = (m_parallelMaxDegree * PRC_DATACACHE) - ((m_parallelMaxDegree * PRC_DATACACHE) % m_parallelMinimumSize);
	else
		m_parallelBlockSize = m_parallelBlockSize - (m_parallelBlockSize % m_parallelMinimumSize);
}

void CMG::Transform(std::vector<byte> &Output, const size_t OutOffset, const size_t Length, std::vector<byte> &Counter)
{
	size_t blkCtr = 0;
	const size_t SSEBLK = 4 * m_blockSize;
	const size_t AVXBLK = 8 * m_blockSize;

	if (m_hasAVX2 && Length >= AVXBLK)
	{
		const size_t PBKALN = Length - (Length % AVXBLK);
		std::vector<byte> ctrBlk(AVXBLK);

		// stagger counters and process 8 blocks with avx
		while (blkCtr != PBKALN)
		{
			memcpy(&ctrBlk[0], &Counter[0], Counter.size());
			Increment(Counter);
			memcpy(&ctrBlk[16], &Counter[0], Counter.size());
			Increment(Counter);
			memcpy(&ctrBlk[32], &Counter[0], Counter.size());
			Increment(Counter);
			memcpy(&ctrBlk[48], &Counter[0], Counter.size());
			Increment(Counter);
			memcpy(&ctrBlk[64], &Counter[0], Counter.size());
			Increment(Counter);
			memcpy(&ctrBlk[80], &Counter[0], Counter.size());
			Increment(Counter);
			memcpy(&ctrBlk[96], &Counter[0], Counter.size());
			Increment(Counter);
			memcpy(&ctrBlk[112], &Counter[0], Counter.size());
			Increment(Counter);
			m_blockCipher->Transform128(ctrBlk, 0, Output, OutOffset + blkCtr);
			blkCtr += AVXBLK;
		}
	}
	else if (m_hasSSE && Length >= SSEBLK)
	{
		const size_t PBKALN = Length - (Length % SSEBLK);
		std::vector<byte> ctrBlk(SSEBLK);

		// 4 blocks with sse
		while (blkCtr != PBKALN)
		{
			memcpy(&ctrBlk[0], &Counter[0], Counter.size());
			Increment(Counter);
			memcpy(&ctrBlk[16], &Counter[0], Counter.size());
			Increment(Counter);
			memcpy(&ctrBlk[32], &Counter[0], Counter.size());
			Increment(Counter);
			memcpy(&ctrBlk[48], &Counter[0], Counter.size());
			Increment(Counter);
			m_blockCipher->Transform64(ctrBlk, 0, Output, OutOffset + blkCtr);
			blkCtr += SSEBLK;
		}
	}

	// process remaining blocks
	const size_t BLKALN = Length - (Length % m_blockSize);
	while (blkCtr != BLKALN)
	{
		m_blockCipher->EncryptBlock(Counter, 0, Output, OutOffset + blkCtr);
		Increment(Counter);
		blkCtr += m_blockSize;
	}

	// last partial
	if (blkCtr != Length)
	{
		std::vector<byte> outputBlock(m_blockSize, 0);
		m_blockCipher->EncryptBlock(Counter, outputBlock);
		const size_t FNLSZE = Length % m_blockSize;
		memcpy(&Output[OutOffset + (Length - FNLSZE)], &outputBlock[0], FNLSZE);
		Increment(Counter);
	}
}

NAMESPACE_DRBGEND