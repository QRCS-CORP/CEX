#include "PBKDF2.h"
#include "ArrayUtils.h"
#include "DigestFromName.h"
#include "IntUtils.h"
#include "SymmetricKey.h"

NAMESPACE_KDF

//~~~Constructor~~~//

PBKDF2::PBKDF2(Digests DigestType, size_t Iterations)
	:
	m_macGenerator(new HMAC(DigestType)),
	m_blockSize(m_macGenerator->BlockSize()),
	m_destroyEngine(true),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_kdfCounter(1),
	m_kdfDigestType(DigestType),
	m_kdfIterations(Iterations != 0 ? Iterations : throw CryptoKdfException("PBKDF2:CTor", "Iterations count can not be zero!")),
	m_kdfKey(0),
	m_kdfSalt(0),
	m_legalKeySizes(0),
	m_macSize(m_macGenerator->MacSize())
{
	LoadState();
}

PBKDF2::PBKDF2(IDigest* Digest, size_t Iterations)
	:
	m_macGenerator(Digest != 0 ? new HMAC(Digest) : throw CryptoKdfException("PBKDF2:CTor", "Digest instance can not be null!")),
	m_blockSize(m_macGenerator->BlockSize()),
	m_destroyEngine(false),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_kdfCounter(1),
	m_kdfDigestType(Digest->Enumeral()),
	m_kdfIterations(Iterations != 0 ? Iterations : throw CryptoKdfException("PBKDF2:CTor", "Iterations count can not be zero!")),
	m_kdfKey(0),
	m_kdfSalt(0),
	m_legalKeySizes(0),
	m_macSize(m_macGenerator->MacSize())
{
	LoadState();
}

PBKDF2::PBKDF2(HMAC* Mac, size_t Iterations)
	:
	m_macGenerator(Mac != 0 ? Mac : throw CryptoKdfException("PBKDF2:CTor", "HMAC instance can not be null!")),
	m_blockSize(m_macGenerator->BlockSize()),
	m_kdfCounter(1),
	m_destroyEngine(false),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_kdfDigestType(m_macGenerator->DigestType()),
	m_kdfIterations(Iterations != 0 ? Iterations : throw CryptoKdfException("PBKDF2:CTor", "Iterations count can not be zero!")),
	m_kdfKey(0),
	m_kdfSalt(0),
	m_legalKeySizes(0),
	m_macSize(m_macGenerator->MacSize())
{
	LoadState();
}

PBKDF2::~PBKDF2()
{
	Destroy();
}

//~~~Public Functions~~~//

void PBKDF2::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_blockSize = 0;
		m_kdfCounter = 0;
		m_kdfDigestType = Digests::None;
		m_isInitialized = false;
		m_kdfIterations = 0;
		m_macSize = 0;

		try
		{
			if (m_destroyEngine)
			{
				m_destroyEngine = false;

				if (m_macGenerator != 0)
					delete m_macGenerator;
			}

			Utility::ArrayUtils::ClearVector(m_kdfKey);
			Utility::ArrayUtils::ClearVector(m_kdfSalt);
			Utility::ArrayUtils::ClearVector(m_legalKeySizes);
		}
		catch(std::exception& ex)
		{
			throw CryptoKdfException("PBKDF2:Destroy", "The class state was not disposed!", std::string(ex.what()));
		}
	}
}

size_t PBKDF2::Generate(std::vector<byte> &Output)
{
	if (!m_isInitialized)
		throw CryptoKdfException("HKDF:Generate", "The generator must be initialized before use!");
	if (Output.size() == 0)
		throw CryptoKdfException("HKDF:Generate", "Output buffer too small!");
	if (m_kdfCounter + (Output.size() / m_macSize) > 255)
		throw CryptoKdfException("HKDF:Generate", "HKDF may only be used for 255 * HashLen bytes of output");

	return Expand(Output, 0, Output.size());
}

size_t PBKDF2::Generate(std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	if (!m_isInitialized)
		throw CryptoKdfException("PBKDF2:Generate", "The generator must be initialized before use!");
	if ((Output.size() - Length) < OutOffset)
		throw CryptoKdfException("PBKDF2:Generate", "Output buffer too small!");
	if (m_kdfCounter + (Length / m_macSize) > 255)
		throw CryptoKdfException("PBKDF2:Generate", "HKDF may only be used for 255 * HashLen bytes of output");

	return Expand(Output, OutOffset, Length);
}

void PBKDF2::Initialize(ISymmetricKey &GenParam)
{
	if (GenParam.Key().size() < MIN_PASSLEN)
		throw CryptoKdfException("PBKDF2:Initialize", "Key size is too small; must be a minumum of 4 bytes!");

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

void PBKDF2::Initialize(const std::vector<byte> &Key)
{
	if (Key.size() < MIN_PASSLEN)
		throw CryptoKdfException("PBKDF2:Initialize", "Key size is too small; must be a minumum of 4 bytes!");

	if (m_isInitialized)
		Reset();

	m_kdfKey.resize(Key.size());
	memcpy(&m_kdfKey[0], &Key[0], m_kdfKey.size());
	m_isInitialized = true;
}

void PBKDF2::Initialize(const std::vector<byte> &Key, const std::vector<byte> &Salt)
{
	if (Key.size() < MIN_PASSLEN)
		throw CryptoKdfException("PBKDF2:Initialize", "Key size is too small, must be a minumum of 4 bytes!");
	if (Salt.size() < MIN_SALTLEN)
		throw CryptoKdfException("PBKDF2:Initialize", "Salt size is too small, must be a minumum of 4 bytes!");

	if (m_isInitialized)
		Reset();

	m_kdfKey.resize(Key.size());
	memcpy(&m_kdfKey[0], &Key[0], Key.size());
	m_kdfSalt.resize(Salt.size());
	memcpy(&m_kdfSalt[0], &Salt[0], Salt.size());

	m_isInitialized = true;
}

void PBKDF2::Initialize(const std::vector<byte> &Key, const std::vector<byte> &Salt, const std::vector<byte> &Info)
{
	if (Key.size() < MIN_PASSLEN)
		throw CryptoKdfException("PBKDF2:Initialize", "Key size is too small, must be a minumum of 4 bytes!");
	if (Salt.size() + Info.size() < MIN_SALTLEN)
		throw CryptoKdfException("PBKDF2:Initialize", "Salt with info size is too small, combined must be a minumum of 4 bytes!");

	if (m_isInitialized)
		Reset();

	m_kdfKey.resize(Key.size());
	memcpy(&m_kdfKey[0], &Key[0], Key.size());
	m_kdfSalt.resize(Salt.size() + Info.size());

	if (Salt.size() > 0)
		memcpy(&m_kdfSalt[0], &Salt[0], Salt.size());
	if (Info.size() > 0)
		memcpy(&m_kdfSalt[Salt.size()], &Info[0], Info.size());

	m_isInitialized = true;
}

void PBKDF2::ReSeed(const std::vector<byte> &Seed)
{
	if (Seed.size() < MIN_PASSLEN)
		throw CryptoKdfException("PBKDF2:ReSeed", "Seed can not be less than 4 bytes in length!");

	if (Seed.size() > m_kdfSalt.size())
		m_kdfSalt.resize(Seed.size());

	memcpy(&m_kdfSalt[0], &Seed[0], Seed.size());
}

void PBKDF2::Reset()
{
	m_macGenerator->Reset();
	m_kdfCounter = 1;
	m_kdfKey.clear();
	m_kdfSalt.clear();
	m_isInitialized = false;
}

//~~~Private Functions~~~//

size_t PBKDF2::Expand(std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	if (m_kdfCounter + (Length / m_macSize) > 255)
		throw CryptoKdfException("PBKDF2:Expand", "Maximum length value is 255 * the digest return size!");

	size_t prcLen = Length;

	do
	{
		size_t prcRmd = Utility::IntUtils::Min(m_macSize, prcLen);

		if (prcRmd >= m_macSize)
		{
			Process(Output, OutOffset);
		}
		else
		{
			std::vector<byte> tmp(m_macSize);
			Process(tmp, 0);
			memcpy(&Output[OutOffset], &tmp[0], prcRmd);
		}

		prcLen -= prcRmd;
		OutOffset += prcRmd;
		++m_kdfCounter;
	} 
	while (prcLen != 0);

	return Length;
}

void PBKDF2::Process(std::vector<byte> &Output, size_t OutOffset)
{
	Key::Symmetric::SymmetricKey kp(m_kdfKey);
	m_macGenerator->Initialize(kp);

	if (m_kdfSalt.size() != 0)
		m_macGenerator->Update(m_kdfSalt, 0, m_kdfSalt.size());

	std::vector<byte> counter(4, 0);
	Utility::IntUtils::Be32ToBytes(m_kdfCounter, counter, 0);
	m_macGenerator->Update(counter, 0, counter.size());

	std::vector<byte> state(m_macSize);
	m_macGenerator->Finalize(state, 0);
	memcpy(&Output[OutOffset], &state[0], state.size());

	for (int i = 1; i != m_kdfIterations; ++i)
	{
		m_macGenerator->Initialize(kp);
		m_macGenerator->Update(state, 0, state.size());
		m_macGenerator->Finalize(state, 0);

		for (size_t j = 0; j != state.size(); ++j)
			Output[OutOffset + j] ^= state[j];
	}
}

void PBKDF2::LoadState()
{
	// best salt size; hash finalizer code and counter length adjusted
	size_t saltLen = m_macGenerator->BlockSize() - (Helper::DigestFromName::GetPaddingSize(m_kdfDigestType) + 4);
	m_legalKeySizes.resize(3);
	// minimum security is the digest output size
	m_legalKeySizes[0] = SymmetricKeySize(m_macSize, 0, 0);
	// recommended size, adjusted salt size to hash full blocks
	m_legalKeySizes[1] = SymmetricKeySize(m_blockSize, saltLen, 0);
	// max recommended; add a block of key to info (appended to salt)
	m_legalKeySizes[2] = SymmetricKeySize(m_blockSize, saltLen, m_blockSize);
}

NAMESPACE_KDFEND
