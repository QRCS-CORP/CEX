#include "PBKDF2.h"
#include "IntUtils.h"

NAMESPACE_GENERATOR

void PBKDF2::Destroy()
{
	if (!m_isDestroyed)
	{
		m_blockSize = 0;
		m_hashSize = 0;
		m_isInitialized = false;
		m_prcIterations = 0;

		CEX::Utility::IntUtils::ClearVector(m_macKey);
		CEX::Utility::IntUtils::ClearVector(m_macSalt);

		m_isDestroyed = true;
	}
}

size_t PBKDF2::Generate(std::vector<byte> &Output)
{
	GenerateKey(Output, 0, Output.size());

	return Output.size();
}

size_t PBKDF2::Generate(std::vector<byte> &Output, size_t OutOffset, size_t Size)
{
	if ((Output.size() - Size) < OutOffset)
		throw CryptoGeneratorException("PBKDF2:Generate", "Output buffer too small!");

	GenerateKey(Output, OutOffset, Size);

	return Size;
}

void PBKDF2::Initialize(const std::vector<byte> &Ikm)
{
	if (Ikm.size() < m_hashSize * 2)
		throw CryptoGeneratorException("PBKDF2:Initialize", "Salt size is too small; must be a minumum of digest return size!");

	m_macKey.resize(m_hashSize);
	memcpy(&m_macKey[0], &Ikm[0], m_hashSize);
	m_macSalt.resize(Ikm.size() - m_hashSize);
	memcpy(&m_macSalt[0], &Ikm[m_hashSize], Ikm.size() - m_hashSize);

	m_isInitialized = true;
}

void PBKDF2::Initialize(const std::vector<byte> &Salt, const std::vector<byte> &Ikm)
{
	if (Salt.size() < m_blockSize)
		throw CryptoGeneratorException("PBKDF2:Initialize", "Salt size is too small; must be a minumum of digest return size!");
	if (Ikm.size() < m_hashSize)
		throw CryptoGeneratorException("PBKDF2:Initialize", "IKM size is too small; must be a minumum of digest block size!");

	// clone iv and salt
	m_macKey.resize(Ikm.size());
	m_macSalt.resize(Salt.size());

	if (m_macKey.size() > 0)
		memcpy(&m_macKey[0], &Ikm[0], Ikm.size());
	if (m_macSalt.size() > 0)
		memcpy(&m_macSalt[0], &Salt[0], Salt.size());

	m_isInitialized = true;
}

void PBKDF2::Initialize(const std::vector<byte> &Salt, const std::vector<byte> &Ikm, const std::vector<byte> &Nonce)
{
	if (Salt.size() + Nonce.size() < m_blockSize)
		throw CryptoGeneratorException("PBKDF2:Initialize", "Salt size is too small; must be a minumum of digest return size!");
	if (Ikm.size() < m_hashSize)
		throw CryptoGeneratorException("PBKDF2:Initialize", "IKM with Nonce size is too small; combined must be a minumum of digest block size!");

	m_macKey.resize(Ikm.size());
	m_macSalt.resize(Salt.size() + Nonce.size());

	if (m_macKey.size() > 0)
		memcpy(&m_macKey[0], &Ikm[0], Ikm.size());
	if (m_macSalt.size() > 0)
		memcpy(&m_macSalt[0], &Salt[0], Salt.size());
	if (Nonce.size() > 0)
		memcpy(&m_macSalt[Salt.size()], &Nonce[0], Nonce.size());

	m_isInitialized = true;
}

void PBKDF2::Update(const std::vector<byte> &Salt)
{
	if (Salt.size() == 0)
		throw CryptoGeneratorException("PBKDF2:Update", "Salt is too small!");

	Initialize(Salt);
}

// *** Protected *** //

size_t PBKDF2::GenerateKey(std::vector<byte> &Output, size_t OutOffset, size_t Size)
{
	size_t diff = Size % m_hashSize;
	size_t max = Size / m_hashSize;
	uint ctr = 0;
	std::vector<byte> buffer(4);
	std::vector<byte> outBytes(Size);

	for (ctr = 0; ctr < max; ++ctr)
	{
		IntToOctet(buffer, ctr + 1);
		Process(buffer, outBytes, ctr * m_hashSize);
	}

	if (diff > 0)
	{
		IntToOctet(buffer, ctr + 1);
		std::vector<byte> rem(m_hashSize);
		Process(buffer, rem, 0);
		memcpy(&outBytes[outBytes.size() - diff], &rem[0], diff);
	}

	memcpy(&Output[OutOffset], &outBytes[0], outBytes.size());

	return Size;
}

void PBKDF2::IntToOctet(std::vector<byte> &Output, uint Counter)
{
	Output[0] = (byte)((uint)Counter >> 24);
	Output[1] = (byte)((uint)Counter >> 16);
	Output[2] = (byte)((uint)Counter >> 8);
	Output[3] = (byte)Counter;
}

void PBKDF2::Process(std::vector<byte> Input, std::vector<byte> &Output, size_t OutOffset)
{
	std::vector<byte> state(m_hashSize);

	m_digestMac->Initialize(m_macKey);

	if (m_macSalt.size() != 0)
		m_digestMac->BlockUpdate(m_macSalt, 0, m_macSalt.size());

	m_digestMac->BlockUpdate(Input, 0, Input.size());
	m_digestMac->DoFinal(state, 0);

	memcpy(&Output[OutOffset], &state[0], state.size());

	for (int count = 1; count != m_prcIterations; count++)
	{
		m_digestMac->Initialize(m_macKey);
		m_digestMac->BlockUpdate(state, 0, state.size());
		m_digestMac->DoFinal(state, 0);

		for (int j = 0; j != state.size(); j++)
			Output[OutOffset + j] ^= state[j];
	}
}

NAMESPACE_GENERATOREND
