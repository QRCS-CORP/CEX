#include "MacStream.h"
#include "MacFromDescription.h"

NAMESPACE_PROCESSING

//~~~Properties~~~//

const std::vector<SymmetricKeySize> MacStream::LegalKeySizes()
{
	return m_macEngine->LegalKeySizes();
}

//~~~Constructor~~~//

MacStream::MacStream(MacDescription &Description)
	:
	m_macEngine(0),
	m_destroyEngine(false),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_progressInterval(0)
{
	if (Description.MacType() == Macs::GMAC)
		throw CryptoProcessingException("MacStream:CTor", "GMAC is not supported!");

	m_macEngine = Helper::MacFromDescription::GetInstance(Description);
}

MacStream::MacStream(IMac* Mac)
	:
	m_macEngine(Mac),
	m_destroyEngine(false),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_progressInterval(0)
{
	if (Mac == 0)
		throw CryptoProcessingException("MacStream:CTor", "The Mac can not be null!");
	if (Mac->Enumeral() == Macs::GMAC)
		throw CryptoProcessingException("MacStream:CTor", "GMAC is not supported!");
}

MacStream::~MacStream()
{
	Destroy();
}

//~~~Public Functions~~~//

std::vector<byte> MacStream::Compute(IByteStream* InStream)
{
	CexAssert(m_isInitialized, "the mac has not been initialized");
	CexAssert(InStream->Length() - InStream->Position() > 0, "the input stream is too short");
	CexAssert(InStream->CanRead(), "the input stream is set to write only!");

	size_t dataLen = InStream->Length() - InStream->Position();
	CalculateInterval(dataLen);

	return Process(InStream, dataLen);
}

std::vector<byte> MacStream::Compute(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	CexAssert(m_isInitialized, "the mac has not been initialized");
	CexAssert((Input.size() - InOffset) > 0 && Length + InOffset <= Input.size(), "the input array is too short");

	size_t dataLen = Length - InOffset;
	CalculateInterval(dataLen);

	return Process(Input, InOffset, Length);
}

void MacStream::Initialize(ISymmetricKey &KeyParams)
{
	if (!SymmetricKeySize::Contains(LegalKeySizes(), KeyParams.Key().size()))
		throw CryptoProcessingException("CipherStream:Initialize", "Invalid key size! Key must be one of the LegalKeySizes() in length.");

	try
	{
		m_macEngine->Initialize(KeyParams);
		m_isInitialized = true;
	}
	catch (std::exception& ex)
	{
		throw CryptoProcessingException("CipherStream:Initialize", "The key could not be loaded, check the key and iv sizes!", std::string(ex.what()));
	}
}

//~~~Private Functions~~~//

void MacStream::CalculateInterval(size_t Length)
{
	size_t interval = Length / 100;

	if (interval < m_macEngine->BlockSize())
		m_progressInterval = m_macEngine->BlockSize();
	else
		m_progressInterval = (interval - (interval % m_macEngine->BlockSize()));

	if (m_progressInterval == 0)
		m_progressInterval = m_macEngine->BlockSize();
}

void MacStream::CalculateProgress(size_t Length, size_t Processed)
{
	if (Length >= Processed)
	{
		double progress = 100.0 * ((double)Processed / Length);
		if (progress > 100.0)
			progress = 100.0;

		size_t block = Length / 100;
		if (block == 0)
			ProgressPercent((int)progress);
		else if (Processed % block == 0)
			ProgressPercent((int)progress);
	}
}

void MacStream::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_isInitialized = false;
		m_progressInterval = 0;

		if (m_destroyEngine)
		{
			delete m_macEngine;
			m_destroyEngine = false;
		}
	}
}

std::vector<byte> MacStream::Process(IByteStream* InStream, size_t Length)
{
	size_t prcLen = 0;
	size_t prcRead = 0;
	std::vector<byte> inpBuffer(0);

	const size_t BLKSZE = m_macEngine->BlockSize();
	const size_t ALNSZE = (Length / BLKSZE) * BLKSZE;
	inpBuffer.resize(BLKSZE);

	while (prcLen != ALNSZE)
	{
		prcRead = InStream->Read(inpBuffer, 0, BLKSZE);
		m_macEngine->Update(inpBuffer, 0, prcRead);
		prcLen += prcRead;
		CalculateProgress(Length, InStream->Position());
	}

	// last block
	if (prcLen < Length)
	{
		const size_t FNLSZE = Length - prcLen;
		inpBuffer.resize(FNLSZE);
		prcRead = InStream->Read(inpBuffer, 0, FNLSZE);
		m_macEngine->Update(inpBuffer, 0, prcRead);
		prcLen += prcRead;
	}

	// get the hash
	std::vector<byte> chkSum(m_macEngine->MacSize());
	m_macEngine->Finalize(chkSum, 0);
	CalculateProgress(Length, prcLen);

	return chkSum;
}

std::vector<byte> MacStream::Process(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	size_t prcLen = 0;
	std::vector<byte> inpBuffer(0);

	const size_t BLKSZE = m_macEngine->BlockSize();
	const size_t ALNSZE = (Length / BLKSZE) * BLKSZE;

	while (prcLen != ALNSZE)
	{
		m_macEngine->Update(Input, InOffset, BLKSZE);
		InOffset += BLKSZE;
		prcLen += BLKSZE;
		CalculateProgress(Length, prcLen);
	}

	// last block
	if (prcLen < Length)
	{
		const size_t FNLSZE = Length - prcLen;
		m_macEngine->Update(Input, InOffset, FNLSZE);
		prcLen += FNLSZE;
	}

	// get the hash
	std::vector<byte> chkSum(m_macEngine->MacSize());
	m_macEngine->Finalize(chkSum, 0);
	CalculateProgress(Length, prcLen);

	return chkSum;
}

NAMESPACE_PROCESSINGEND
