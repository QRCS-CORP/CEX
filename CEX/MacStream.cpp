#include "MacStream.h"
#include "MacFromDescription.h"

NAMESPACE_PROCESSING

//~~~Constructor~~~//

MacStream::MacStream(MacDescription &Description)
	:
	m_macEngine(Description.MacType() != Macs::GMAC ? Helper::MacFromDescription::GetInstance(Description) :
		throw CryptoProcessingException("MacStream:CTor", "GMAC is not supported!")),
	m_destroyEngine(false),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_progressInterval(0)
{
}

MacStream::MacStream(IMac* Mac)
	:
	m_macEngine(Mac != nullptr && Mac->Enumeral() != Macs::GMAC ? Mac :
		throw CryptoProcessingException("MacStream:CTor", "The Mac can not be null!")),
	m_destroyEngine(false),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_progressInterval(0)
{
}

MacStream::~MacStream()
{
	Destroy();
}

//~~~Accessors~~~//

const std::vector<SymmetricKeySize> MacStream::LegalKeySizes()
{
	return m_macEngine->LegalKeySizes();
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
	{
		throw CryptoProcessingException("CipherStream:Initialize", "Invalid key size! Key must be one of the LegalKeySizes() in length.");
	}

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
	{
		m_progressInterval = m_macEngine->BlockSize();
	}
	else
	{
		m_progressInterval = (interval - (interval % m_macEngine->BlockSize()));
	}

	if (m_progressInterval == 0)
	{
		m_progressInterval = m_macEngine->BlockSize();
	}
}

void MacStream::CalculateProgress(size_t Length, size_t Processed)
{
	if (Length >= Processed)
	{
		double progress = 100.0 * (static_cast<double>(Processed) / Length);
		if (progress > 100.0)
		{
			progress = 100.0;
		}

		size_t block = Length / 100;
		if (block == 0)
		{
			ProgressPercent(static_cast<int>(progress));
		}
		else if (Processed % block == 0)
		{
			ProgressPercent(static_cast<int>(progress));
		}
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
			m_destroyEngine = false;

			if (m_macEngine != nullptr)
			{
				m_macEngine.reset(nullptr);
			}
		}
		else
		{
			if (m_macEngine != nullptr)
			{
				m_macEngine.release();
			}
		}
	}
}

std::vector<byte> MacStream::Process(IByteStream* InStream, size_t Length)
{
	size_t prcLen = 0;
	size_t prcRead = 0;
	std::vector<byte> inpBuffer(0);

	const size_t BLKLEN = m_macEngine->BlockSize();
	const size_t ALNLEN = (Length / BLKLEN) * BLKLEN;
	inpBuffer.resize(BLKLEN);

	while (prcLen != ALNLEN)
	{
		prcRead = InStream->Read(inpBuffer, 0, BLKLEN);
		m_macEngine->Update(inpBuffer, 0, prcRead);
		prcLen += prcRead;
		CalculateProgress(Length, InStream->Position());
	}

	// last block
	if (prcLen < Length)
	{
		const size_t FNLLEN = Length - prcLen;
		inpBuffer.resize(FNLLEN);
		prcRead = InStream->Read(inpBuffer, 0, FNLLEN);
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

	const size_t BLKLEN = m_macEngine->BlockSize();
	const size_t ALNLEN = (Length / BLKLEN) * BLKLEN;

	while (prcLen != ALNLEN)
	{
		m_macEngine->Update(Input, InOffset, BLKLEN);
		InOffset += BLKLEN;
		prcLen += BLKLEN;
		CalculateProgress(Length, prcLen);
	}

	// last block
	if (prcLen < Length)
	{
		const size_t FNLLEN = Length - prcLen;
		m_macEngine->Update(Input, InOffset, FNLLEN);
		prcLen += FNLLEN;
	}

	// get the hash
	std::vector<byte> chkSum(m_macEngine->MacSize());
	m_macEngine->Finalize(chkSum, 0);
	CalculateProgress(Length, prcLen);

	return chkSum;
}

NAMESPACE_PROCESSINGEND
