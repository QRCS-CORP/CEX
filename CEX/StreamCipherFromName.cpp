#include "StreamCipherFromName.h"
#include "ChaCha20.h"
#include "Salsa20.h"

NAMESPACE_HELPER

IStreamCipher* StreamCipherFromName::GetInstance(StreamCiphers StreamCipherType, size_t RoundCount)
{
	IStreamCipher* cprPtr;

	try
	{
		switch (StreamCipherType)
		{
			case StreamCiphers::ChaCha20:
			{
				cprPtr = new Cipher::Symmetric::Stream::ChaCha20(RoundCount);
				break;
			}
			case StreamCiphers::Salsa20:
			{
				cprPtr = new Cipher::Symmetric::Stream::Salsa20(RoundCount);
				break;
			}
			default:
			{
				throw CryptoException("StreamCipherFromName:GetStreamEngine", "The stream cipher is not recognized!");
			}
		}
	}
	catch (const std::exception &ex)
	{
		throw CryptoException("StreamCipherFromName:GetInstance", "The stream cipher is unavailable!", std::string(ex.what()));
	}

	return cprPtr;
}

NAMESPACE_HELPEREND
