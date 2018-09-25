#include "StreamCipherFromName.h"
#include "ChaCha256.h"
#include "ChaCha512.h"
#include "Threefish512.h"

NAMESPACE_HELPER

IStreamCipher* StreamCipherFromName::GetInstance(StreamCiphers StreamCipherType, size_t RoundCount)
{
	IStreamCipher* cprPtr = nullptr;

	try
	{
		switch (StreamCipherType)
		{
			case StreamCiphers::ChaCha256:
			{
				cprPtr = new Cipher::Symmetric::Stream::ChaCha256;
				break;
			}
			case StreamCiphers::ChaCha512:
			{
				cprPtr = new Cipher::Symmetric::Stream::ChaCha512;
				break;
			}
			case StreamCiphers::Salsa20:
			{
				cprPtr = new Cipher::Symmetric::Stream::Threefish512;
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
