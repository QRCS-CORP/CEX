#include "StreamCipherFromName.h"
#include "ACS.h"
#include "ChaCha256.h"
#include "ChaCha512.h"
#include "Threefish256.h"
#include "Threefish512.h"
#include "Threefish1024.h"

NAMESPACE_HELPER

IStreamCipher* StreamCipherFromName::GetInstance(StreamCiphers StreamCipherType, size_t RoundCount)
{
	IStreamCipher* cprPtr = nullptr;

	try
	{
		switch (StreamCipherType)
		{
			case StreamCiphers::ACS:
			case StreamCiphers::ACS512A:
			{
				cprPtr = new Cipher::Symmetric::Stream::ACS(Enumeration::BlockCiphers::AHX, Enumeration::BlockCipherExtensions::SHAKE512, Enumeration::StreamAuthenticators::KMAC512);
				break;
			}
			case StreamCiphers::ACS256A:
			{
				cprPtr = new Cipher::Symmetric::Stream::ACS(Enumeration::BlockCiphers::AHX, Enumeration::BlockCipherExtensions::SHAKE256, Enumeration::StreamAuthenticators::KMAC256);
				break;
			}
			case StreamCiphers::ACS256S:
			{
				cprPtr = new Cipher::Symmetric::Stream::ACS(Enumeration::BlockCiphers::SHX, Enumeration::BlockCipherExtensions::SHAKE256, Enumeration::StreamAuthenticators::KMAC256);
				break;
			}
			case StreamCiphers::ACS512S:
			{
				cprPtr = new Cipher::Symmetric::Stream::ACS(Enumeration::BlockCiphers::SHX, Enumeration::BlockCipherExtensions::SHAKE512, Enumeration::StreamAuthenticators::KMAC512);
				break;
			}
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
			case StreamCiphers::Threefish256:
			{
				cprPtr = new Cipher::Symmetric::Stream::Threefish256;
				break;
			}
			case StreamCiphers::Threefish512:
			{
				cprPtr = new Cipher::Symmetric::Stream::Threefish512;
				break;
			}
			case StreamCiphers::Threefish1024:
			{
				cprPtr = new Cipher::Symmetric::Stream::Threefish1024;
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
