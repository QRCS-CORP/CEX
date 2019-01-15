#include "CSP.h"
#include "IntegerTools.h"

#if defined(CEX_OS_WINDOWS)
#	include <Windows.h>
#elif defined (CEX_OS_ANDROID)
#	include <sys/types.h>
#	include <thread>
#elif defined (CEX_OS_POSIX)
#	include <sys/types.h>
#	include <sys/stat.h>
#	include <fcntl.h>
#	include <unistd.h>
#	include <errno.h>
#endif

NAMESPACE_PROVIDER

using Utility::MemoryTools;

#if defined(CEX_OS_WINDOWS)
#	pragma comment(lib, "advapi32.lib")
	HCRYPTPROV m_hProvider = 0;
#elif defined (CEX_OS_POSIX)
#	if !defined(O_NOCTTY)
#		define O_NOCTTY 0
#	endif
#	define CEX_SYSTEM_RNG_DEVICE "/dev/urandom"
#endif

const std::string CSP::CLASS_NAME("CSP");

//~~~Accessors~~~//

const Enumeration::Providers CSP::Enumeral()
{
	return Enumeration::Providers::CSP; 
}

const bool CSP::IsAvailable()
{ 
	return m_isAvailable; 
}

const std::string CSP::Name() 
{ 
	return CLASS_NAME;
}

//~~~Constructor~~~//

CSP::CSP()
	:
#if defined(CEX_OS_WINDOWS) || defined(CEX_OS_ANDROID) || defined(CEX_OS_POSIX)
	m_isAvailable(true)
#else
	m_isAvailable(false)
#endif
{
	if (!m_isAvailable)
	{
		throw CryptoRandomException(CLASS_NAME, std::string("Constructor"), std::string("Random provider is not available!"), ErrorCodes::NotFound);
	}
}

CSP::~CSP()
{
	m_isAvailable = false;
}

//~~~Public Functions~~~//

void CSP::Generate(std::vector<byte> &Output)
{
	size_t prcLen = Output.size();
	size_t prcOffset = 0;

#if defined(CEX_OS_WINDOWS)

	HCRYPTPROV hProvider = NULL;

	if (!CryptAcquireContextW(&hProvider, 0, 0, PROV_RSA_FULL, (CRYPT_VERIFYCONTEXT | CRYPT_SILENT)))
	{
		throw CryptoRandomException(CLASS_NAME, std::string("Generate"), std::string("Random provider is not available!"), ErrorCodes::NotFound);
	}

	if (hProvider != NULL)
	{
		BYTE* ptr = (BYTE*)&Output[0];
		if (!::CryptGenRandom(hProvider, (DWORD)prcLen, ptr))
		{
			CryptReleaseContext(hProvider, 0);
			hProvider = NULL;
			throw CryptoRandomException(CLASS_NAME, std::string("Generate"), std::string("Random provider is not available!"), ErrorCodes::NotFound);
		}
	}

	if (hProvider != NULL)
	{
		CryptReleaseContext(hProvider, 0);
		hProvider = NULL;
	}

#elif defined(CEX_OS_ANDROID)

	try
	{
		do
		{
			size_t prcRmd = Utility::IntegerTools::Min(sizeof(uint), prcLen);
			uint rndNum = arc4random();
			MemoryTools::Copy(rndNum, Output, prcOffset, prcRmd);
			prcOffset += prcRmd;
			prcLen -= prcRmd;
		} 
		while (prcLen != 0)
	}
	catch (std::exception&)
	{
		throw CryptoRandomException(CLASS_NAME, std::string("Generate"), std::string(ex.what()), ErrorCodes::UnKnown);
	}

#else

	int fdHandle = ::open(CEX_SYSTEM_RNG_DEVICE, O_RDONLY | O_NOCTTY);

	if (fdHandle <= 0)
	{
		throw CryptoRandomException(CLASS_NAME, std::string("Generate"), std::string("System RNG failed to open RNG device!"), ErrorCodes::NotFound);
	}

	do
	{
		int rndLen = ::read(fdHandle, &Output[prcOffset], prcLen);

		if (rndLen < 0)
		{
			if (errno == EINTR)
			{
				continue;
			}
			else
			{
				throw CryptoRandomException(CLASS_NAME, std::string("Generate"), std::string("System RNG read failed error!"), ErrorCodes::BadRead);
			}
		}
		else if (rndLen == 0)
		{
			throw CryptoRandomException(CLASS_NAME, std::string("Generate"), std::string("System RNG read failed error!"), ErrorCodes::BadRead);
		}

		prcOffset += rndLen;
		prcLen -= rndLen;
	}
	while (prcLen != 0)

	if (fdHandle > 0)
	{
		::close(fdHandle);
		fdHandle = 0;
	}

#endif
}

void CSP::Generate(std::vector<byte> &Output, size_t Offset, size_t Length)
{
	if ((Output.size() - Offset) < Length)
	{
		throw CryptoRandomException(CLASS_NAME, std::string("Generate"), std::string("The output buffer is too small!"), ErrorCodes::InvalidSize);
	}

	std::vector<byte> rnd(Length);
	Generate(rnd);
	MemoryTools::Copy(rnd, 0, Output, Offset, rnd.size());
}

std::vector<byte> CSP::Generate(size_t Length)
{
	std::vector<byte> data(Length);
	Generate(data);

	return data;
}

ushort CSP::NextUInt16()
{
	ushort x = 0;
	MemoryTools::CopyToValue(Generate(sizeof(ushort)), 0, x, sizeof(ushort));

	return x;
}

uint CSP::NextUInt32()
{
	uint x = 0;
	MemoryTools::CopyToValue(Generate(sizeof(uint)), 0, x, sizeof(uint));

	return x;
}

ulong CSP::NextUInt64()
{
	ulong x = 0;
	MemoryTools::CopyToValue(Generate(sizeof(ulong)), 0, x, sizeof(ulong));

	return x;
}

void CSP::Reset()
{
}

NAMESPACE_PROVIDEREND
