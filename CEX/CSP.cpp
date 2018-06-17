#include "CSP.h"
#include "IntUtils.h"

#if defined(CEX_OS_WINDOWS)
#	include <Windows.h>
#	pragma comment(lib, "advapi32.lib")
	HCRYPTPROV m_hProvider = 0;
#elif defined (CEX_OS_ANDROID)
#	include <sys/types.h>
#	include <thread>
#elif defined (CEX_OS_POSIX)
#	include <sys/types.h>
#	include <sys/stat.h>
#	include <fcntl.h>
#	include <unistd.h>
#	include <errno.h>
#	ifndef O_NOCTTY
#		define O_NOCTTY 0
#	endif
#	define CEX_SYSTEM_RNG_DEVICE "/dev/urandom"
#endif

NAMESPACE_PROVIDER

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
}

CSP::~CSP()
{
	m_isAvailable = false;
}

//~~~Public Functions~~~//

void CSP::Generate(std::vector<byte> &Output)
{
	if (!m_isAvailable)
	{
		throw CryptoRandomException("CSP:Generate", "Random provider is not available!");
	}

	size_t prcLen = Output.size();
	size_t prcOffset = 0;

#if defined(CEX_OS_WINDOWS)

	HCRYPTPROV hProvider = NULL;
	if (!::CryptAcquireContextW(&hProvider, 0, 0, PROV_RSA_FULL, (CRYPT_VERIFYCONTEXT | CRYPT_SILENT)))
	{
		throw CryptoRandomException("CSP:Generate", "Call to CryptAcquireContext failed; random provider is not available!");
	}

	if (hProvider != NULL)
	{
		BYTE* ptr = (BYTE*)&Output[0];
		if (!::CryptGenRandom(hProvider, (DWORD)prcLen, ptr))
		{
			::CryptReleaseContext(hProvider, 0);
			hProvider = NULL;
			throw CryptoRandomException("CSP:Generate", "Call to CryptGenRandom failed; random provider is not available!");
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
			size_t prcRmd = Utility::IntUtils::Min(sizeof(uint), prcLen);
			uint rndNum = arc4random();
			Utility::MemUtils::Copy(rndNum, Output, prcOffset, prcRmd);
			prcOffset += prcRmd;
			prcLen -= prcRmd;
		} 
		while (prcLen != 0)
	}
	catch (std::exception&)
	{
		throw CryptoRandomException("CSP:Generate", "Call to arc4random failed; random provider is not available!");
	}

#else

	int fdHandle = ::open(CEX_SYSTEM_RNG_DEVICE, O_RDONLY | O_NOCTTY);

	if (fdHandle <= 0)
	{
		throw CryptoRandomException("CSP:Generate", "System RNG failed to open RNG device!");
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
				throw CryptoRandomException("CSP:Generate", "System RNG read failed error!");
			}
		}
		else if (rndLen == 0)
		{
			throw CryptoRandomException("CSP:Generate", "System RNG EOF on device!");
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
	CexAssert(Offset + Length <= Output.size(), "the array is too small to fulfill this request");

	std::vector<byte> rnd(Length);
	Generate(rnd);
	Utility::MemUtils::Copy(rnd, 0, Output, Offset, rnd.size());
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
	Utility::MemUtils::CopyToValue(Generate(sizeof(ushort)), 0, x, sizeof(ushort));

	return x;
}

uint CSP::NextUInt32()
{
	uint x = 0;
	Utility::MemUtils::CopyToValue(Generate(sizeof(uint)), 0, x, sizeof(uint));

	return x;
}

ulong CSP::NextUInt64()
{
	ulong x = 0;
	Utility::MemUtils::CopyToValue(Generate(sizeof(ulong)), 0, x, sizeof(ulong));

	return x;
}

void CSP::Reset()
{
}

NAMESPACE_PROVIDEREND
