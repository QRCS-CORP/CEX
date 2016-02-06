#ifndef _CEXTEST_TestUtils_H
#define _CEXTEST_TestUtils_H

#ifdef _WIN32
#include <Windows.h>
#else
#include <sys/types.h>
#include <sys/time.h>
#endif

#include <fstream>
#include <iostream>
#include "Common.h"
#include "CSPRsg.h"
#include "KeyParams.h"
#include <algorithm>

namespace Test
{
	class TestUtils
	{
	public:

		/// <summary>
		/// Copy an int vector array
		/// </summary>
		static void CopyVector(const std::vector<int> &srcArray, size_t srcIndex, std::vector<int> &dstArray, size_t dstIndex, size_t length)
		{
			memcpy(&dstArray[dstIndex], &srcArray[srcIndex], length*sizeof(srcArray[srcIndex]));
		}

		/// <summary>
		/// Compares two byte arrays
		/// </summary>
		/// 
		/// <returns>Arrays Are Equal</returns>
		static bool IsEqual(std::vector<byte> &A, std::vector<byte> &B)
		{
			size_t i = A.size();

			if (i != B.size())
				return false;

			while (i != 0)
			{
				--i;
				if (A[i] != B[i])
					return false;
			}

			return true;
		}

		/// <summary>
		/// Returns the amount of milliseconds elapsed since the UNIX epoch. Works on both
		/// windows and linux. (see http://stackoverflow.com/questions/1861294/how-to-calculate-execution-time-of-a-code-snippet-in-c)
		/// </summary>
		/// 
		/// <returns>Time in Milliseconds</returns>
		static uint64_t GetTimeMs64()
		{
#ifdef _WIN32
			/* Windows */
			FILETIME ft;
			LARGE_INTEGER li;

			// Get the amount of 100 nano seconds intervals elapsed since January 1, 1601 (UTC) and copy it to a LARGE_INTEGER structure
			GetSystemTimeAsFileTime(&ft);
			li.LowPart = ft.dwLowDateTime;
			li.HighPart = ft.dwHighDateTime;

			uint64_t ret = li.QuadPart;
			ret -= 116444736000000000LL; /* Convert from file time to UNIX epoch time. */
			ret /= 10000; /* From 100 nano seconds (10^-7) to 1 millisecond (10^-3) intervals */

			return ret;
#else
			/* Linux */
			struct timeval tv;

			gettimeofday(&tv, NULL);
			uint64_t ret = tv.tv_usec;
			/* Convert from micro seconds (10^-6) to milliseconds (10^-3) */
			ret /= 1000;
			/* Adds the seconds (10^0) after converting them to milliseconds (10^-3) */
			ret += (tv.tv_sec * 1000);

			return ret;
#endif
		}

		/// <summary>
		/// Initializes a KeyParams structure with pseudo random data
		/// </summary>
		static void GetRandomKey(CEX::Common::KeyParams &keyParams, int keySize, int ivSize)
		{
			CEX::Seed::CSPRsg rng;
			std::vector<byte> key(keySize, 0);
			std::vector<byte> iv(ivSize, 0);
			rng.GetBytes(key);
			rng.GetBytes(iv);
			keyParams.Key() = key;
			keyParams.IV() = iv;
		}

		/// <summary>
		/// Reads a file into a buffer
		/// </summary>
		/// 
		/// <returns>Success</returns>
		static bool Read(const std::string &path, std::string &contents)
		{
			bool status = false;
			std::ifstream ifs(path, std::ios::binary | std::ios::ate);

			if (!ifs.is_open())
			{
				throw std::string("file not open");
			}
			else
			{
				ifs.seekg(0, std::ios::end);
				const int bufsize = (int)ifs.tellg();
				ifs.seekg(0, std::ios::beg);

				if (bufsize > 0)
				{
					status = true;
					std::vector<char> bufv(bufsize, 0);
					char *buf = &bufv[0];
					ifs.read(buf, bufsize);
					contents.assign(buf, bufsize);
				}
				else
				{
					throw std::string("file empty");
				}
			}

			return status;
		}

		static std::vector<byte> Reduce(std::vector<byte> Seed)
		{
			int len = Seed.size() / 2;
			std::vector<byte> data(len);

			for (int i = 0; i < len; i++)
				data[i] = (byte)(Seed[i] ^ Seed[len + i]);

			return data;
		}

		/// <summary>
		/// Reverses a byte array
		/// </summary>
		static void Reverse(std::vector<byte> &v)
		{
			std::reverse(v.begin(), v.end());
		}
	};
}
#endif
