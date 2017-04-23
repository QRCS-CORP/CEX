#include "SecureStreamTest.h"
#include "../CEX/MemoryStream.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SecureStream.h"

namespace Test
{
	using namespace CEX::IO;

	const std::string SecureStreamTest::DESCRIPTION = "SecureStream test; compares serialization, reads and writes";
	const std::string SecureStreamTest::FAILURE = "FAILURE! ";
	const std::string SecureStreamTest::SUCCESS = "SUCCESS! All SecureStream tests have executed succesfully.";

	SecureStreamTest::SecureStreamTest()
		:
		m_progressEvent()
	{
	}

	SecureStreamTest::~SecureStreamTest()
	{
	}

	std::string SecureStreamTest::Run()
	{
		try
		{
			CompareSerial();
			OnProgress(std::string("SymmetricKeyGenerator: Passed serialization tests.."));
			CheckAccess();
			OnProgress(std::string("SymmetricKeyGenerator: Passed read/write comparison tests.."));

			return SUCCESS;
		}
		catch (std::exception const &ex)
		{
			throw TestException(std::string(FAILURE + " : " + ex.what()));
		}
		catch (...)
		{
			throw TestException(std::string(FAILURE + " : Unknown Error"));
		}
	}

	void SecureStreamTest::CheckAccess()
	{
		Prng::SecureRandom rnd;
		uint32_t cnt;
		std::vector<byte> data;

		for (size_t i = 0; i < 10; ++i)
		{
			cnt = rnd.NextUInt32(40, 4000);
			data = rnd.GetBytes(cnt);

			// add array via constructor
			SecureStream secStm1(data);
			if (secStm1.ToArray() != data)
				throw TestException("CheckAccess: The stream is invalid!");

			// test write method
			SecureStream secStm2;
			secStm2.Write(data, 0, data.size());
			if (secStm2.ToArray() != data)
				throw TestException("CheckAccess: The stream is invalid!");

			// test read/write
			size_t tmpSze = cnt - 1;
			std::vector<byte> tmp1(tmpSze);
			secStm1.Seek(0, SeekOrigin::Begin);
			secStm1.Read(tmp1, 0, tmpSze);
			std::vector<byte> tmp2(tmpSze);
			memcpy(&tmp2[0], &data[0], tmpSze);
			if (tmp1 != tmp2)
				throw TestException("CheckAccess: The stream is invalid!");

			// read byte from start
			secStm2.Seek(1, SeekOrigin::Begin);
			byte x = secStm2.ReadByte();
			if (x != data[1])
				throw TestException("CheckAccess: The stream is invalid!");

			// read byte from end
			secStm2.Seek(1, SeekOrigin::End);
			byte x1 = secStm2.ReadByte();
			if (x1 != data[cnt - 1])
				throw TestException("CheckAccess: The stream is invalid!");

			// prepend byte
			secStm2.Seek(0, SeekOrigin::Begin);
			secStm2.WriteByte(x1);
			secStm2.Seek(0, SeekOrigin::Begin);
			byte x2 = secStm2.ReadByte();
			if (x1 != x2)
				throw TestException("CheckAccess: The stream is invalid!");

			// append byte
			secStm2.Seek(0, SeekOrigin::Begin);
			secStm2.WriteByte(33);
			secStm2.Seek(0, SeekOrigin::Begin);
			x2 = secStm2.ReadByte();
			if (x2 != 33)
				throw TestException("CheckAccess: The stream is invalid!");
		}
	}

	void SecureStreamTest::CompareSerial()
	{
		Prng::SecureRandom rnd;
		std::vector<byte> data = rnd.GetBytes(1023);
		SecureStream secStm1(data);

		MemoryStream memStm;
		secStm1.CopyTo(&memStm);
		if (memStm.ToArray() != secStm1.ToArray() || memStm.ToArray() != data)
			throw TestException("CompareSerial: The serialized key is invalid!");
	}

	void SecureStreamTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}