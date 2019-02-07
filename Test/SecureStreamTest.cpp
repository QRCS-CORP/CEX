#include "SecureStreamTest.h"
#include "../CEX/MemoryStream.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SecureStream.h"

namespace Test
{
	using namespace CEX::IO;

	const std::string SecureStreamTest::CLASSNAME = "SecureStreamTest";
	const std::string SecureStreamTest::DESCRIPTION = "SecureStream test; compares serialization, reads and writes";
	const std::string SecureStreamTest::SUCCESS = "SUCCESS! All SecureStream tests have executed succesfully.";

	SecureStreamTest::SecureStreamTest()
		:
		m_progressEvent()
	{
	}

	SecureStreamTest::~SecureStreamTest()
	{
	}

	const std::string SecureStreamTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &SecureStreamTest::Progress()
	{
		return m_progressEvent;
	}

	std::string SecureStreamTest::Run()
	{
		try
		{
			Evaluate();
			OnProgress(std::string("SecureStreamTest: Passed read/write comparison tests.."));
			Serialization();
			OnProgress(std::string("SecureStreamTest: Passed serialization tests.."));

			return SUCCESS;
		}
		catch (TestException const &ex)
		{
			throw TestException(CLASSNAME, ex.Function(), ex.Origin(), ex.Message());
		}
		catch (CryptoException &ex)
		{
			throw TestException(CLASSNAME, ex.Location(), ex.Origin(), ex.Message());
		}
		catch (std::exception const &ex)
		{
			throw TestException(CLASSNAME, std::string("Unknown Origin"), std::string(ex.what()));
		}
	}

	void SecureStreamTest::Evaluate()
	{
		Prng::SecureRandom gen;
		uint32_t cnt;
		std::vector<byte> data;

		for (size_t i = 0; i < 10; ++i)
		{
			cnt = gen.NextUInt32(4000, 40);
			data = gen.Generate(cnt);

			// add array via constructor
			SecureStream sec1(data);
			if (sec1.ToArray() != data)
			{
				throw TestException(std::string("Evaluate"), gen.Name(), std::string("The stream is invalid! -SE1"));
			}

			// test write method
			SecureStream sec2;
			sec2.Write(data, 0, data.size());
			if (sec2.ToArray() != data)
			{
				throw TestException(std::string("Evaluate"), gen.Name(), std::string("The stream is invalid! -SE2"));
			}

			// test read/write
			size_t tmpSze = cnt - 1;
			std::vector<byte> tmp1(tmpSze);
			sec1.Seek(0, SeekOrigin::Begin);
			sec1.Read(tmp1, 0, tmpSze);
			std::vector<byte> tmp2(tmpSze);
			memcpy(&tmp2[0], &data[0], tmpSze);
			if (tmp1 != tmp2)
			{
				throw TestException(std::string("Evaluate"), gen.Name(), std::string("The stream is invalid! -SE3"));
			}

			// read byte from start
			sec2.Seek(1, SeekOrigin::Begin);
			byte x = sec2.ReadByte();
			if (x != data[1])
			{
				throw TestException(std::string("Evaluate"), gen.Name(), std::string("The stream is invalid! -SE4"));
			}

			// read byte from end
			sec2.Seek(1, SeekOrigin::End);
			byte x1 = sec2.ReadByte();
			if (x1 != data[cnt - 1])
			{
				throw TestException(std::string("Evaluate"), gen.Name(), std::string("The stream is invalid! -SE5"));
			}

			// prepend byte
			sec2.Seek(0, SeekOrigin::Begin);
			sec2.WriteByte(x1);
			sec2.Seek(0, SeekOrigin::Begin);
			byte x2 = sec2.ReadByte();
			if (x1 != x2)
			{
				throw TestException(std::string("Evaluate"), gen.Name(), std::string("The stream is invalid! -SE6"));
			}

			// append byte
			sec2.Seek(0, SeekOrigin::Begin);
			sec2.WriteByte(33);
			sec2.Seek(0, SeekOrigin::Begin);
			x2 = sec2.ReadByte();
			if (x2 != 33)
			{
				throw TestException(std::string("Evaluate"), gen.Name(), std::string("The stream is invalid! -SE7"));
			}
		}
	}

	void SecureStreamTest::Serialization()
	{
		Prng::SecureRandom gen;
		std::vector<byte> data = gen.Generate(1023);
		SecureStream sec(data);

		MemoryStream mem;
		sec.CopyTo(&mem);
		if (mem.ToArray() != sec.ToArray() || mem.ToArray() != data)
		{
			throw TestException(std::string("Evaluate"), gen.Name(), std::string("The serialized key is invalid! -SS1"));
		}
	}

	void SecureStreamTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
