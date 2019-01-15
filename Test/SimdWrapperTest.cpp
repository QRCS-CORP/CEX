#include "SimdWrapperTest.h"

namespace Test
{
	const std::string SimdWrapperTest::CLASSNAME = "SymmetricKeyGeneratorTest";
	const std::string SimdWrapperTest::DESCRIPTION = "Simd wrapper test; tests the output of SIMD wrapper functions.";
	const std::string SimdWrapperTest::SUCCESS = "SUCCESS! All Simd wrapper tests have executed succesfully.";

	SimdWrapperTest::SimdWrapperTest()
		:
		m_progressEvent()
	{
	}

	SimdWrapperTest::~SimdWrapperTest()
	{
	}

	const std::string SimdWrapperTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &SimdWrapperTest::Progress()
	{
		return m_progressEvent;
}

	std::string SimdWrapperTest::Run()
	{
		try
		{
#if defined(__AVX512__)
			SimdMathCheck<Numeric::UInt512>();
			OnProgress(std::string("SimdWrapperTest: Passed UInt512 comparison tests.."));
#elif defined(__AVX2__)
			SimdMathCheck<Numeric::UInt256>();
			OnProgress(std::string("SimdWrapperTest: Passed UInt256 comparison tests.."));
#elif defined(__AVX__)
			SimdMathCheck<Numeric::UInt128>();
			OnProgress(std::string("SimdWrapperTest: Passed UInt128 comparison tests.."));
#endif

			return SUCCESS;
		}
		catch (TestException const &ex)
		{
			throw TestException(CLASSNAME, ex.Function(), ex.Origin(), ex.Message());
		}
		catch (std::exception const &ex)
		{
			throw TestException(CLASSNAME, std::string("Unknown Origin"), std::string(ex.what()));
		}
	}

	void SimdWrapperTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
