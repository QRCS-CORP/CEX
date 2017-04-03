#ifndef _CEXENGINE_TESTEXCEPTION_H
#define _CEXENGINE_TESTEXCEPTION_H

#include <string>
#include <iostream>
#include <exception>

namespace Test
{
	/// <summary>
	/// Generalized error container
	/// </summary>
	struct TestException : std::exception
	{
	private:
		std::string m_origin;
		std::string m_message;

	public:
		/// <summary>
		/// The origin of the exception in the format Class:Method
		/// </summary>
		const std::string &Origin() const { return m_origin; }
		std::string &Origin() { return m_origin; }

		const std::string &Message() const { return m_message; }
		std::string &Message() { return m_message; }

		/// <summary>
		/// Exception constructor
		/// </summary>
		///
		/// <param name="Message">A custom message or error data</param>
		explicit TestException(const std::string &Message)
			:
			m_origin(""),
			m_message(Message)
		{
		}

		/// <summary>
		/// Exception constructor
		/// </summary>
		///
		/// <param name="Origin">The origin of the exception</param>
		/// <param name="Message">A custom message or error data</param>
		TestException(const std::string &Origin, const std::string &Message)
			:
			m_origin(Origin),
			m_message(Message)
		{
		}
	};
}
#endif