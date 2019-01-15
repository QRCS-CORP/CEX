#ifndef CEXENGINE_TESTEXCEPTION_H
#define CEXENGINE_TESTEXCEPTION_H

#include <exception>
#include <iostream>
#include <string>

namespace Test
{
	/// <summary>
	/// Generalized error container
	/// </summary>
	struct TestException : std::exception
	{
	private:

		std::string m_function;
		std::string m_location;
		std::string m_message;
		std::string m_origin;

	public:

		/// <summary>
		/// Exception constructor
		/// </summary>
		///
		/// <param name="Function">The name of the function throwing the exception</param>
		/// <param name="Origin">The primitive origin of the exception</param>
		/// <param name="Message">The custom message or error data</param>
		TestException(const std::string &Function, const std::string &Origin, const std::string &Message)
			:
			m_function(Function),
			m_location(""),
			m_origin(Origin),
			m_message(Message)
		{
		}

		/// <summary>
		/// Exception constructor
		/// </summary>
		///
		/// <param name="Location">The class location of the exception</param>
		/// <param name="Function">The name of the function throwing the exception</param>
		/// <param name="Origin">The primitive origin of the exception</param>
		/// <param name="Message">The custom message or error data</param>
		TestException(const std::string &Location, const std::string &Function, const std::string &Origin, const std::string &Message)
			:
			m_function(Function),
			m_location(Location),
			m_origin(Origin),
			m_message(Message)
		{
		}

		/// <summary>
		/// The name of the function throwing the exception
		/// </summary>
		const std::string &Function() const
		{
			return m_function;
		}

		/// <summary>
		/// The class location of the exception
		/// </summary>
		const std::string &Location() const
		{
			return m_location;
		}

		/// <summary>
		/// The primitive origin of the exception
		/// </summary>
		const std::string &Origin() const
		{
			return m_origin;
		}

		/// <summary>
		/// The custom message or error data
		/// </summary>
		const std::string &Message() const
		{
			return m_message;
		}
	};
}

#endif
