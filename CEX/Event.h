#ifndef CEX_EVENT_H
#define CEX_EVENT_H

#include "CexDomain.h"
#include "Delegate.h"

NAMESPACE_ROUTING

/// <summary>
/// An Event interface pattern
/// <para>Uses callbacks to simulate low cost event processing</para>
/// </summary>
/// 
/// <example>
/// <description>Example of returning a value:</description>
/// <code>
/// class SampleEvent
/// {
/// public:
/// 	SampleEvent();
/// 	void Completed(int result);
/// 	LISTENER(SampleEvent, Completed, int);
/// };
/// 
/// SampleEvent::SampleEvent()
/// 	: LCompleted(this)
/// { }
/// 
/// void SampleEvent::Completed(int result)
/// {
/// 	std::cout << result << std::endl;
/// }
/// 
/// void ProgressTest()
/// {
/// 	CipherStream cs(Enumeration::SymmetricCiphers::RHX,
/// 		Enumeration::CipherModes::CBC,
/// 		Enumeration::PaddingModes::PKCS7);
/// 
/// 	SampleEvent evt;
/// 	cs.ProgressPercent += &evt.Completed;
/// 	std::vector&lt;byte&gt; key(32);
/// 	std::vector&lt;byte&gt; iv(16);
/// 	cs.Initialize(true, Cipher::SymmetricKey(key, iv));
/// 	std::vector&lt;byte&gt; data(32000);
/// 	std::vector&lt;byte&gt; vret(32000);
/// 	cs.Write(data, 0, vret, 0);
/// }
/// </code>
/// </example>
template <typename T>
class Event
{
private:
	std::vector<Delegate<T>*> m_delegates;

public:

	/// <summary>
	/// 
	/// </summary>
	inline void operator+=(Delegate<T>* delegate)
	{
		// an object can only subscribe once
		if (find(m_delegates.begin(), m_delegates.end(), delegate) == m_delegates.end())
		{
			m_delegates.push_back(delegate);
		}
	}

	/// <summary>
	/// The -= operator
	/// </summary>
	inline void operator-=(Delegate<T>* delegate)
	{
		typedef typename std::vector<Delegate<T>*>::iterator iter;
		iter i;

		i = m_delegates.begin();

		while (i != m_delegates.end())
		{
			if (*i == delegate)
			{
				i = m_delegates.erase(i);
			}
			else
			{
				++i;
			}
		}
	}

	/// <summary>
	/// The virtual operator
	/// </summary>
	inline void operator()(T param)
	{
		typedef typename std::vector<Delegate<T>*>::iterator iter;

		for (iter i = m_delegates.begin(); i != m_delegates.end(); ++i)
		{
			(*i)->operator()(param);
		}
	}
};

NAMESPACE_ROUTINGEND
#endif
