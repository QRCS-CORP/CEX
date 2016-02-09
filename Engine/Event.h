#ifndef _CEXENGINE_EVENT_H
#define _CEXENGINE_EVENT_H

#include "Common.h"
#include <vector>
#include <algorithm>
#include "Delegate.h"

NAMESPACE_EVENT


/// <summary>
/// An Event interface pattern
/// <para>Uses callbacks to simulate low cost event processing</para>
/// </summary>
/// 
/// <example>
/// <description>Example of getting a seed value:</description>
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
/// 	CipherStream cs(CEX::Enumeration::SymmetricEngines::RDX,
/// 		22,
/// 		CEX::Enumeration::CipherModes::CBC,
/// 		CEX::Enumeration::PaddingModes::PKCS7);
/// 
/// 	SampleEvent evt;
/// 	cs.ProgressPercent += &evt.Completed;
/// 	std:vector&lt;byte&gt; key(32);
/// 	std:vector&lt;byte&gt; iv(16);
/// 	cs.Initialize(true, CEX::Common::KeyParams(key, iv));
/// 	std:vector&lt;byte&gt; data(32000);
/// 	std:vector&lt;byte&gt; vret(32000);
/// 	cs.Write(data, 0, vret, 0);
/// }
/// </code>
/// </example>
template <typename T>
class Event
{
private:
	std::vector< Delegate<T>* > _delegates;

public:

	/// <summary>
	/// 
	/// </summary>
	inline void operator+=(Delegate<T>* delegate)
	{
		// an object can only subscribe once
		if (find(_delegates.begin(), _delegates.end(), delegate) == _delegates.end())
			_delegates.push_back(delegate);
	}

	/// <summary>
	/// The -= operator
	/// </summary>
	inline void operator-=(Delegate<T>* delegate)
	{
		typedef typename std::vector< Delegate<T>* >::iterator iter;
		iter i = _delegates.begin();

		while (i != _delegates.end())
		{
			if (*i == delegate)
				i = _delegates.erase(i);
			else
				++i;
		}
	}

	/// <summary>
	/// The virtual operator
	/// </summary>
	inline void operator()(T param)
	{
		typedef typename std::vector< Delegate<T>* >::iterator iter;

		for (iter i = _delegates.begin(); i != _delegates.end(); ++i)
			(*i)->operator()(param);
	}
};

NAMESPACE_EVENTEND
#endif
