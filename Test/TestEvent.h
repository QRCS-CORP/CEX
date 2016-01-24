#ifndef _CEXTEST_TESTEVENT_H
#define _CEXTEST_TESTEVENT_H

#include <vector>
#include <iostream>

namespace Test
{
	template <typename ListenerType>
	class TestEvent
	{
	private:
		std::vector<ListenerType*> _listeners;

	public:
		void operator += (ListenerType* Listener)
		{
			_listeners.push_back(Listener);
		}

		void operator -= (ListenerType* Listener)
		{
			for (unsigned int i = 0; i < _listeners.size(); i++)
			{
				if (_listeners[i] == Listener)
				{
					_listeners.erase(_listeners.begin() + i);
					break;
				}
			}
		}

		template <typename... Params>
		void operator()(Params... Data) 
		{
			for (auto l : _listeners)
				(*l)(Data...);
		}
	};

	class EventHandler 
	{
	public:
	};
}

#endif