#include "Wait.h"
#include "IntegerTools.h"
#include <assert.h>

#if defined(CEX_BERKELY_SOCKETS)
#	include <errno.h>
#	include <sys/types.h>
#	include <sys/time.h>
#	include <unistd.h>
#endif

NAMESPACE_NETWORK

using Enumeration::ErrorCodes;
using Utility::IntegerTools;

uint WaitObjectContainer::MaxWaitObjects()
{
#if defined(CEX_WINDOWS_SOCKETS)
	return MAXIMUM_WAIT_OBJECTS * (MAXIMUM_WAIT_OBJECTS - 1);
#else
	return FD_SETSIZE;
#endif
}

WaitObjectContainer::WaitObjectContainer(WaitObjectsTracer* tracer)
	: 
	m_tracer(tracer),
	m_eventTimer(Timer::MILLISECONDS)
	, m_sameResultCount(0),
	m_noWaitTimer(Timer::MILLISECONDS)
{
	Clear();
	m_eventTimer.StartTimer();
}

void WaitObjectContainer::Clear()
{
#if defined(CEX_WINDOWS_SOCKETS)
	m_handles.clear();
#else
	m_maxFd = 0;
	FD_ZERO(&m_readfds);
	FD_ZERO(&m_writefds);
#endif
	m_noWait = false;
	m_firstEventTime = 0;
}

inline void WaitObjectContainer::SetLastResult(LastResultType result)
{
	if (result == m_lastResult)
	{
		++m_sameResultCount;
	}
	else
	{
		m_lastResult = result;
		m_sameResultCount = 0;
	}
}

void WaitObjectContainer::DetectNoWait(LastResultType result, CallStack const& callStack)
{
	if (result == m_lastResult && m_noWaitTimer.ElapsedTime() > 1000)
	{
		if (m_sameResultCount > m_noWaitTimer.ElapsedTime())
		{
			if (m_tracer)
			{
				std::string desc = "No wait loop detected - m_lastResult: ";
				desc.append(IntegerTools::ToString(m_lastResult)).append(", call stack:");

				for (CallStack const* cs = &callStack; cs; cs = cs->Prev())
				{
					desc.append("\n- ").append(cs->Format());
				}

				m_tracer->TraceNoWaitLoop(desc);
			}
			try 
			{ 
				throw CryptoException(std::string("WaitObjectContainer"), std::string("DetectNoWait"), std::string("No message"), ErrorCodes::IllegalOperation);
			}
			catch (CryptoException const)
			{
			}
		}

		m_noWaitTimer.StartTimer();
		m_sameResultCount = 0;
	}
}

void WaitObjectContainer::SetNoWait(CallStack const& callStack)
{
	DetectNoWait(LASTRESULT_NOWAIT, CallStack("WaitObjectContainer::SetNoWait()", &callStack));
	m_noWait = true;
}

void WaitObjectContainer::ScheduleEvent(double milliseconds, CallStack const& callStack)
{
	double etme;

	if (milliseconds <= 3)
	{
		DetectNoWait(LASTRESULT_SCHEDULED, CallStack("WaitObjectContainer::ScheduleEvent()", &callStack));
	}

	etme = m_eventTimer.ElapsedTimeAsDouble() + milliseconds;

	if (!m_firstEventTime || etme < m_firstEventTime)
	{
		m_firstEventTime = etme;
	}
}

#if defined(CEX_WINDOWS_SOCKETS)

struct WaitingThreadData
{
	bool waitingToWait, terminate;
	HANDLE startWaiting, stopWaiting;
	const HANDLE *waitHandles;
	uint count;
	HANDLE threadHandle;
	DWORD threadId;
	DWORD* error;
};

WaitObjectContainer::~WaitObjectContainer()
{
	// don't let exceptions escape destructor

	try
	{
		if (!m_threads.empty())
		{
			HANDLE threadHandles[MAXIMUM_WAIT_OBJECTS];
			uint i;

			for (i = 0; i < m_threads.size(); i++)
			{
				WaitingThreadData &thread = *m_threads[i];

				// spin until thread is in the initial "waiting to wait" state
				while (!thread.waitingToWait)
				{
					Sleep(0);
				}

				thread.terminate = true;
				threadHandles[i] = thread.threadHandle;
			}

			PulseEvent(m_startWaiting);
			::WaitForMultipleObjects((DWORD)m_threads.size(), threadHandles, TRUE, INFINITE);

			for (i = 0; i < m_threads.size(); ++i)
			{
				CloseHandle(threadHandles[i]);
			}

			CloseHandle(m_startWaiting);
			CloseHandle(m_stopWaiting);
		}
	}
	catch (std::exception&)
	{
	}
}


void WaitObjectContainer::AddHandle(HANDLE handle, CallStack const& callStack)
{
	DetectNoWait(m_handles.size(), CallStack("WaitObjectContainer::AddHandle()", &callStack));
	m_handles.push_back(handle);
}

DWORD WINAPI WaitingThread(LPVOID lParam)
{
	std::auto_ptr<WaitingThreadData> pThread((WaitingThreadData*)lParam);
	WaitingThreadData &thread = *pThread;
	std::vector<HANDLE> handles;

	while (true)
	{
		thread.waitingToWait = true;
		::WaitForSingleObject(thread.startWaiting, INFINITE);
		thread.waitingToWait = false;

		if (thread.terminate)
		{
			break;
		}
		if (!thread.count)
		{
			continue;
		}

		handles.resize(thread.count + 1);
		handles[0] = thread.stopWaiting;
		std::copy(thread.waitHandles, thread.waitHandles + thread.count, handles.begin() + 1);

		DWORD result = ::WaitForMultipleObjects((DWORD)handles.size(), &handles[0], FALSE, INFINITE);

		// another thread finished waiting first, so do nothing
		if (result == WAIT_OBJECT_0)
		{
			continue;
		}

		SetEvent(thread.stopWaiting);

		if (!(result > WAIT_OBJECT_0 && result < WAIT_OBJECT_0 + handles.size()))
		{
			// break here so we can see which thread has an error
			assert(!"error in WaitingThread");
			*thread.error = ::GetLastError();
		}
	}

	// return a value here to avoid compiler warning
	return S_OK;
}

void WaitObjectContainer::CreateThreads(uint count)
{
	size_t nthrd;

	nthrd = m_threads.size();

	if (nthrd == 0)
	{
		m_startWaiting = ::CreateEvent(NULL, TRUE, FALSE, NULL);
		m_stopWaiting = ::CreateEvent(NULL, TRUE, FALSE, NULL);
	}

	if (nthrd < count)
	{
		m_threads.resize(count);

		for (size_t i = nthrd; i < count; ++i)
		{
			m_threads[i] = new WaitingThreadData;
			WaitingThreadData &thread = *m_threads[i];
			thread.terminate = false;
			thread.startWaiting = m_startWaiting;
			thread.stopWaiting = m_stopWaiting;
			thread.waitingToWait = false;
			thread.threadHandle = CreateThread(NULL, 0, &WaitingThread, &thread, 0, &thread.threadId);
		}
	}
}

bool WaitObjectContainer::Wait(ulong milliseconds)
{
	bool sched;

	if (m_noWait || (m_handles.empty() && !m_firstEventTime))
	{
		SetLastResult(LASTRESULT_NOWAIT);
		return true;
	}

	sched = false;

	if (m_firstEventTime)
	{
		double timeToFirstEvent = IntegerTools::SaturatingSubtract(m_firstEventTime, m_eventTimer.ElapsedTimeAsDouble());

		if (timeToFirstEvent <= milliseconds)
		{
			milliseconds = (ulong)timeToFirstEvent;
			sched = true;
		}

		if (m_handles.empty() || !milliseconds)
		{
			if (milliseconds)
			{
				Sleep(milliseconds);
			}

			SetLastResult(sched ? LASTRESULT_SCHEDULED : LASTRESULT_TIMEOUT);
			return sched;
		}
	}

	if (m_handles.size() > MAXIMUM_WAIT_OBJECTS)
	{
		// too many wait objects for a single WaitForMultipleObjects call, so use multiple threads
		static const uint WAIT_OBJECTS_PER_THREAD = MAXIMUM_WAIT_OBJECTS - 1;
		uint nthrd;

		nthrd = static_cast<uint>((m_handles.size() + WAIT_OBJECTS_PER_THREAD - 1) / WAIT_OBJECTS_PER_THREAD);

		if (nthrd > MAXIMUM_WAIT_OBJECTS)
		{
			throw CryptoException(std::string("WaitObjectContainer"), std::string("Wait"), std::string("Too many wait objects"), ErrorCodes::MaxExceeded);
		}

		CreateThreads(nthrd);
		DWORD error = S_OK;

		for (uint i = 0; i < m_threads.size(); ++i)
		{
			WaitingThreadData &thread = *m_threads[i];

			// spin until thread is in the initial "waiting to wait" state
			while (!thread.waitingToWait)
			{
				Sleep(0);
			}

			if (i < nthrd)
			{
				thread.waitHandles = &m_handles[i * WAIT_OBJECTS_PER_THREAD];
				thread.count = IntegerTools::Min((size_t)WAIT_OBJECTS_PER_THREAD, (m_handles.size() - i * WAIT_OBJECTS_PER_THREAD));
				thread.error = &error;
			}
			else
			{
				thread.count = 0;
			}
		}

		ResetEvent(m_stopWaiting);
		PulseEvent(m_startWaiting);

		DWORD result = ::WaitForSingleObject(m_stopWaiting, milliseconds);

		if (result == WAIT_OBJECT_0)
		{
			if (error == S_OK)
			{
				return true;
			}
			else
			{
				throw CryptoException(std::string("WaitObjectContainer"), std::string("Wait"), std::string("Too many wait objects"), ErrorCodes::MaxExceeded);
			}
		}

		SetEvent(m_stopWaiting);

		if (result == WAIT_TIMEOUT)
		{
			SetLastResult(sched ? LASTRESULT_SCHEDULED : LASTRESULT_TIMEOUT);

			return sched;
		}
		else
		{
			throw CryptoException(std::string("WaitObjectContainer"), std::string("Wait"), IntegerTools::ToString(::GetLastError()), ErrorCodes::IllegalOperation);
		}
	}
	else
	{
#if TRACE_WAIT
		static Timer t(Timer::MICROSECONDS);
		static ulong lastTime = 0;
		ulong timeBeforeWait = t.ElapsedTime();
#endif
		DWORD result = ::WaitForMultipleObjects((DWORD)m_handles.size(), &m_handles[0], FALSE, milliseconds);
#if TRACE_WAIT
		if (milliseconds > 0)
		{
			ulong timeAfterWait = t.ElapsedTime();
			OutputDebugString(("Handles " + IntToString(m_handles.size()) + ", Woke up by " + IntToString(result - WAIT_OBJECT_0) + ", Busied for " + IntToString(timeBeforeWait - lastTime) + " us, Waited for " + IntToString(timeAfterWait - timeBeforeWait) + " us, max " + IntToString(milliseconds) + "ms\n").c_str());
			lastTime = timeAfterWait;
		}
#endif
		if (result >= WAIT_OBJECT_0 && result < WAIT_OBJECT_0 + m_handles.size())
		{
			if (result == m_lastResult)
			{
				++m_sameResultCount;
			}
			else
			{
				m_lastResult = result;
				m_sameResultCount = 0;
			}

			return true;
		}
		else if (result == WAIT_TIMEOUT)
		{
			SetLastResult(sched ? LASTRESULT_SCHEDULED : LASTRESULT_TIMEOUT);
			return sched;
		}
		else
		{
			throw CryptoException(std::string("WaitObjectContainer"), std::string("Wait"), IntegerTools::ToString(::GetLastError()), ErrorCodes::IllegalOperation);
		}
	}
}

#else

void WaitObjectContainer::AddReadFd(int fd, CallStack const& callStack)	// TODO: do something with callStack
{
	FD_SET(fd, &m_readfds);
	m_maxFd = STDMAX(m_maxFd, fd);
}

void WaitObjectContainer::AddWriteFd(int fd, CallStack const& callStack) // TODO: do something with callStack
{
	FD_SET(fd, &m_writefds);
	m_maxFd = STDMAX(m_maxFd, fd);
}

bool WaitObjectContainer::Wait(ulong milliseconds)
{
	bool sched;

	if (m_noWait || (!m_maxFd && !m_firstEventTime))
	{
		return true;
	}

	sched = false;

	if (m_firstEventTime)
	{
		double timeToFirstEvent = SaturatingSubtract(m_firstEventTime, m_eventTimer.ElapsedTimeAsDouble());

		if (timeToFirstEvent <= milliseconds)
		{
			milliseconds = (ulong)timeToFirstEvent;
			sched = true;
		}
	}

	timeval tv, *timeout;

	if (milliseconds == INFINITE_TIME)
	{
		timeout = NULL;
	}
	else
	{
		tv.tv_sec = milliseconds / 1000;
		tv.tv_usec = (milliseconds % 1000) * 1000;
		timeout = &tv;
	}

	int result = select(m_maxFd + 1, &m_readfds, &m_writefds, NULL, timeout);

	if (result > 0)
	{
		return true;
	}
	else if (result == 0)
	{
		return sched;
	}
	else
	{
		throw CryptoException(std::string("WaitObjectContainer"), std::string("Wait"), std::string("Select failed with error ") + IntegerTools::ToString(errno), ErrorCodes::IllegalOperation);
	}
}

#endif

std::string CallStack::Format() const
{
	return m_info;
}

NAMESPACE_NETWORKEND