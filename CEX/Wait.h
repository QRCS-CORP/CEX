#ifndef CEX_WAIT_H
#define CEX_WAIT_H

// 'borrowed' from crypto++

#include "CexDomain.h"
#include "CryptoException.h"
#include "CryptoSocketException.h"
#include "Timer.h"

#if defined(CEX_WINDOWS_SOCKETS)
#	include <winsock2.h>
#else
#	include <errno.h>
#	include <sys/types.h>
#	include <sys/time.h>
#	include <unistd.h>
#endif

NAMESPACE_NETWORK

using Exception::CryptoException;
using Utility::Timer;

class Tracer
{
private:

	uint m_level;

public:

	Tracer(uint level) 
		: 
		m_level(level) 
	{
	}

	virtual ~Tracer()
	{
	}

protected:

	// Override this in your most-derived tracer to do the actual tracing.
	virtual void Trace(uint n, std::string const& s) = 0;

	// By default, tracers will decide which trace messages to trace according to a trace level
	// mechanism. If your most-derived tracer uses a different mechanism, override this to
	// return false. If this method returns false, the default TraceXxxx(void) methods will all
	// return 0 and must be overridden explicitly by your tracer for trace messages you want.
	virtual bool UsingDefaults() const 
	{ 
		return true; 
	}

	void TraceIf(uint n, std::string const&s)
	{
		if (n)
		{
			Trace(n, s);
		}
	}

	// Returns nr if, according to the default log settings mechanism (using log levels),
	// the message should be traced. Returns 0 if the default trace level mechanism is not
	// in use, or if it is in use but the event should not be traced. Provided as a utility
	// method for easier and shorter coding of default TraceXxxx(void) implementations.
	uint Tracing(uint nr, uint minLevel) const
	{
		return (UsingDefaults() && m_level >= minLevel) ? nr : 0;
	}
};

// Your Tracer-derived class should inherit as virtual public from Tracer or another
// Tracer-derived class, and should pass the log level in its constructor. You can use the
// following methods to begin and end your Tracer definition.

// This constructor macro initializes Tracer directly even if not derived directly from it;
// this is intended, virtual base classes are always initialized by the most derived class.
#define CEX_TRACER_CONSTRUCTOR(DERIVED) \
public: DERIVED(uint level = 0) : Tracer(level) {}

#define CEX_BEGIN_TRACER_CLASS_1(DERIVED, BASE1) \
class DERIVED : virtual public BASE1 { CEX_TRACER_CONSTRUCTOR(DERIVED)

#define CEX_BEGIN_TRACER_CLASS_2(DERIVED, BASE1, BASE2) \
class DERIVED : virtual public BASE1, virtual public BASE2 { CEX_TRACER_CONSTRUCTOR(DERIVED)

#define CEX_END_TRACER_CLASS };

// In your Tracer-derived class, you should define a globally unique event number for each
// new event defined. This can be done using the following macros.

#define CEX_BEGIN_TRACER_EVENTS(UNIQUENR)	enum { EVENTBASE = UNIQUENR,
#define CEX_TRACER_EVENT(EVENTNAME)				EventNr_##EVENTNAME,
#define CEX_END_TRACER_EVENTS				};

// In your own Tracer-derived class, you must define two methods per new trace event type:
// - uint TraceXxxx() const
//   Your default implementation of this method should return the event number if according
//   to the default trace level system the event should be traced, or 0 if it should not.
// - void TraceXxxx(string const& s)
//   This method should call TraceIf(TraceXxxx(), s); to do the tracing.
// For your convenience, a macro to define these two types of methods are defined below.
// If you use this macro, you should also use the TRACER_EVENTS macros above to associate
// event names with numbers.

#define CEX_TRACER_EVENT_METHODS(EVENTNAME, LOGLEVEL) \
virtual uint Trace##EVENTNAME() const { return Tracing(EventNr_##EVENTNAME, LOGLEVEL); } \
virtual void Trace##EVENTNAME(std::string const& s) { TraceIf(Trace##EVENTNAME(), s); }


// A simple unidirectional linked list with m_prev == 0 to indicate the final entry.
// The aim of this implementation is to provide a very lightweight and practical
// tracing mechanism with a low performance impact. Functions and methods supporting
// this call-stack mechanism would take a parameter of the form "CallStack const& callStack",
// and would pass this parameter to subsequent functions they call using the construct:
//
// SubFunc(arg1, arg2, CallStack("my func at place such and such", &callStack));
//
// The advantage of this approach is that it is easy to use and should be very efficient,
// involving no allocation from the heap, just a linked list of stack objects containing
// pointers to static ASCIIZ strings (or possibly additional but simple data if derived).
class CallStack
{
protected:

	char const* m_info;
	CallStack const* m_prev;

public:

	CallStack(char const* i, CallStack const* p)
		: 
		m_info(i), 
		m_prev(p) 
	{
	}

	CallStack const* Prev() const 
	{ 
		return m_prev; 
	}

	virtual std::string Format() const;


};

// An extended CallStack entry type with an additional numeric parameter.
class CallStackWithNr : public CallStack
{
protected:

	uint m_nr;

public:

	CallStackWithNr(char const* i, uint n, CallStack const* p)
		: 
		CallStack(i, p), m_nr(n)
	{
	}

	std::string Format() const;


};


CEX_BEGIN_TRACER_CLASS_1(WaitObjectsTracer, Tracer)
	CEX_BEGIN_TRACER_EVENTS(0x48752841)
	CEX_TRACER_EVENT(NoWaitLoop)
	CEX_END_TRACER_EVENTS
	CEX_TRACER_EVENT_METHODS(NoWaitLoop, 1)
	CEX_END_TRACER_CLASS

	struct WaitingThreadData;

// container of wait objects
class WaitObjectContainer
{
public:

	WaitObjectContainer(WaitObjectsTracer* tracer = 0);

	static uint MaxWaitObjects();

	void Clear();
	void SetNoWait(CallStack const& callStack);
	void ScheduleEvent(double milliseconds, CallStack const& callStack);
	// returns false if timed out
	bool Wait(ulong milliseconds);

#ifdef CEX_WINDOWS_SOCKETS
	~WaitObjectContainer();
	void AddHandle(HANDLE handle, CallStack const& callStack);
#else
	void AddReadFd(int fd, CallStack const& callStack);
	void AddWriteFd(int fd, CallStack const& callStack);
#endif

private:
	WaitObjectsTracer* m_tracer;

#ifdef CEX_WINDOWS_SOCKETS
	void CreateThreads(uint count);
	std::vector<HANDLE> m_handles;
	std::vector<WaitingThreadData *> m_threads;
	HANDLE m_startWaiting;
	HANDLE m_stopWaiting;
#else
	fd_set m_readfds, m_writefds;
	int m_maxFd;
#endif

	bool m_noWait;
	double m_firstEventTime;
	Timer m_eventTimer;

#ifdef CEX_WINDOWS_SOCKETS
	typedef size_t LastResultType;
#else
	typedef int LastResultType;
#endif

	enum : int
	{ 
		LASTRESULT_NOWAIT = -1, 
		LASTRESULT_SCHEDULED = -2, 
		LASTRESULT_TIMEOUT = -3 
	};

	LastResultType m_lastResult;
	uint m_sameResultCount;
	Timer m_noWaitTimer;
	void SetLastResult(LastResultType result);
	void DetectNoWait(LastResultType result, CallStack const& callStack);
};

NAMESPACE_NETWORKEND
#endif

