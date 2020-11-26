#ifndef CEX_WINDOWSHANDLE_H
#define CEX_WINDOWSHANDLE_H

#include "CexDomain.h"
#include <winsock2.h>

NAMESPACE_TOOLS

//! Windows Handle
class WindowsHandle
{
public:

	WindowsHandle(HANDLE h = INVALID_HANDLE_VALUE, bool own = false);
	WindowsHandle(const WindowsHandle &h) : m_h(h.m_h), m_own(false) {}
	~WindowsHandle();

	bool GetOwnership() const { return m_own; }
	void SetOwnership(bool own) { m_own = own; }

	operator HANDLE() 
	{ 
		return m_h; 
	}

	HANDLE GetHandle() const 
	{ 
		return m_h; 
	}

	bool HandleValid() const;
	void AttachHandle(HANDLE h, bool own = false);
	HANDLE DetachHandle();
	void CloseHandle();

protected:
	void HandleChanged() {}

	HANDLE m_h;
	bool m_own;
};

NAMESPACE_TOOLSEND
#endif
