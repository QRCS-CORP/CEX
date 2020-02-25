#include "WindowsHandle.h"

NAMESPACE_UTILITY

WindowsHandle::WindowsHandle(HANDLE Handle, bool Owner)
	: 
	m_h(Handle),
	m_own(Owner)
{
}

WindowsHandle::~WindowsHandle()
{
	if (m_own)
	{
		try
		{
			CloseHandle();
		}
		catch (...)
		{
		}
	}
}

bool WindowsHandle::HandleValid() const
{
	return m_h && m_h != INVALID_HANDLE_VALUE;
}

void WindowsHandle::AttachHandle(HANDLE h, bool own)
{
	if (m_own)
	{
		CloseHandle();
	}

	m_h = h;
	m_own = own;
	HandleChanged();
}

HANDLE WindowsHandle::DetachHandle()
{
	HANDLE h = m_h;
	m_h = INVALID_HANDLE_VALUE;
	HandleChanged();
	return h;
}

void WindowsHandle::CloseHandle()
{
	if (m_h != INVALID_HANDLE_VALUE)
	{
		::CloseHandle(m_h);
		m_h = INVALID_HANDLE_VALUE;
		HandleChanged();
	}
}

NAMESPACE_UTILITYEND
