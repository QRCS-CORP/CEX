#ifndef _CEX_DELEGATE_H
#define _CEX_DELEGATE_H

#include "CexDomain.h"

NAMESPACE_ROUTING

/// <summary>
/// The Delegate Listener interface definition
/// </summary>
#define LISTENER(thisType, handler, type)\
    class __L##handler##__ : public Delegate< type >\
    {\
        public:\
            __L##handler##__ ( thisType * obj )\
            : _obj(obj) {}\
            inline void operator()( type param )\
            {\
                _obj-> handler (param);\
            }\
            thisType * _obj;\
    };\
    __L##handler##__ L##handler;

/// <summary>
/// A Delegate interface pattern pattern
/// </summary>
template <typename T>
class Delegate
{
public:

	/// <summary>
	/// The virtual operator
	/// </summary>
	virtual void operator()(T param) = 0;
};

NAMESPACE_ROUTINGEND
#endif
