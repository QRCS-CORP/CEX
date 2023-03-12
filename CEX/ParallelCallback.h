#ifndef CEX_PARALLELCALLBACK_H
#define CEX_PARALLELCALLBACK_H

#include "CexDomain.h"
#include <functional>
#include <assert.h>
#include <algorithm>
#include <utility>
#include <atomic>
#include <mutex>
#include <future>

NAMESPACE_ROOT

typedef std::function<void()> Callback;

struct ParallelCallbackData
{
    Callback callback;
    std::atomic<int32_t> counter;
    std::atomic<bool> started;

    ParallelCallbackData(const Callback& callback) 
        :
        callback(callback), 
        counter(0),
        started(false)
    {
    }
};

class ParallelCallback
{
private:

    std::mutex m_mutex;

    typedef ParallelCallbackData Data;
    typedef std::shared_ptr<Data> DataPtr;

    DataPtr _data;

    static void step(const DataPtr& data)
    {
        if (data->counter-- == 0)
        {
            if (data->started && data->callback)
            {
                data->callback();
            }
        }
    }

public:

    ParallelCallback(const Callback& callback)
        :
        _data(new Data(callback))
    {
    }

    operator Callback()
    {
        assert(!_data->started);
        ++_data->counter;
        return std::bind(&ParallelCallback::step, _data);
    }

    void AsyncCall(const Callback &callback)
    {
        std::async(std::launch::async, [callback]() 
        {
            callback();
        });
    }

    void check()
    {
        assert(!_data->started);
        _data->started = true;
        step(_data);
    }
};

NAMESPACE_ROOTEND
#endif