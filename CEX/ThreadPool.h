#ifndef CEX_THREADPOOL_H
#define CEX_THREADPOOL_H

#include "CexDomain.h"
#include <atomic>
#include <condition_variable>
#include <functional>
#include <list>
#include <mutex>
#include <thread>

NAMESPACE_ROOT

/// <summary>
/// A thread pool with dynamically sized thread allocations
/// </summary>
class ThreadPool 
{
private:

    static const size_t DEF_MAXTHREADS = 1024;

    std::vector<std::thread> m_threadPool;
    std::list<std::function<void(void)>> m_threadQueue;
    std::atomic_size_t      m_jobsRemaining;
    std::atomic_size_t      m_maxThreads;
    std::atomic_bool        m_jobsAbort;
    std::atomic_bool        m_jobsFinished;
    std::condition_variable m_jobsAvailable;
    std::condition_variable m_waitCondition;
    std::mutex              m_queueMutex;
    std::mutex              m_waitMutex;

public:

    /// <summary>
    /// The threadpool constructor
    /// </summary>
    /// 
    /// <param name="MaximumThreads">The maximum number of threads in the queue.
    /// <para>The thread count must be between 2 and 128 threads.</para></param>
    ThreadPool(size_t MaximumThreads = DEF_MAXTHREADS)
        : 
        m_threadPool(0),
        m_threadQueue(0),
        m_jobsRemaining(0),
        m_maxThreads(MaximumThreads > 1 && MaximumThreads <= DEF_MAXTHREADS ?
            MaximumThreads : 
            DEF_MAXTHREADS),
        m_jobsAbort(false), 
        m_jobsFinished(false)
    {
    }

    /// <summary>
    /// Destructor
    /// </summary>
    ~ThreadPool() 
    {
        JoinAll();
    }

    /// <summary>
    /// Get: The number of threads in the queue
    /// </summary>
    const size_t ThreadCount()
    {
        std::lock_guard<std::mutex> guard(m_queueMutex);

        return m_threadPool.size();
    }

    /// <summary>
    /// Get: The number of jobs remaining in the queue
    /// </summary>
    const size_t JobsRemaining() 
    {
        std::lock_guard<std::mutex> guard(m_queueMutex);

        return m_threadQueue.size();
    }

    /// <summary>
    /// Get: The maximum number of threads the queue can hold
    /// </summary>
    const size_t MaximumThreads()
    {
        std::lock_guard<std::mutex> guard(m_queueMutex);

        return DEF_MAXTHREADS;
    }

    /// <summary>
    /// Add a new job to the thread pool
    /// </summary>
    /// 
    /// <param name="Task">The asynchronous task to run</param>
    void AddTask(std::function<void(void)> Task)
    {
        std::lock_guard<std::mutex> guard(m_queueMutex);

        if (ThreadCount() < MaximumThreads())
        {
            m_threadPool.push_back(std::thread([this] { this->Task(); }));
        }

        m_threadQueue.emplace_back(Task);
        ++m_jobsRemaining;
        m_jobsAvailable.notify_one();
    }

    /// <summary>
    /// Add a detached new job to the thread pool
    /// </summary>
    /// 
    /// <param name="Task">The asynchronous task to run</param>
    void AddDetachedTask(std::function<void(void)> Task)
    {
        std::lock_guard<std::mutex> guard(m_queueMutex);

        if (ThreadCount() < MaximumThreads())
        {
            std::thread thd([this] { this->Task(); });
            thd.detach();
            m_threadPool.push_back(thd);
        }

        m_threadQueue.emplace_back(Task);
        ++m_jobsRemaining;
        m_jobsAvailable.notify_one();
    }

    /// <summary>
    /// Join all threads in the pool.
    /// </summary>
    /// 
    /// <param name="WaitForAll">If true, waits for the thread queue to empty, else completes current jobs</param>
    void JoinAll(bool WaitForAll = true)
    {
        if (!m_jobsFinished)
        {
            if (WaitForAll)
            {
                WaitAll();
            }

            // wake up any thread that's waiting for a new job
            m_jobsAbort = true;

            m_jobsAvailable.notify_all();

            for (auto &x : m_threadPool)
            {
                if (x.joinable())
                {
                    x.join();
                }
            }

            m_jobsFinished = true;
        }
    }

    /// <summary>
    /// Wait for the pool to empty all work items
    /// </summary>
    void WaitAll()
    {
        if (m_jobsRemaining > 0)
        {
            std::unique_lock<std::mutex> lock(m_waitMutex);
            m_waitCondition.wait(lock, [this] { return this->m_jobsRemaining == 0; });
            lock.unlock();
        }
    }

private:

    void Task()
    {
        while (!m_jobsAbort)
        {
            NextJob()();

            --m_jobsRemaining;
            m_waitCondition.notify_one();
        }
    }

    std::function<void(void)> NextJob()
    {
        std::unique_lock<std::mutex> lock(m_queueMutex);
        std::function<void(void)> func;

        // wait for a job if we don't have any.
        m_jobsAvailable.wait(lock, [this]() ->bool { return m_threadQueue.size() || m_jobsAbort; });

        // get job from the thread queue
        if (!m_jobsAbort)
        {
            func = m_threadQueue.front();
            m_threadQueue.pop_front();
        }
        else
        {
            func = []{};
            ++m_jobsRemaining;
        }

        return func;
    }
};

NAMESPACE_ROOTEND
#endif
