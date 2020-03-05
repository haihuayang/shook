# README #

Shook stands for syscall hook.

Register python hooks to handle entering and leaving system call, entering signal.
The hooks can access tracee's system call arguments and return value.

Return value of hooks

    None, the tracee continue the system call
    (ACTION_BYPASS, retval), the tracee skip the system call and return retval directly
    (ACTION_REDIRECT, newsyscall, argument, ...), redirect system call to newsyscall with the arguments
    (ACTION_SUSPEND, ), suspend tracee
    (ACTION_GDB, ), launch GDB attaching to tracee
    (ACTION_DETACH, ), detach the tracee
    (ACTION_RETURN, retval), change the system call return value
    (ACTION_KILL, signal), send signal to tracee


Shook Functions
    alloc_copy(...)
        alloc_copy(pid, data) -> address
    
    alloc_stack(...)
        alloc_stack(pid, size) -> address
    
    backtrace(...)
        backtrace(pid [, depth]) -> (stackframe, ...)
    
    cancel_timer(...)
        Cancel a timer
    
    peek_data(...)
        peek_data(pid, addr, len) -> data
        Read data from tracee
    
    peek_datav(...)
        peek_datav(pid, total | None, (addr, len), ...) -> data
        Read data from pid's space
    
    peek_epoll_event(...)
        Read epoll_event array from tracee
    
    peek_iovec(...)
        Read iovec array from tracee
    
    peek_mmsghdr(...)
        Read mmsghdr array from tracee
    
    peek_msghdr(...)
        Read msghdr array from tracee
    
    peek_path(...)
        Read path from tracee
    
    peek_pollfd(...)
        Read pollfd array from tracee
    
    peek_sockaddr(...)
        peek_sockaddr(pid, addr, slen) -> tuple
        Read sockaddr from tracee
    
    peek_timespec(...)
        Read timespec array from tracee
    
    peek_timeval(...)
        Read timeval array from tracee
    
    peek_timezone(...)
        Read timezone array from tracee
    
    peek_uint32(...)
        Read uint32 array from tracee
    
    peek_uint64(...)
        Read uint64 array from tracee
    
    poke_data(...)
        Write data to tracee
    
    poke_datav(...)
        poke_datav(pid, data, (addr, len), ...)
        "Write data to tracee
    
    poke_epoll_event(...)
        Write epoll_event array to tracee
    
    poke_iovec(...)
        Write iovec array to tracee
    
    poke_mmsghdr(...)
        Write mmsghdr array to tracee
    
    poke_msghdr(...)
        Write msghdr array to tracee
    
    poke_pollfd(...)
        Write pollfd array to tracee
    
    poke_sockaddr(...)
        poke_sockaddr(pid, addr, len, af, ...)
        Write sockaddr to tracee
    
    poke_sockaddr2(...)
        poke_sockaddr2(pid, addr, plen, af, ...)
        Write sockaddr to tracee, unlike to poke_sockaddr, plen is an address
    
    poke_timespec(...)
        Write timespec array to tracee
    
    poke_timeval(...)
        Write timeval array to tracee
    
    poke_timezone(...)
        Write timezone array to tracee
    
    poke_uint32(...)
        Write uint32 array to tracee
    
    poke_uint64(...)
        Write uint64 array to tracee
    
    register(...)
        register(event, handler, ...)
        Register event handlers
    
    resume(...)
        Resume process
    
    set_gdb(...)
        Run gdb on the pid
    
    set_timer(...)
        set_timer(milliseconds, timer, data) -> timer_id
        Return the timer id
    
    signal_name(...)
        Return signal name
    
    syscall_name(...)
        Return syscall name
    
    write(...)
        write(stream, string)
        Write string to shook output.


