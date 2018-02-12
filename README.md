# memory-hack-tools

<br />

various memory hack tools to help debug memory related issues

---

<br />

##  heap memory overwrite issue

<br />

this is a debug helper tools which used with gdb to deal with heap memory overwrite issue

### THEORY

<br />

please check [this article](http://saiyn.github.io/homepage/2017/09/01/debug-DIY/#堆内存越界死机检测工具)

### HOW TO USE


---

<br />

## heap memory leak detect

<br />

a tool to stat the malloc/free useage through the system, and help to chech whether a memleak happens and then help
to locat the backtrace where cause the issue.

### THEORY

<br />

heap memory used by malloc should be freed at sometime propbely, if not then a memory leak happens. So we statatic the use count of malloc and free, if the malloc of a backtrace always beyond the number of free, then we asume the backtace 
cause the memory leak issue.

<br />

### HOW TO USE

<br />

1. make 
2. link with th libmemLeak.so at the very first place of your project, which will wrap all the malloc/realloc/calloc/free c library functions.
3.start your program as mormal.
4.shell `cat /var/malloc_stat` to check the heap memroy stat in terms of thread.
5.find which thread , e.g. thread_id has the biggest suspect and then shell `echo thread_id > /var/proc_bt` to stat the
heap memory in terms of backtrace.


----

