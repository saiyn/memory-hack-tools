# memory-hack-tools

<br />

various memory hack tools to help debug memory related issues

---

<br />

## 1.Heap Memory Overwrite Issue

<br />

this is a debug helper tools which used with gdb to deal with heap memory overwrite issue

### THEORY

<br />

please check [this article](http://saiyn.github.io/homepage/2017/09/01/debug-DIY/#堆内存越界死机检测工具)

### HOW TO USE


---

<br />

## 2.Heap Memory Leak Detect

<br />

a tool to stat the malloc/free useage through the system, and help to chech whether a memleak happens and then help
to locat the backtrace where cause the issue.

### THEORY

<br />

Heap memory used by malloc should be freed at sometime propbely, if not then a memory leak happens. So we statatic the use count of malloc and free, if the malloc of a backtrace always beyond the number of free, then we asume the backtace 
cause the memory leak issue.

More details behind the tool please check [this article](http://saiyn.github.io/homepage/2017/09/01/debug-DIY/#内存泄露检测工具)

<br />

### HOW TO USE

<br />

1.Make 

2.Link with th libmemLeak.so at the very first place of your project, which will wrap all the malloc,realloc,calloc,free c library functions.

3.Start your program as mormal.

4.Shell `cat /var/malloc_stat` to check the heap memroy stat in terms of thread. Below is a screenshot.

![mreadm_0](http://omp8s6jms.bkt.clouddn.com/image/git/mreadm_0.png)

> Note that, at this point, the tool have not record the backtrace of any malloc all, so the result above is somehow not very accurate.

5.Find which thread , e.g. thread_id has the biggest suspect and then shell `echo thread_id > /var/bt_proc` to stat the
heap memory in terms of backtrace. Below is another screenshot.

![mreadm_1](http://omp8s6jms.bkt.clouddn.com/image/git/mreadm_1.png)

 Compare about the two result above, we can find that the misinformation is much less.


> Note that, when we echo a thread id to /var/bt_proc, we are entring a "real" mode where the accracy of the tool is very impressive.

6. After we echo a thread id to /var/bt_proc, if the thread do have the memory leak issue, we will see the very detail stack of the malloc all. 

![mreadm_4](http://omp8s6jms.bkt.clouddn.com/image/git/mreadm_4.png)

7. Last but not the least, the tool have a mode called 'print all' that we can see all what we have recorded. Since sometimes when we may get what is not what we expect, we need check if we have done the correct records. So when we shell `echo -2 > /var/bt_proc`, we entry the 'print all' mode. 

 And what't more, there are two different result of the 'print all' mode, one is before we echo a thread id to /var/bt_proc and the   other is after which also can be called 'real print all' mode.

![mreadm_2](http://omp8s6jms.bkt.clouddn.com/image/git/mreadm_2.png)

> From the screenshot above we can see that if we are not in 'print all' mode, the thread where malloc count is equal free won't be shown.

![mreadm_3](http://omp8s6jms.bkt.clouddn.com/image/git/mreadm_3.png)

> From the screenshot above we can see that if we are not in 'real print all' mode, the backtrace of the thread where malloc count is equal the free won't be shown.



----

