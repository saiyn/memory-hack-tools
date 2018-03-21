/**
 * 这里的define很重要，不然编译时会提示RTLD_NEXT符号未定义
 *
 * 详细说明可以参加《Unix高级环境编程》。
 */ 
#define _GNU_SOURCE


#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <dlfcn.h>
#include <assert.h>
#include <execinfo.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <time.h>

#include "uthash.h"

#define MAX_NB_NODES  (1000000)

#define STACK_TRACE_DEPTH (8)


#define ALIGN(size, n)  (((size) + (n) - 1) & ~((n) - 1))

#define PAGE_ALIGN(size)  ALIGN(size, sysconf(_SC_PAGE_SIZE))


typedef void* (*malloc_func)(size_t);
typedef void* (*realloc_func)(void *, size_t);
typedef void  (*free_func)(void *);
typedef void* (*memalign_func)(size_t , size_t);


#define true (1)
#define false (0)

malloc_func real_malloc = NULL;
realloc_func real_realloc = NULL;
free_func   real_free = NULL;
memalign_func real_memalign = NULL;


#define wrap_malloc malloc
#define wrap_calloc calloc
#define wrap_realloc realloc
#define wrap_free    free
#define wrap_memalign memalign

static int page_size;


static pthread_key_t isNeedCallRealMalloc = 0;

static  pthread_rwlock_t hash_str_lock;

static pthread_mutex_t hash_ptr_lock;

static int print_all = 0;



/**
 * dlsym函数里面会调用calloc，这样第一次
 *
 * 内存分配就不可用，所以使用下面的补救措施
 */ 
static char firstBuffer[1024];


typedef struct{
	unsigned long cnt;
	unsigned long free;
	int tid;
	char trace[STACK_TRACE_DEPTH*20];
	UT_hash_handle hh;
}stat_bt_t; 

typedef struct{
	void *key;
	int tid;
	char trace[STACK_TRACE_DEPTH*20];
	UT_hash_handle hh;
}stat_ptr_t;


static stat_bt_t *users = NULL;

static stat_ptr_t *conver = NULL;


typedef struct{
	int tid;
	unsigned long cnt;
	unsigned long free;
	unsigned long long increase;
	unsigned long long decrease;
	unsigned long long start_time;
	int next;
}stat_node_t;

static stat_node_t *hash_table;

static int first_node, last_node;

static int tid_to_record_bt;


static void *virtual_alloc(size_t size)
{
	void *ptr;
	size_t align_size = PAGE_ALIGN(size);
	

	ptr = mmap(NULL, align_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);		

	return ptr;
}


static unsigned long long get_current_time_inMs(void)
{
	struct timespec tv;
	unsigned long long time;


	clock_gettime(CLOCK_MONOTONIC, &tv);	 
	
	time = tv.tv_sec * 1000 + (tv.tv_nsec / 1000000);

	return time;
}


static void print_malloc_stat(char *buf)
{
	stat_node_t *node;		
	int offset = 0;
	unsigned long long elasp_time;
	int i =0, j = 0;


	offset += sprintf(buf, "Tid     |malloc    |total(Kb) |free      |total(Kb) |LeakFps   |ElaspTime |\n");
	buf += offset;
	
	offset += sprintf(buf, "---------------------------------------------------------------------------\n");
	buf += offset;

	for(node = &hash_table[first_node]; node->tid > 0; node = &hash_table[node->next])
	{

		//if(node->cnt < 100)
		//	continue;

		elasp_time = get_current_time_inMs() - node->start_time;
		
		if(node->cnt > node->free || print_all)
		{

			offset += sprintf(buf, "%-8d %-10ld %-10lld %-10ld %-10lld %-10.3f %-10ld\n", node->tid, node->cnt, node->increase >> 10,node->free, 
					node->decrease >> 10,(float)((node->cnt - node->free)* 1000.0 / elasp_time), elasp_time);

			buf += offset;

			node->start_time = get_current_time_inMs();

			node->cnt = 0;
			node->free = 0;

			j++;

		}
		if(tid_to_record_bt == node->tid)
		{
			stat_bt_t *s;
				
			offset += sprintf(buf,"************stat detail of Thread %d******************\n", node->tid);
			buf += offset;
			
			offset += sprintf(buf, "malloc    |free      |LeakFps   |stack\n");
			buf += offset;

			offset += sprintf(buf,"-------------------------------------------\n");
			buf += offset;			


			for(s=users; s != NULL; s = s->hh.next)
			{
				if((s->cnt != s->free) && (s->tid == tid_to_record_bt))
				{
					offset += sprintf(buf, "%-10ld %-10ld %-10.3f %-s\n", s->cnt,
						s->free,(float)((s->cnt - s->free)* 1000.0 / elasp_time) ,s->trace);				
					//s->cnt = 0;
					//s->free = 0;
				
					buf += offset;

					i++;
				}
				
				
			}
		
			offset += sprintf(buf,"********detail total : %d**************************************\n", i);
			buf += offset;
		}
		
		if(node->next < 0)
		{
			break;	
		}
	
	}			

	sprintf(buf, "***************total : %d****************************\n", j);
}


static void *malloc_stat_moniter(void *arg)
{
	int fd = -1;
	int fd2 = -1;
        int tid = -1;
	char tid_buf[16] = {0};
	void *stat_buf;

	printf("here comes the malloc stat moniter thread\n");

	fd2 = open("/var/bt_proc", O_CREAT | O_TRUNC | O_RDWR, 0644);
	


	for(;;)
	{

		if(read(fd2, tid_buf, 16) > 0)
		{
			tid = atoi(tid_buf);

			if(tid == -2)
			{
				print_all = 1;

				printf("saiyn: in print all mode\n");
			}
			else
			{

				if(tid != tid_to_record_bt)
				{
					tid_to_record_bt = tid;

					printf("tid to record bt changed to %d\n", tid);
				}
				
				if(tid == 0){
					print_all = 0;
				}
			}
		}

		
		lseek(fd2, 0, SEEK_SET);

		fd = open("/var/malloc_stat", O_CREAT | O_TRUNC | O_RDWR, 0644);
		assert(fd >= 0);

		ftruncate(fd, 1024*1024*8);

		stat_buf = mmap(NULL, 1024*1024*8, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		
		
		print_malloc_stat(stat_buf);

				
		sleep(9);
	}

}


void wrap_init(void)
{
	static int once = 1;
	int ret;
	pthread_t tid;

	if(!once)
	{
		return;
	}	

	
	once = 0;

	page_size = sysconf(_SC_PAGE_SIZE);


	hash_table = (stat_node_t *)virtual_alloc(MAX_NB_NODES*sizeof(stat_node_t));
	assert(hash_table);

	printf("in wrap init, hash_table:%p\n", hash_table);

	if(pthread_rwlock_init(&hash_str_lock, NULL) != 0)
	{
		printf("saiyn: can't create rwlock\n");
		return;
	}

	if(pthread_mutex_init(&hash_ptr_lock, NULL) != 0)
	{
		printf("saiyn: can't create ptr lock\n");
		return;
	}

        ret = pthread_key_create(&isNeedCallRealMalloc, NULL);
        if(ret)
        {
                printf("pthread_key_create fail:%d\n", ret);
                return;
        }

        ret = pthread_setspecific(isNeedCallRealMalloc, (void *)true);
        if(ret)
        {
                printf("pthread_setspecific fail:%d\n", ret);
                return;
        }

		
	
	if(real_malloc == NULL)
	{
		real_malloc = (malloc_func)dlsym(RTLD_NEXT,"malloc");
	}
	assert(real_malloc);


	if(real_realloc == NULL)
	{
		real_realloc = (realloc_func)dlsym(RTLD_NEXT, "realloc");
	}
	assert(real_realloc);

	if(real_memalign == NULL)
	{
		real_memalign = (memalign_func)dlsym(RTLD_NEXT, "memalign");
	}
	assert(real_memalign);

	if(real_free == NULL)
	{
		real_free = (free_func)dlsym(RTLD_NEXT, "free");
	}
	assert(real_free);

	
	ret = pthread_create(&tid, NULL, malloc_stat_moniter, NULL);


	pthread_setspecific(isNeedCallRealMalloc, (void *)false);

	printf("saiyn:wrap mem init done\n");
	
}



static void record_retFunc_addr(void *ptr)
{
        int len;
        int i;
	void *trace[STACK_TRACE_DEPTH + 3] = {0};
	char bt_str[STACK_TRACE_DEPTH*20] = {0};

	char addr[20] = {0};
	stat_bt_t *s = NULL;
	stat_ptr_t *sp = NULL;

	
        /**
         * backtrace中会调用malloc,反止递归死循环。
         */
        pthread_setspecific(isNeedCallRealMalloc, (void *)true);

		
	len = backtrace(trace, STACK_TRACE_DEPTH + 2);

	if(len < 5){
		/**
		 * use syscall backtrace to get the stack info may fail duo to compile setting.
		 */
		goto exit;	
	}
	
	for(i = 3; i < len; i++)
	{
		sprintf(addr, "%p ", trace[i]);

		strcat(bt_str, addr);

		memset(addr, 0, 20);	
	}

	pthread_rwlock_rdlock(&hash_str_lock);
	HASH_FIND_STR(users, bt_str, s);
	pthread_rwlock_unlock(&hash_str_lock);

	if(s)
	{
		s->cnt++;
	}
	else
	{
		s = (stat_bt_t *)real_malloc(sizeof(*s));
	
		memset(s->trace, 0, STACK_TRACE_DEPTH*10);

		strcpy(s->trace, bt_str);
	
		s->cnt = 1;
		
		s->free = 0;
		
		s->tid = tid;

		pthread_rwlock_wrlock(&hash_str_lock);
		HASH_ADD_STR(users, trace, s);
		pthread_rwlock_unlock(&hash_str_lock);
	
	}


	pthread_mutex_lock(&hash_ptr_lock);
	HASH_FIND_PTR(conver, &ptr, sp);
	pthread_mutex_unlock(&hash_ptr_lock);

	if(!sp)
	{

		/**
 	 	 * 哈希申请的地址，因为free只能拿到地址信息。
 		 * 
 		 */
		sp = (stat_ptr_t *)real_malloc(sizeof(*sp));

		memset(sp->trace, 0, sizeof(sp->trace));

		strcpy(sp->trace, bt_str);
	
		sp->key = ptr;
	
		sp->tid = tid;
		
		pthread_mutex_lock(&hash_ptr_lock);
		HASH_ADD_PTR(conver, key, sp);
		pthread_mutex_unlock(&hash_ptr_lock);
		
	}

        pthread_setspecific(isNeedCallRealMalloc, (void *)false);

	
}


static int update_retFunc_addr(void *ptr) 
{
	stat_bt_t *s = NULL;
	stat_ptr_t *sp = NULL;
	int tid = 0;

	pthread_mutex_lock(&hash_ptr_lock);
	HASH_FIND_PTR(conver, &ptr, sp);
	pthread_mutex_unlock(&hash_ptr_lock);
	
	if(sp)
	{
		tid = sp->tid;
		pthread_rwlock_rdlock(&hash_str_lock);
		HASH_FIND_STR(users, sp->trace, s);
		pthread_rwlock_unlock(&hash_str_lock);

		if(s)
		{
			s->free++;
			
			pthread_setspecific(isNeedCallRealMalloc, (void *)true);
			
			pthread_mutex_lock(&hash_ptr_lock);
			HASH_DEL(conver, sp);
			pthread_mutex_unlock(&hash_ptr_lock);
			
			pthread_setspecific(isNeedCallRealMalloc, (void *)false);
			
			real_free(sp);
		}


	}						

	return tid;
}



static void malloc_record(void *ptr, size_t size)
{
	int tid = (int)syscall(SYS_gettid);
	stat_node_t *node = &hash_table[tid];

	if(node->tid == tid)
	{
		node->cnt++;
		node->increase += size;
	}
	else
	{
		node->tid = tid;
		node->cnt = 1;
		node->increase = size;
		node->decrease = 0;
		node->free = 0;
		node->next = -1;
		node->start_time = get_current_time_inMs();
		
		if(!first_node)
		{
			first_node = last_node = tid;	
		}
		else
		{
			node->next = first_node;
			first_node = tid;
		}

	} 


	if(tid_to_record_bt != 0)
	{
		record_retFunc_addr(ptr);					
	}
}


static  unsigned int get_trunk_size(void *addr)
{
	size_t chunk_size = (*(size_t *)(addr - sizeof(size_t))) & (~(2*sizeof(size_t) - 1));

	int isMemMap = (*(size_t *)(addr - sizeof(size_t))) & (1 << 1);


	return isMemMap ? chunk_size - sizeof(void *)*2 : chunk_size - sizeof(void *);
} 

static void free_record(void *ptr)
{
	int tid = (int)syscall(SYS_gettid);

	stat_node_t *node;
	
	int tid2 = update_retFunc_addr(ptr);
	
	node = tid2 == 0 ? &hash_table[tid] : &hash_table[tid2];

	if(node->tid == (tid2 == 0 ? tid : tid2))
	{
		node->free++;
		node->decrease += get_trunk_size(ptr); 
		
	}		
}



/**
 * malloc中主要是获取调用堆栈的信息，然后和MAGIC NUM
 * 
 * 一起存储在内存块的最开始部分。
 *
 * MAGIC NUM 的加入一个是方便我们到时分析内存块，快速找到各个内存块
 *
 * 同时主要是为了解决有效内存分配没有经过wrap，这时free必须要知道，
 *
 * 当前要释放的内存是否是包含头信息的。
 */ 
void *wrap_malloc(size_t size)
{
	void *ptr = NULL;

	wrap_init();

        if(pthread_getspecific(isNeedCallRealMalloc))
        {
                return real_malloc(size);
        }

	
	ptr = real_malloc(size);

	if(ptr)
	{
		malloc_record(ptr, size);
	}

	return ptr;
}

/**
 * wrap_calloc调用wrap_malloc实现 ,这里第一次返回firstBuffer
 *
 * 是因为我们dlsym函数内部会调用calloc，而此时我们还没有拿到glibc库
 *
 * malloc的地址呢，就出现了先有鸡还是先有蛋的问题。	
 */
void *wrap_calloc(size_t nmemb, size_t size)
{
	void *ret = NULL;
	static int isfirst = true;

	if(isfirst)
	{
		isfirst = false;

		return firstBuffer;
	}

	if(nmemb == 0 || size == 0)
	{
		return wrap_malloc(0);
	}		

	ret = wrap_malloc(nmemb*size);
	
	if(ret) memset(ret, 0, nmemb*size);

	return ret;
}



void *wrap_realloc(void *ptr, size_t size)
{
	void *ret = NULL;

	wrap_init();

        if(pthread_getspecific(isNeedCallRealMalloc))
        {
                return real_realloc(ptr ,size);
        }

	
	ret = real_realloc(ptr, size);


	/**
  	 * 只有当ptr为空时，realloc才申请新内存，否则只是调整内存大小。
  	 * 暂时排除调整内存大小情况的统计。
  	 */
	if(!ptr && ret)
	{
		malloc_record(ret, size);
	}
		

	return ret;	
}


void *wrap_memalign(size_t boundary, size_t size)
{
	void *ptr = NULL;

	wrap_init();		

	if(pthread_getspecific(isNeedCallRealMalloc))
	{
		return real_memalign(boundary, size);
	}

	ptr = real_memalign(boundary, size);

	if(ptr)
	{
		malloc_record(ptr, size);
	}


	return ptr;
}


void *wrap_valloc(size_t size)
{
	return wrap_memalign(page_size, size);
}


void wrap_free(void *ptr)
{

	if(ptr == firstBuffer)
        {
                return;
        }

        wrap_init();


	if(!ptr || !real_free)
	{
		return;	
	}
	
	
	if(pthread_getspecific(isNeedCallRealMalloc)) 
	{
		return real_free(ptr);
	}

	free_record(ptr);
	

	return real_free(ptr);
}












