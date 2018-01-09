/**
 * 这里的define很重要，不然编译时会提示RTLD_NEXT符号未定义
 *
 * 详细说明可以参加《Unix高级环境编程》。
 */ 
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <dlfcn.h>
#include <assert.h>
#include <execinfo.h>
#include <pthread.h>



#define STACK_TRACE_DEPTH (8)

#define MAGIC_NUM (0x12345678UL)


#define USE_SHARED

#ifdef USE_SHARED

typedef void* (*malloc_func)(size_t);
typedef void  (*free_func)(void *);


#define true (1)
#define false (0)

malloc_func real_malloc = NULL;
free_func   real_free = NULL;

#define wrap_malloc malloc
#define wrap_free   free
#define wrap_calloc calloc
#define wrap_realloc realloc
#define wrap_memalign memalign
#define wrap_valloc valloc


#else

void *__real_malloc(size_t);
void __real_free(void *);

#define real_malloc __real_malloc
#define real_free   __real_free

#define wrap_malloc  __wrap_malloc
#define wrap_free    __wrap_free
#define wrap_calloc  __wrap_calloc
#define wrap_realloc __wrap_realloc
#define wrap_memalign __wrap_memalign
#define wrap_valloc  __wrap_valloc




/**
 * 下面的符号在连接器和glibc中定义的，代码里可以直接引用
 */
extern char __executable_start[];
extern char __etext[];
extern void *__libc_stack_end;


#endif

pthread_key_t isNeedCallRealMalloc = 0;

/**
 * dlsym函数里面会调用calloc，这样第一次
 *
 * 内存分配就不可用，所以使用下面的补救措施
 */ 
static char firstBuffer[1024];

void wrap_free(void *ptr);


void wrap_init(void)
{
	static int once = 1;
	int ret;

	if(!once)
	{
		return;
	}	

	
	once = 0;

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


#ifdef USE_SHARED
	
	if(real_malloc == NULL)
	{
		real_malloc = (malloc_func)dlsym(RTLD_NEXT,"malloc");
	}
	assert(real_malloc);
	
	if(real_free == NULL)
	{
		real_free   = (free_func)dlsym(RTLD_NEXT, "free");
	}
	assert(real_free);
	
#endif

	pthread_setspecific(isNeedCallRealMalloc, (void *)false);

	printf("saiyn:wrap mem init done\n");
	
}

#ifdef USE_SHARED

static void fill_retFunc_addr(size_t *sp, char *ptr, size_t depth)
{
	void *trace[STACK_TRACE_DEPTH] = {0};	
	int len;
	int i;

	(void)sp;
	(void)depth;


	/**
 	 * backtrace中会调用malloc,反止递归死循环。
 	 */ 
	pthread_setspecific(isNeedCallRealMalloc, (void *)true);
	
	len = backtrace(trace, STACK_TRACE_DEPTH - 1);

	pthread_setspecific(isNeedCallRealMalloc, (void *)false);

	for(i = 0; i < len; i++)
	{
		
		*((size_t *)ptr + i) = trace[i];
	}

	/**
         * 添加MAGIC NUM,用于判断是否是我们的malloc分配的内存，
         *
         * 这样free时可以检测。
         */ 
	*((size_t *)ptr + STACK_TRACE_DEPTH - 1) = MAGIC_NUM; 

}


#else

static void fill_retFunc_addr(size_t *sp, char *ptr, size_t depth)
{
	size_t *stack_end = sp + 4096;
	int i;
	
	//printf("searching start:%p exec_start:%p exec_end:%p\n", sp, __executable_start, __etext);

	for(i = 0; i < depth && sp < stack_end; ++sp)
	{
		if(*sp > __executable_start && *sp < __etext)
		{
			//printf("find retFunc addr %p\n", *sp);
			
			*((size_t *)ptr + i) = *sp;
			
			i++;
		}
	}

}

#endif

static inline unsigned char *get_real_addr(void *addr)
{

	if(*((size_t *)addr - 1) != MAGIC_NUM)
	{
		return addr;
	}
	
	
	return(unsigned char *)addr - sizeof(size_t *)*STACK_TRACE_DEPTH;
}

static inline size_t get_real_size(unsigned char *addr)
{
	size_t chunk_size = (*(size_t *)(addr - sizeof(size_t))) & (~(2*sizeof(size_t) - 1));
	int isMemMap = (*(size_t *)(addr - sizeof(size_t))) & (1 << 1);

	/**
         * 当ptmalloc用mmap方式分配内存时，chunk中没有对应的下一块，所以当前块
         *
         * 不会借用下一块的前sizeof(sizt_t)字节。
         *
         * 这里有点难以理解，需要好好思考消化。
         */
	return isMemMap ? chunk_size - sizeof(void *)*2 : chunk_size - sizeof(void *);
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
	size_t total = size + sizeof(size_t *)*STACK_TRACE_DEPTH;
	char *ptr = NULL;	

	wrap_init();
	//printf("saiyn:use our wrap malloc\n");


	if(pthread_getspecific(isNeedCallRealMalloc))
	{
		return real_malloc(size);
	}

	ptr = real_malloc(total);
	assert(ptr);	

	fill_retFunc_addr(&total, ptr, STACK_TRACE_DEPTH);
	
	return ptr + sizeof(size_t *)*STACK_TRACE_DEPTH;
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

/**
 * wrap_realloc调用wrap_malloc和wrap_free实现
 */
void *wrap_realloc(void *ptr, size_t size)
{
	int real_size;
	unsigned char *real_addr;
	void *ret = NULL;

	if(ptr == 0)
	{
		return wrap_malloc(size);
	}			
	else if(size == 0)
	{
		wrap_free(ptr);
		return NULL;
	}

	real_addr = get_real_addr(ptr);

	/**
         * 判断该内存是否是我们wrap的内存。
         */ 
	if(real_addr == ptr)
	{
		real_size = get_real_size(real_addr);
	}
	else
	{
		real_size = get_real_size(real_addr) - sizeof(size_t *)*STACK_TRACE_DEPTH;	
	}	

	/**
 	 * 如果再次申请的字节小于之前申请的就直接返回ptr,
 	 * 
 	 * 实际的realloc函数实现是要
 	 *
 	 * 释放掉多余的内存的。但是为了简单起见，暂时这样处理。
 	 */ 
	if(real_size >= size)
	{
		return ptr;
	}

	ret = wrap_malloc(size);
	if(ret)
	{
		memcpy(ret, ptr, real_size);
	}
	
	wrap_free(ptr);
	
	return ret;	
}

/**
 * 判断firstBuffer的原因参见上面的calloc说明
 *
 */ 
void wrap_free(void *ptr)
{
	unsigned char *real_addr;

	if(ptr == firstBuffer)
	{
		return;
	}

	wrap_init();
	//printf("saiyn:use our wrap free\n");

	if(!ptr)
		return;

	real_addr = get_real_addr(ptr); 

	real_free(real_addr);
	return;
}


