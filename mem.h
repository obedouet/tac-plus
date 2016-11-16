/*
 * Memory management func
 *
 * Simples func to handle correctly memory alloc
 * Created by Olivier BEDOUET 2009/12/7
 */

extern int n_malloc_call;
extern int n_free_call;
extern int n_bytes_alloc;

extern void *s_malloc(size_t size);
extern void s_free(void *ptr);
extern void s_sum(void);

