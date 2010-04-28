/*
 * csp_buffer.c
 *
 *  Created on: 29/01/2010
 *      Author: johan
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <csp/csp.h>

#define CSP_BUFFER_STATIC 0
#define CSP_BUFFER_SIZE 320
#define CSP_BUFFER_COUNT 12
#define CSP_BUFFER_FREE	0
#define CSP_BUFFER_USED	1

#if CSP_BUFFER_STATIC
	typedef struct { uint8_t data[CSP_BUFFER_SIZE]; } csp_buffer_element_t;
	static csp_buffer_element_t csp_buffer[CSP_BUFFER_COUNT];
	static uint8_t csp_buffer_list[CSP_BUFFER_COUNT];
	static void * csp_buffer_p = &csp_buffer;
	static const int size = CSP_BUFFER_SIZE;
	static const int count = CSP_BUFFER_COUNT;
#else
	void * csp_buffer_p;
	uint8_t * csp_buffer_list;
	int size, count;
#endif

static uint8_t csp_buffer_last_given = 0;

int csp_buffer_init(int buf_count, int buf_size) {

#if CSP_BUFFER_STATIC
	return 1;
#else

	/* Remember size */
	count = buf_count;
	size = buf_size;

	/* Allocate main memory */
	csp_buffer_p = pvPortMalloc(count * size);
	if (csp_buffer_p == NULL)
		return 0;

	/* Allocate housekeeping memory */
	csp_buffer_list = (uint8_t *) pvPortMalloc(count * sizeof(uint8_t));
	if (csp_buffer_list == NULL) {
		vPortFree(csp_buffer_p);
		return 0;
	}

	/* Clear housekeeping memory = all free mem */
	memset(csp_buffer_list, 0, count);

	return 1;
#endif
}

/**
 * Searched a statically assigned array for a free entry
 * Starts with the last given element + 1 for optimisation
 * This call is safe from both ISR and task context
 * @return poiter to a free csp_packet_t or NULL if out of memory
 */
void * csp_buffer_get(size_t buf_size) {

	if (buf_size > size) {
		printf("Attempt to allocate too large block\r\n");
		return NULL;
	}

	int i = csp_buffer_last_given;							// Start with the last given element
	i = (i + 1) % count;									// Increment by one
	while(i != csp_buffer_last_given) {						// Loop till we have checked all
		if (csp_buffer_list[i] == CSP_BUFFER_FREE) {		// Check the buffer list
			csp_buffer_list[i] = CSP_BUFFER_USED;			// Mark as used
			csp_buffer_last_given = i;						// Remember the progress
			return csp_buffer_p + (i * size);				// Return poniter
		}
		i = (i + 1) % count;								// Increment by one
	}
	return NULL;											// If we are out of memory, return NULL
}

/**
 * Instantly free's the packet buffer
 * This call is safe from both ISR and Task context
 * @param packet
 */
void csp_buffer_free(void * packet) {
	int i = (packet - csp_buffer_p) / size;					// Find number in array by math (wooo)
	if (i < 0 || i > count)
		return;
	csp_buffer_list[i] = CSP_BUFFER_FREE;					// Mark this as free now
}

/**
 * Counts the amount of remaning buffers
 * @return Integer amount
 */
int csp_buffer_remaining(void) {
	int buf_count = 0, i;
	for(i = 0; i < count; i++) {
		if (csp_buffer_list[i] == CSP_BUFFER_FREE)
			buf_count++;
	}
	return buf_count;
}