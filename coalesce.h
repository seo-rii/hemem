/*
 * =====================================================================================
 *
 *       Filename:  simple.h
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  02/04/2020 09:56:26 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */
#ifndef HEMEM_COALESCE_H
#define HEMEM_COALESCE_H

#include <stdint.h>
#include <stdbool.h>

#include "hemem.h"
#include "paging.h"

struct huge_page {
  uint64_t base_addr;
  uint64_t offset;
  uint32_t fd;
  uint16_t num_faulted;
};

extern long uffd;

void coalesce_init();
void incr_dram_huge_page(uint64_t addr, uint32_t fd, uint64_t offset);
void incr_nvm_huge_page(uint64_t addr, uint32_t fd, uint64_t offset);
void* check_aligned(uint64_t addr);
void decrement_huge_page(uint64_t addr);
void migrate_to_dram_hp(uint64_t addr, uint32_t fd, uint64_t offset);
void migrate_to_nvm_hp(uint64_t addr, uint32_t fd, uint64_t offset);

#endif // HEMEM_SIMPLE_H
