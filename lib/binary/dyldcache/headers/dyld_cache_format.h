/*
 * Copyright (c) 2006-2008 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */

struct shared_file_mapping_np {
    uint64_t       sfm_address;
    uint64_t       sfm_size;
    uint64_t       sfm_file_offset;
    int            sfm_max_prot;
    int            sfm_init_prot;
};

// v1 apparently has some extra gunk at the end, oh well
struct dyld_cache_header
{
	char		magic[16];				// e.g. "dyld_v0     ppc"
	uint32_t	mappingOffset;			// file offset to first shared_file_mapping_np
	uint32_t	mappingCount;			// number of shared_file_mapping_np entries
	uint32_t	imagesOffset;			// file offset to first dyld_cache_image_info
	uint32_t	imagesCount;			// number of dyld_cache_image_info entries
	uint64_t	dyldBaseAddress;		// base address of dyld when cache was built
};

struct dyld_cache_image_info
{
	uint64_t	address;
	uint64_t	modTime;
	uint64_t	inode;
	uint32_t	pathFileOffset;
	uint32_t	pad;
};


