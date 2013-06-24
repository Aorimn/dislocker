/* -*- coding: utf-8 -*- */
/* -*- mode: c -*- */
/*
 * Dislocker -- enables to read/write on BitLocker encrypted partitions under
 * Linux
 * Copyright (C) 2012-2013  Romain Coltel, Hervé Schauer Consultants
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */


/*
 * Special thanks to Nitin Kumar and Vipin Kumar for helping me building this
 * file
 */


#include "common.h"
#include "encommon.h"
#include "dislocker.h"
#include "encryption/decrypt.h"
#include "sectors.h"
#include "metadata/metadata.h"
#include "fuse.h"




static int fs_getattr(const char *path, struct stat *stbuf)
{
	int res = 0;
	
	if(!path || !stbuf)
		return -EINVAL;
	
	memset(stbuf, 0, sizeof(struct stat));
	if(strcmp(path, "/") == 0)
	{
		stbuf->st_mode = S_IFDIR | 0555;
		stbuf->st_nlink = 2;
	}
	else if(strcmp(path, NTFS_FILENAME) == 0)
	{
		/** @see encommon.h for disk_op_data */
		mode_t m = disk_op_data.cfg->is_ro ? 0444 : 0666;
		stbuf->st_mode = S_IFREG | m;
		stbuf->st_nlink = 1;
		stbuf->st_size = (off_t)disk_op_data.volume_size;
	}
	else
		res = -ENOENT;
	
	return res;
}

static int fs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                      off_t offset, struct fuse_file_info *fi)
{
	/* Both variables aren't used here */
	(void) offset;
	(void) fi;
	
	if(!path || !buf || !filler)
		return -EINVAL;
	
	if(strcmp(path, "/") != 0)
		return -ENOENT;
	
	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);
	filler(buf, NTFS_FILENAME + 1, NULL, 0);

	return 0;
}

static int fs_open(const char *path, struct fuse_file_info *fi)
{
	if(!path || !fi)
		return -EINVAL;
	
	if(strcmp(path, NTFS_FILENAME) != 0)
		return -ENOENT;
	
	
	if(disk_op_data.cfg->is_ro & READ_ONLY)
	{
		if((fi->flags & 3) != O_RDONLY)
			return -EACCES;
	}
	else
	{
		/* Authorize read/write, readonly and writeonly operations */
		if((fi->flags & 3) != O_RDWR   &&
		   (fi->flags & 3) != O_RDONLY &&
		   (fi->flags & 3) != O_WRONLY)
			return -EACCES;
	}
	
	return 0;
}

static int fs_read(const char *path, char *buf, size_t size,
                   off_t offset, UNUSED struct fuse_file_info *fi)
{
	if(!path || !buf)
		return -EINVAL;
	
	uint8_t* buffer = NULL;
	
	size_t sector_count;
	off_t  sector_start;
	size_t sector_to_add = 0;
	
	
	/*
	 * Perform basic checks
	 */
	if(strcmp(path, NTFS_FILENAME) != 0)
	{
		xprintf(L_DEBUG, "Unknown entry requested: \"%s\"\n", path);
		return -ENOENT;
	}
	
	if(size == 0)
	{
		xprintf(L_DEBUG, "Received a request with a null size\n");
		return 0;
	}
	
	if(offset < 0)
	{
		xprintf(L_ERROR, "Offset under 0: %#" F_OFF_T "\n", offset);
		return -EFAULT;
	}
	
	/** @see encommon.h for disk_op_data */
	if(offset >= (off_t)disk_op_data.volume_size)
	{
		xprintf(L_ERROR, "Offset (%#" F_OFF_T ") exceeds volume's size (%#"
		                 F_OFF_T ")\n",
		        offset, (off_t)disk_op_data.volume_size);
		return -EFAULT;
	}
	
	
	/* 
	 * The offset may not be at a sector limit, so we need to decrypt the entire
	 * sector where it starts. Idem for the end.
	 * 
	 * 
	 * Example:
	 * Sector number:              1   2   3   4   5   6   7...
	 * Data, continuous sectors: |___|___|___|___|___|___|__...
	 * The data the user want:         |__________|
	 * 
	 * The user don't want all of the data from sectors 2 and 5, but as the data
	 * are encrypted sector by sector, we have to decrypt them even though we
	 * won't give him the beginning of the sector 2 and the end of the sector 5.
	 * 
	 * 
	 * 
	 * Logic to do this is below :
	 *  - count the number of full sectors
	 *  - decode all sectors
	 *  - select and copy the data to user and deallocate all buffers
	 */
	
	/* Do not add sectors if we're at the edge of one already */
	if((offset % disk_op_data.sector_size) != 0)
		sector_to_add += 1;
	if(((offset + (off_t)size) % disk_op_data.sector_size) != 0)
		sector_to_add += 1;
	
	sector_count = ( size / disk_op_data.sector_size ) + sector_to_add;
	sector_start = offset / disk_op_data.sector_size;
	
	xprintf(L_DEBUG,
	        "--------------------{ Fuse reading }-----------------------\n");
	xprintf(L_DEBUG, "  Offset and size needed: %#" F_OFF_T
	                 " and %#" F_SIZE_T "\n", offset, size);
	xprintf(L_DEBUG, "  Start sector number: %#" F_OFF_T
	                 " || Number of sectors: %#" F_SIZE_T "\n",
	                 sector_start, sector_count);
	
	
	/*
	 * NOTE: DO NOT use xmalloc() here, we don't want to mess everything up!
	 * In general, do not use xfunctions() but xprintf() here.
	 */
	
	size_t to_allocate = size + sector_to_add*(size_t)disk_op_data.sector_size;
	xprintf(L_DEBUG, "  Trying to allocate %#" F_SIZE_T " bytes\n",to_allocate);
	buffer = malloc(to_allocate);
	
	/* If buffer could not be allocated, return an error */
	if(!buffer)
	{
		xprintf(L_ERROR, "Cannot allocate buffer for reading, abort.\n");
		xprintf(L_DEBUG,
		       "-----------------------------------------------------------\n");
		if(errno < 0)
			return errno;
		else
			return -ENOMEM;
	}
	
	
	if(!disk_op_data.decrypt_region(
		disk_op_data.volume_fd,
		sector_count,
		disk_op_data.sector_size,
		sector_start * disk_op_data.sector_size,
		buffer
	))
	{
		free(buffer);
		xprintf(L_ERROR, "Cannot decrypt sectors, abort.\n");
		xprintf(L_DEBUG,
		       "-----------------------------------------------------------\n");
		return -EIO;
	}
	
	/* Now copy the required amount of data to the user buffer */
	memcpy(buf, buffer + (offset % disk_op_data.sector_size), size);
	
	free(buffer);
	
	xprintf(L_DEBUG, "  Outsize which will be returned: %d\n", (int)size);
	xprintf(L_DEBUG,
	        "-----------------------------------------------------------\n");
	
	return (int)size;
}

static int fs_write(const char *path, const char *buf, size_t size,
                    off_t offset, struct fuse_file_info *fi)
{
	// Check parameters
	if(!path || !buf)
		return -EINVAL;
	
	uint8_t* buffer = NULL;
	int      ret    = 0;
	
	size_t sector_count;
	off_t  sector_start;
	size_t sector_to_add = 0;
	
	
	/* Perform basic checks */
	if(disk_op_data.cfg->is_ro & READ_ONLY)
	{
		xprintf(L_DEBUG, "Only decrypting (-r or --read-only option passed)\n");
		return -EACCES;
	}
	
	if(strcmp(path, NTFS_FILENAME) != 0)
	{
		xprintf(L_DEBUG, "Unknown entry requested: \"%s\"\n", path);
		return -ENOENT;
	}
	
	if(size == 0)
	{
		xprintf(L_DEBUG, "Received a request with a null size\n");
		return 0;
	}
	
	if(offset < 0)
	{
		xprintf(L_ERROR, "Offset under 0: %#" F_OFF_T "\n", offset);
		return -EFAULT;
	}
	
	/** @see encommon.h for disk_op_data */
	if(offset >= (off_t)disk_op_data.volume_size)
	{
		xprintf(L_ERROR, "Offset (%#" F_OFF_T ") exceeds volume's size (%#"
		                 F_OFF_T ")\n",
		        offset, (off_t)disk_op_data.volume_size);
		return -EFAULT;
	}
	
	if((size_t)offset + size >= (size_t)disk_op_data.volume_size)
	{
		size_t nsize = (size_t)disk_op_data.volume_size
		               - (size_t)offset;
		xprintf(L_WARNING, "Size modified as exceeding volume's end (offset=%#"
		                   F_SIZE_T " + size=%#" F_SIZE_T " >= volume_size=%#"
		                   F_SIZE_T ") ; new size: %#" F_SIZE_T "\n",
		        (size_t)offset, size, (size_t)disk_op_data.volume_size, nsize);
		size = nsize;
	}
	
	
	/*
	 * Don't authorize to write on metadata
	 */
	off_t metadata_offset = 0;
	off_t metadata_size   = disk_op_data.metafiles_size;
	int   loop            = 0;
	
	for(loop = 0; loop < 3; loop++)
	{
		metadata_offset = (off_t)disk_op_data.metadata->offset_bl_header[loop];
		
		if(offset >= metadata_offset &&
		   offset <= metadata_offset + metadata_size)
		{
			xprintf(L_INFO, "Denying write request on the metadata (1:%#"
			        F_OFF_T ")\n", offset);
			return -EFAULT;
		}
		if(offset < metadata_offset &&
		   offset + (off_t)size >= metadata_offset)
		{
			xprintf(L_INFO, "Denying write request on the metadata (2:%#"
			        F_OFF_T "+ %#" F_SIZE_T ")\n", offset, size);
			return -EFAULT;
		}
	}
	
	/*
	 * Don't authorize writing directly on the NTFS firsts sectors backup area
	 * on BitLocker's 7 disks
	 */
	if(disk_op_data.metadata->version == V_SEVEN)
	{
		metadata_offset = (off_t)disk_op_data.metadata->boot_sectors_backup;
		metadata_size   = disk_op_data.virtualized_size;
		
		if(offset >= metadata_offset &&
		   offset <= metadata_offset + metadata_size)
		{
			xprintf(L_INFO,
			        "Denying write request on the virtualized area (1:%#"
			        F_OFF_T ")\n", offset);
			return -EFAULT;
		}
		if(offset < metadata_offset &&
		   offset + (off_t)size >= metadata_offset)
		{
			xprintf(L_INFO,
			        "Denying write request on the virtualized area (2:%#"
			        F_OFF_T")\n", offset);
			return -EFAULT;
		}
	}
	
	
	/*
	 * For BitLocker 7's volume, redirect writes to firsts sectors to the backed
	 * up ones
	 */
	if(disk_op_data.metadata->version == V_SEVEN &&
	   offset < disk_op_data.virtualized_size)
	{
		xprintf(L_DEBUG, "  Entering virtualized area\n");
		if(offset + (off_t)size <= disk_op_data.virtualized_size)
		{
			/*
			 * If all the request is within the virtualized area, just change
			 * the offset
			 */
			offset = offset + (off_t)disk_op_data.metadata->boot_sectors_backup;
			xprintf(L_DEBUG, "  `-> Just redirecting to %#"F_OFF_T"\n", offset);
		}
		else
		{
			/*
			 * But if the buffer is within the virtualized area and overflow it,
			 * split the request in two:
			 * - One for the virtualized area completely (which will be handled
			 *   by "recursing" and entering the case above)
			 * - One for the rest by changing the offset to the end of the
			 *   virtualized area and the size to the rest to be dec/encrypted
			 */
			xprintf(L_DEBUG, "  `-> Splitting the request in two, recursing\n");
			
			size_t nsize = (size_t)(disk_op_data.virtualized_size - offset);
			ret = fs_write(path, buf, nsize, offset, fi);
			if(ret < 0)
				return ret;
			
			offset = disk_op_data.virtualized_size;
			size  -= nsize;
			buf   += nsize;
		}
	}
	
	
	/* 
	 * As in the read function, the offset may not be at a sector limit, so we
	 * need to decrypt the entire sector where it starts till the entire sector
	 * where it ends, then push the changes into the sectors at correct offset
	 * and finally encrypt all of these sectors and write them back to the disk.
	 * 
	 * 
	 * Example:
	 * Sector number:                    1   2   3   4   5   6   7...
	 * Data, continuous sectors:       |___|___|___|___|___|___|__...
	 * Where the user want to write:         |__________|
	 * 
	 * The user don't want to write everywhere, just from the middle of sector 2
	 * till a part of sector 5. But we're writing sectors by sectors to be able
	 * to encrypt using AES. So we'll need entire sectors 2 to 5 included.
	 * 
	 * 
	 * 
	 * Logic to do this is below :
	 *  - read and decrypt all sectors completely (2 to 5 in the example above)
	 *  - replace some data by the user's one
	 *  - encrypt and write the read sectors
	 */
	
	/* Do not add sectors if we're at the edge of one already */
	if((offset % disk_op_data.sector_size) != 0)
		sector_to_add += 1;
	if(((offset + (off_t)size) % disk_op_data.sector_size) != 0)
		sector_to_add += 1;
	
	
	sector_count = ( size / disk_op_data.sector_size ) + sector_to_add;
	sector_start = offset / disk_op_data.sector_size;
	
	xprintf(L_DEBUG,
	        "--------------------{ Fuse writing }-----------------------\n");
	xprintf(L_DEBUG, "  Offset and size requested: %#" F_OFF_T " and %#"
	        F_SIZE_T "\n", offset, size);
	xprintf(L_DEBUG, "  Start sector number: %#" F_OFF_T
	        " || Number of sectors: %#" F_SIZE_T "\n",
	        sector_start, sector_count);
	
	
	/*
	 * NOTE: DO NOT use xmalloc() here, we don't want to mess everything up!
	 * In general, do not use xfunctions() but xprintf() here.
	 */
	
	buffer = malloc(size + sector_to_add * (size_t)disk_op_data.sector_size);
	
	/* If buffer could not be allocated */
	if(!buffer)
	{
		xprintf(L_ERROR, "Cannot allocate buffer for writing, abort.\n");
		xprintf(L_DEBUG,
		       "-----------------------------------------------------------\n");
		return -ENOMEM;
	}
	
	
	if(!disk_op_data.decrypt_region(
		disk_op_data.volume_fd,
		sector_count,
		disk_op_data.sector_size,
		sector_start * disk_op_data.sector_size,
		buffer
	))
	{
		free(buffer);
		xprintf(L_ERROR, "Cannot decrypt sectors, abort.\n");
		xprintf(L_DEBUG,
		       "-----------------------------------------------------------\n");
		return -EIO;
	}
	
	
	/* Now copy the user's buffer to the received data */
	memcpy(buffer + (offset % disk_op_data.sector_size), buf, size);
	
	
	/* Finally, encrypt the buffer and write it to the disk */
	if(!disk_op_data.encrypt_region(
		disk_op_data.volume_fd,
		sector_count,
		disk_op_data.sector_size,
		sector_start * disk_op_data.sector_size,
		buffer
	))
	{
		free(buffer);
		xprintf(L_ERROR, "Cannot encrypt sectors, abort.\n");
		xprintf(L_DEBUG,
		       "-----------------------------------------------------------\n");
		return -EIO;
	}
	
	
	free(buffer);
	
	
	/* Note that ret is zero when no recursion occurs */
	int outsize = (int)size + ret;
	
	xprintf(L_DEBUG, "  Outsize which will be returned: %d\n", outsize);
	xprintf(L_DEBUG,
	        "-----------------------------------------------------------\n");
	
	return outsize;
}

static int fs_fsync(const char *path, int isdatasync,
					UNUSED struct fuse_file_info* fi)
{
	/*
	 * In fact, this should not be necessary but you know, zeal...
	 */
	(void) path;
	(void) isdatasync;
	
	return fdatasync(disk_op_data.volume_fd);
}

static int fs_flush(const char *path, UNUSED struct fuse_file_info* fi)
{
	(void) path;
	
	return fdatasync(disk_op_data.volume_fd);
}




struct fuse_operations fs_oper = {
	.getattr = fs_getattr,
	.readdir = fs_readdir,
	.open    = fs_open,
	.read    = fs_read,
	.write   = fs_write,
	.fsync   = fs_fsync,
	.flush   = fs_flush,
};
