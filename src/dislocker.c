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



#define _GNU_SOURCE


#include "encommon.h"
#include "metadata/datums.h"
#include "metadata/metadata.h"
#include "metadata/fvek.h"
#include "metadata/vmk.h"
#include "sectors.h"


#include "xstd/xstdio.h"

#include "config.h"



#include "dislocker.h"

#include <locale.h>


/*
 * On Darwin and FreeBSD, files are opened using 64 bits offsets/variables
 * and O_LARGEFILE isn't defined
 */
#if defined(__DARWIN) || defined(__FREEBSD)
#  define O_LARGEFILE 0
#endif /* __DARWIN || __FREEBSD */



/**
 * Function used to initialize keys used for decryption/encryption
 */
static int init_keys(bitlocker_dataset_t* dataset, datum_key_t* fvek,
                     contexts_t* ctx);

/**
 * Function used to prepare a structure which hold data used for
 * decryption/encryption
 */
static int prepare_crypt(bitlocker_header_t* metadata, contexts_t* ctx,
                        dis_config_t* cfg, volume_header_t* volume_header,
                        off_t offset, int fd_volume);



/**
 * Main function ran initially
 */
int main(int argc, char** argv)
{
	// Check parameters number
	if(argc < 2)
	{
		usage();
		exit(EXIT_FAILURE);
	}
	
	
	int param_idx = 0;
	
	int fd_volume = 0;
	
	volume_header_t volume_header;
	void* bl_metadata = NULL;
	
	bitlocker_dataset_t* dataset= NULL;
	
	void* vmk_datum = NULL;
	void* fvek_datum = NULL;
	
	contexts_t ctx;
	memset(&ctx, 0, sizeof(ctx));
	
	int ret = EXIT_SUCCESS;
	
	dis_config_t cfg;
	memset(&cfg, 0, sizeof(cfg));
	
	
	/* Get command line options */
	param_idx = parse_args(&cfg, argc, argv);
	
	/* Initialize outputs */
	xstdio_init(cfg.verbosity, cfg.log_file);
	
	if(cfg.verbosity >= L_INFO)
		print_args(&cfg);
	
	
	
	/*
	 * Check parameters given
	 */
	if(!cfg.volume_path)
	{
		usage();
		ret = EXIT_FAILURE;
		goto FIRST_CLEAN;
	}
	
	
	
	/* Open the volume as a (big) normal file */
	fd_volume = open(cfg.volume_path, O_RDWR|O_LARGEFILE);
	if(fd_volume < 0)
	{
		/* Trying to open it in read-only if O_RDWR doesn't work */
		fd_volume = xopen(cfg.volume_path, O_RDONLY|O_LARGEFILE);
		if(fd_volume < 0)
		{
			xprintf(L_CRITICAL,
					"Failed to open %s: %s\n",
					cfg.volume_path, strerror(errno));
			ret = EXIT_FAILURE;
			goto FIRST_CLEAN;
		}
		cfg.is_ro |= READ_ONLY;
		xprintf(L_WARNING,
				"Failed to open %s for writing. Falling back to read-only.\n",
				cfg.volume_path);
	}
	else
		xprintf(L_DEBUG, "Opened (fd #%d).\n", fd_volume);
	
	
	
	/* To print UTF-32 strings */
	setlocale(LC_ALL, "");
	
	
	
	/*
	 * Deal with the volume first
	 */
	xprintf(L_INFO, "Looking for BitLocker metadata...\n");
	
	/* Initialize structures */
	memset(&volume_header, 0, sizeof(volume_header_t));
	
	
	/* Getting volume infos */
	if(!get_volume_header(&volume_header, fd_volume, cfg.offset))
	{
		xprintf(L_CRITICAL,
		        "Error during reading the volume: not enough byte read.\n");
		ret = EXIT_FAILURE;
		goto FIRST_CLEAN;
	}
	
	/* Checking the signature */
	if(memcmp(BITLOCKER_SIGNATURE, volume_header.signature,
	          BITLOCKER_SIGNATURE_SIZE) != 0)
	{
		xprintf(L_CRITICAL,
		        "The signature of the volume (%.8s) doesn't match the "
				"BitLocker's one (-FVE-FS-). Abort.\n",
				volume_header.signature);
		ret = EXIT_FAILURE;
		goto FIRST_CLEAN;
	}
	
	/* Checking sector size */
	if(volume_header.sector_size == 0)
	{
		xprintf(L_CRITICAL, "The sector size found is null. Abort.\n");
		ret = EXIT_FAILURE;
		goto FIRST_CLEAN;
	}
	
	/* Getting BitLocker metadata and validate them */
	if(!get_metadata_check_validations(&volume_header, fd_volume, &bl_metadata,
	   &cfg))
	{
		xprintf(L_CRITICAL,
		       "A problem occured during the retrieving of metadata. Abort.\n");
		ret = EXIT_FAILURE;
		goto FIRST_CLEAN;
	}
	
	if(cfg.force_block == 0 || !bl_metadata)
	{
		xprintf(L_CRITICAL,
		        "Can't find a valid set of metadata on the disk. Abort.\n");
		ret = EXIT_FAILURE;
		goto FIRST_CLEAN;
	}
	
	/* Checking BitLocker version */
	if(((bitlocker_header_t*)bl_metadata)->version > V_SEVEN)
	{
		xprintf(L_CRITICAL,
		        "Program designed only for BitLocker version 2 and less, "
		        "the version here is %hd. Abort.\n",
		        ((bitlocker_header_t*)bl_metadata)->version);
		ret = EXIT_FAILURE;
		goto FIRST_CLEAN;
	}
	
	
	xprintf(L_INFO, "BitLocker metadata found and parsed.\n");
	
	/* For debug purpose, print the volume header retrieved and the metadata */
	print_bl_metadata(L_DEBUG, bl_metadata);
	print_data(L_DEBUG, bl_metadata);
	
	/* Now that we have the metadata, get the dataset within it */
	if(get_dataset(bl_metadata, &dataset) != TRUE)
	{
		xprintf(L_CRITICAL, "Unable to find a valid dataset. Abort.\n");
		goto FIRST_CLEAN;
	}
	
	/*
	 * First, get the VMK datum using either a clear key, a recovery password
	 * or a bek file
	 */
	while(cfg.decryption_mean)
	{
		if(cfg.decryption_mean & USE_CLEAR_KEY)
		{
			if(!get_vmk_from_clearkey(dataset, &vmk_datum))
			{
				cfg.decryption_mean &= (unsigned) ~USE_CLEAR_KEY;
			}
			else
			{
				xprintf(L_INFO, "Used clear key decryption method\n");
				cfg.decryption_mean = USE_CLEAR_KEY;
				break;
			}
		}
		else if(cfg.decryption_mean & USE_USER_PASSWORD)
		{
			if(!get_vmk_from_user_pass(dataset, &cfg, &vmk_datum))
			{
				cfg.decryption_mean &= (unsigned) ~USE_USER_PASSWORD;
			}
			else
			{
				xprintf(L_INFO, "Used user password decryption method\n");
				cfg.decryption_mean = USE_USER_PASSWORD;
				break;
			}
		}
		else if(cfg.decryption_mean & USE_RECOVERY_PASSWORD)
		{
			if(!get_vmk_from_rp(dataset, &cfg, &vmk_datum))
			{
				cfg.decryption_mean &= (unsigned) ~USE_RECOVERY_PASSWORD;
			}
			else
			{
				xprintf(L_INFO, "Used recovery password decryption method\n");
				cfg.decryption_mean = USE_RECOVERY_PASSWORD;
				break;
			}
		}
		else if(cfg.decryption_mean & USE_BEKFILE)
		{
			if(!get_vmk_from_bekfile(dataset, &cfg, &vmk_datum))
			{
				cfg.decryption_mean &= (unsigned) ~USE_BEKFILE;
			}
			else
			{
				xprintf(L_INFO, "Used bek file decryption method\n");
				cfg.decryption_mean = USE_BEKFILE;
				break;
			}
		}
		else if(cfg.decryption_mean & USE_FVEKFILE)
		{
			if(!build_fvek_from_file(&cfg, &fvek_datum))
			{
				cfg.decryption_mean &= (unsigned) ~USE_FVEKFILE;
			}
			else
			{
				xprintf(L_INFO, "Used FVEK file decryption method\n");
				cfg.decryption_mean = USE_FVEKFILE;
				break;
			}
		}
		else
		{
			xprintf(L_CRITICAL, "Wtf!? Abort.\n");
			ret = EXIT_FAILURE;
			goto FIRST_CLEAN;
		}
	}
	
	if(!cfg.decryption_mean)
	{
		xprintf(L_CRITICAL, "None of the provided decryption mean is "
		                    "decrypting the keys. Abort.\n");
		ret = EXIT_FAILURE;
		goto FIRST_CLEAN;
	}
	
	
	/*
	 * NOTE -- We could here validate bl_metadata in a more precise way
	 * using the VMK and the validations infos after the informations
	 * 
	 * NOTE -- We could here get all of the other key a user could use
	 * using the VMK and the reverse encrypted data
	 */
	
	
	/*
	 * And then, use the VMK to decrypt the FVEK
	 */
	if(cfg.decryption_mean != USE_FVEKFILE)
	{
		if(!get_fvek(dataset, vmk_datum, &fvek_datum))
		{
			ret = EXIT_FAILURE;
			goto FIRST_CLEAN;
		}
	}
	
	
	/* Just a check of the algo used to crypt data here */
	datum_key_t* fvek_typed_datum = (datum_key_t*) fvek_datum;
	fvek_typed_datum->algo &= 0xffff;
	
	if(fvek_typed_datum->algo < AES_128_DIFFUSER ||
	   fvek_typed_datum->algo > AES_256_NO_DIFFUSER)
	{
		xprintf(L_CRITICAL,
		        "Can't recognize the encryption algorithm used: %#x. Abort\n",
		        fvek_typed_datum->algo);
		ret = EXIT_FAILURE;
		goto FIRST_CLEAN;
	}
	
	
	
	/*
	 * Init the decrypt keys' contexts
	 */
	if(!init_keys(dataset, fvek_typed_datum, &ctx))
	{
		xprintf(L_CRITICAL, "Can't initialize keys. Abort.\n");
		ret = EXIT_FAILURE;
		goto FIRST_CLEAN;
	}
	
	
	
	/*
	 * We have everything we need to run in fuse or whatever now
	 * Let's clean things we don't need here
	 */
	ret = EXIT_SUCCESS;
	
FIRST_CLEAN:
	
	/* Free them all! */
	if(vmk_datum)
		memclean(vmk_datum,
		        ((datum_generic_type_t*)vmk_datum)->header.datum_size);
	
	if(fvek_datum)
		memclean(fvek_datum, fvek_typed_datum->header.datum_size);
	
	/* Goto finnishing to clean everything before returning */
	if(ret == EXIT_FAILURE)
		goto LAST_CLEAN;
	
	
	/*
	 * Fill the data_t structure which will be used for decryption afterward
	 */
	if(!prepare_crypt((bitlocker_header_t*) bl_metadata, &ctx, &cfg,
	                  &volume_header, cfg.offset, fd_volume))
	{
		xprintf(L_CRITICAL, "Can't prepare the crypt structure. Abort.\n");
		ret = EXIT_FAILURE;
		goto LAST_CLEAN;
	}
	
	
#if defined(__RUN_FUSE)
	/** @see fuse.c */
	extern struct fuse_operations fs_oper;
	
	/*
	 * Create the parameters table needed for FUSE and run it
	 * This is as we're running argv[0] followed by ARGS (see usage())
	 */
	
	/* Get the new value for argc */
	if(param_idx >= argc || param_idx <= 0)
	{
		xprintf(L_CRITICAL, "Error, no mount point given. Abort.\n");
		ret = EXIT_FAILURE;
		goto LAST_CLEAN;
	}
	
	size_t new_argc = (size_t)(argc - param_idx + 1);
	xprintf(L_DEBUG, "New value for argc: %d\n", new_argc);
	
	char** new_argv = xmalloc(new_argc * sizeof(char*));
	
	
	/* Get argv[0] */
	size_t lg = strlen(argv[0]) + 1;
	*new_argv = xmalloc(lg);
	memcpy(*new_argv, argv[0], lg);
	
	
	/* Get all of the parameters from param_idx till the end */
	size_t loop = 0;
	for(loop = 1; loop < new_argc; ++loop)
	{
		lg = strlen(argv[(size_t)param_idx + loop - 1]) + 1;
		*(new_argv + loop) = xmalloc(lg);
		memcpy(*(new_argv + loop), argv[(size_t)param_idx + loop - 1], lg);
	}
	
	
	xprintf(L_INFO, "Running FUSE with these arguments: \n");
	for(loop = 0; loop < new_argc; ++loop)
		xprintf(L_INFO, "  `--> '%s'\n", *(new_argv + loop));
	
	
	/* Run FUSE */
	ret = fuse_main((int)new_argc, new_argv, &fs_oper, NULL);
	
	/* Free FUSE params */
	for(loop = 0; loop < new_argc; ++loop)
		xfree(new_argv[loop]);
	xfree(new_argv);
	
#elif defined(__RUN_FILE)
	
	/*
	 * Create a NTFS file which could be mounted using `mount -o loop...`
	 */
	
	/* Check that we have the file where to put NTFS data */
	if(argc <= param_idx)
	{
		xprintf(L_CRITICAL, "Error, no file given. Abort.\n");
		ret = EXIT_FAILURE;
		goto LAST_CLEAN;
	}
	
	char* ntfs_file = argv[param_idx];
	xprintf(L_INFO, "Putting NTFS data into '%s'...\n", ntfs_file);
	
	/* Run the decryption */
	ret = file_main(ntfs_file);
	
#else /* no __RUN_FUSE, nor __RUN_FILE */
	xprintf(L_ERROR, "Neither __RUN_FILE nor __RUN_FUSE was enabled. "
	                 "Nothing to do.\n");
#endif
	
LAST_CLEAN:
	/* Finnish cleaning things */
	if(bl_metadata)
		xfree(bl_metadata);
	
	pthread_mutex_destroy(&disk_op_data.mutex_lseek_rw);
	
	free_args(&cfg);
	
	xclose(fd_volume);
	
	xstdio_end();
	
	
	return ret;
}


/**
 * Initialize data decryption keys
 * 
 * @param dataset BitLocker dataset
 * @param fvek The entire 32 bytes FVEK, without the KEY structure
 * @param ctx Contexts to initialize, used by AES-CBC for data en/decryption
 * @return TRUE if result can be trusted, FALSE otherwise
 */
static int init_keys(bitlocker_dataset_t* dataset, datum_key_t* fvek_datum,
                     contexts_t* ctx)
{
	// Check parameters
	if(!dataset || !fvek_datum || !ctx)
		return FALSE;
	
	uint8_t* fvek    = NULL;
	size_t size_fvek = 0;
	
	if(!get_payload_safe(fvek_datum, (void**)&fvek, &size_fvek))
	{
		xprintf(L_ERROR, "Can't get the FVEK datum payload. Abort.\n");
		return FALSE;
	}
	
	xprintf(L_DEBUG,
	        "FVEK -----------------------------------------------------\n");
	hexdump(L_DEBUG, fvek, size_fvek);
	xprintf(L_DEBUG,
	        "----------------------------------------------------------\n");
	
	/*
	 * It shouldn't be necessary as the algorithms should be the same, but
	 * still, we have a choice, so we do both
	 */
	uint16_t  algo[3] = {dataset->algorithm, fvek_datum->algo, 0};
	uint16_t* palgo   = algo;
	
	while(*palgo != 0)
	{
		switch(*palgo)
		{
			case AES_128_DIFFUSER:
				AES_SETENC_KEY(&ctx->TWEAK_E_ctx, fvek + 0x20, 128);
				AES_SETDEC_KEY(&ctx->TWEAK_D_ctx, fvek + 0x20, 128);
				/* no break on purpose */
			case AES_128_NO_DIFFUSER:
				AES_SETENC_KEY(&ctx->FVEK_E_ctx, fvek, 128);
				AES_SETDEC_KEY(&ctx->FVEK_D_ctx, fvek, 128);
				memclean(fvek, size_fvek);
				return TRUE;
				
			case AES_256_DIFFUSER:
				AES_SETENC_KEY(&ctx->TWEAK_E_ctx, fvek + 0x20, 256);
				AES_SETDEC_KEY(&ctx->TWEAK_D_ctx, fvek + 0x20, 256);
				/* no break on purpose */
			case AES_256_NO_DIFFUSER:
				AES_SETENC_KEY(&ctx->FVEK_E_ctx, fvek, 256);
				AES_SETDEC_KEY(&ctx->FVEK_D_ctx, fvek, 256);
				memclean(fvek, size_fvek);
				return TRUE;
				
			default:
			{
				unsigned long i = (unsigned long)(palgo - algo);
				i /= sizeof(uint16_t);
				xprintf(L_WARNING, "[%lu] Algo not supported: %#hx\n",
				        i, *palgo);
				break;
			}
		}
		
		palgo++;
	}
	
	xprintf(L_ERROR,
	        "Dataset's and FVEK's algorithms not supported: %#hx and %#hx\n",
	        dataset->algorithm, fvek_datum->algo);
	memclean(fvek, size_fvek);
	
	return FALSE;
}


/**
 * Prepare a structure which hold data used for decryption/encryption
 * 
 * @param metadata The BitLocker metadata block
 * @param ctx Contexts used to encrypt/decrypt data
 * @param sector_size The sector size of the volume
 * @param offset Where the real volume begins
 * @param fd The volume's file descriptor
 */
static int prepare_crypt(bitlocker_header_t* metadata, contexts_t* ctx,
                         dis_config_t* cfg, volume_header_t* volume_header,
                         off_t offset, int fd_volume)
{
	uint16_t sector_size = volume_header->sector_size;
	
	/** @see encommon.h for disk_op_data */
	memset(&disk_op_data, 0, sizeof(data_t));
	
	disk_op_data.metadata       = metadata;
	disk_op_data.metafiles_size = (off_t)
	                              (~(sector_size - 1) & (sector_size + 0xffff));
	disk_op_data.xinfo          = NULL;
	disk_op_data.sector_size    = sector_size;
	disk_op_data.part_off       = offset;
	disk_op_data.ctx            = ctx;
	disk_op_data.cfg            = cfg;
	disk_op_data.volume_fd      = fd_volume;
	disk_op_data.decrypt_region = read_decrypt_sectors;
	disk_op_data.encrypt_region = encrypt_write_sectors;
	
	if(pthread_mutex_init(&disk_op_data.mutex_lseek_rw, NULL) != 0)
	{
		xprintf(L_ERROR, "Can't initialize mutex: %s\n", strerror(errno));
		return FALSE;
	}
	
	/*
	 * We need to grab the volume's size from the first sector, so we can
	 * announce it on a getattr call
	 */
	if(volume_header->nb_sectors_16b)
	{
		disk_op_data.volume_size = (uint64_t)volume_header->sector_size
		                         * volume_header->nb_sectors_16b;
	}
	else if(volume_header->nb_sectors_32b)
	{
		disk_op_data.volume_size = (uint64_t)volume_header->sector_size
		                         * volume_header->nb_sectors_32b;
	}
	else if(disk_op_data.metadata->version == V_VISTA && volume_header->nb_sectors_64b)
	{
		disk_op_data.volume_size = (uint64_t)volume_header->sector_size
		                         * volume_header->nb_sectors_64b;
	}
	else if(disk_op_data.metadata->version == V_SEVEN)
	{
		/* This is not the first sector but well, it's worth a try */
		disk_op_data.volume_size = metadata->encrypted_volume_size;
	}
	else
	{
		xprintf(L_ERROR, "Can't initialize the volume's size\n");
		return FALSE;
	}
	
	xprintf(L_INFO, "Found volume's size: 0x%1$" F_U64_T " (%1$llu) bytes\n", disk_op_data.volume_size);
	
	
	/*
	 * On BitLocker 7's volumes, there's a virtualized space used to store
	 * firsts NTFS sectors. BitLocker creates a NTFS file to not write on the
	 * area and displays a zeroes-filled file.
	 * A second part, new from Windows 8, follows...
	 */
	if(disk_op_data.metadata->version == V_SEVEN)
	{
		datum_virtualization_t* datum = NULL;
		if(!get_next_datum(&metadata->dataset, -1,
		    DATUM_VIRTUALIZATION_INFO, NULL, (void**)&datum))
		{
			char* type_str = datumtypestr(DATUM_VIRTUALIZATION_INFO);
			xprintf(L_ERROR, "Error looking for the VIRTUALIZATION datum type"
			                 " %hd (%s). Internal failure, abort.\n",
			                 DATUM_VIRTUALIZATION_INFO, type_str);
			xfree(type_str);
			datum = NULL;
			return FALSE;
		}
		
		disk_op_data.virtualized_size = (off_t)datum->nb_bytes;
		xprintf(L_DEBUG, "Virtualized info size: %#" F_OFF_T "\n",
		        disk_op_data.virtualized_size);
		
		/* Extended info is new to Windows 8 */
		size_t win7_size   = datum_types_prop[datum->header.datum_type].size_header;
		size_t actual_size = ((size_t)datum->header.datum_size) & 0xffff;
		if(actual_size > win7_size)
		{
			disk_op_data.xinfo = &datum->xinfo;
			xprintf(L_DEBUG, "Got extended info\n");
			
			/* FIXME Windows 8 writing is not supported right now */
			disk_op_data.cfg->is_ro |= READ_ONLY;
			xprintf(L_WARNING, "Volume formated Win8, falling back to read-only.\n");
		}
	}
	
	return TRUE;
}


