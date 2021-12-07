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

#define _GNU_SOURCE 1
#include "dislocker/encryption/crc32.h"
#include "dislocker/metadata/metadata.priv.h"
#include "dislocker/metadata/metadata_config.h"
#include "dislocker/metadata/print_metadata.h"
#include "dislocker/dislocker.priv.h"

#include <sys/ioctl.h>

#define BLKSSZGET  _IO(0x12,104)/* get block device sector size */

/*
 * On Darwin and FreeBSD, files are opened using 64 bits offsets/variables
 * and O_LARGEFILE isn't defined
 */
#if defined(__DARWIN) || defined(__FREEBSD)
#  define O_LARGEFILE 0
#endif /* __DARWIN || __FREEBSD */




static int get_volume_header(
	volume_header_t *volume_header,
	int fd,
	off_t partition_offset
);

static int check_volume_header(
	dis_metadata_t dis_metadata,
	int volume_fd,
	off_t disk_offset
);

static int begin_compute_regions(
	volume_header_t* vh,
	int fd,
	off_t disk_offset,
	dis_regions_t* regions
);

static int end_compute_regions(dis_metadata_t dis_meta);

static int get_metadata(off_t source, void **metadata, int fd);

static int get_dataset(void* metadata, bitlocker_dataset_t** dataset);

static int get_eow_information(off_t source, void** eow_infos, int fd);

static int get_metadata_lazy_checked(
	volume_header_t* volume_header,
	int fd,
	void** metadata,
	off_t disk_offset,
	unsigned char force_block,
	dis_regions_t *regions
);

static int get_eow_check_valid(
	volume_header_t *volume_header,
	int fd,
	void **eow_infos,
	off_t disk_offset
);




dis_metadata_config_t dis_metadata_config_new()
{
	size_t len = sizeof(struct _dis_metadata_config);
	dis_metadata_config_t dis_meta_cfg = dis_malloc(len);

	if(dis_meta_cfg == NULL)
		return NULL;

	memset(dis_meta_cfg, 0, len);

	return dis_meta_cfg;
}

void dis_metadata_config_destroy(dis_metadata_config_t dis_meta_cfg)
{
	if(dis_meta_cfg)
		dis_free(dis_meta_cfg);
}



dis_metadata_t dis_metadata_new(dis_metadata_config_t dis_metadata_cfg)
{
	if(!dis_metadata_cfg)
		return NULL;

	dis_metadata_t dis_meta = dis_malloc(sizeof(struct _dis_metadata));
	memset(dis_meta, 0, sizeof(struct _dis_metadata));

	dis_meta->volume_header = dis_malloc(sizeof(volume_header_t));

	memset(dis_meta->volume_header, 0, sizeof(volume_header_t));

	dis_meta->cfg = dis_metadata_cfg;

	return dis_meta;
}


dis_metadata_t dis_metadata_get(dis_context_t dis_ctx)
{
	if(!dis_ctx)
		return NULL;

	return dis_ctx->metadata;
}


int dis_metadata_initialize(dis_metadata_t dis_meta)
{
	if(!dis_meta)
		return DIS_RET_ERROR_DISLOCKER_INVAL;

	dis_metadata_config_t dis_meta_cfg = dis_meta->cfg;

	int ret = DIS_RET_SUCCESS;

	void*                    metadata    = NULL;
	bitlocker_information_t* information = NULL;
	bitlocker_dataset_t*     dataset     = NULL;


	/* Getting volume infos */
	if(!get_volume_header(
		dis_meta->volume_header,
		dis_meta_cfg->fve_fd,
		dis_meta_cfg->offset))
	{
		dis_printf(
			L_CRITICAL,
			"Error during reading the volume: not enough byte read.\n"
		);
		return DIS_RET_ERROR_VOLUME_HEADER_READ;
	}

	//Windows 10 1903 exFAT
	if (!dis_meta->volume_header->sector_size) {
		uint64_t nSectorSize = 0;
		ioctl(dis_meta_cfg->fve_fd, BLKSSZGET, &nSectorSize);
		if(!nSectorSize)
			nSectorSize = 512;
		dis_meta->volume_header->sector_size = (uint16_t)nSectorSize;
	}
	//Windows 10 1903 exFAT

	/* For debug purpose, print the volume header retrieved */
	print_volume_header(L_DEBUG, dis_meta);

	checkupdate_dis_meta_state(dis_meta_cfg, DIS_STATE_AFTER_VOLUME_HEADER);


	/* Checking the volume header */
	if(!check_volume_header(dis_meta, dis_meta_cfg->fve_fd, dis_meta_cfg->offset))
	{
		dis_printf(L_CRITICAL, "Cannot parse volume header. Abort.\n");
		return DIS_RET_ERROR_VOLUME_HEADER_CHECK;
	}

	checkupdate_dis_meta_state(dis_meta_cfg, DIS_STATE_AFTER_VOLUME_CHECK);


	/* Fill the regions the metadata occupy on disk */
	if(!begin_compute_regions(
		dis_meta->volume_header,
		dis_meta_cfg->fve_fd,
		dis_meta_cfg->offset,
		dis_meta->virt_region))
	{
		dis_printf(
			L_CRITICAL,
			"Can't compute regions from volume header. Abort.\n"
		);
		return DIS_RET_ERROR_METADATA_OFFSET;
	}


	/* Getting BitLocker metadata and validate them */
	if(!get_metadata_lazy_checked(
		dis_meta->volume_header,
		dis_meta_cfg->fve_fd,
		&metadata,
		dis_meta_cfg->offset,
		dis_meta_cfg->force_block,
		dis_meta->virt_region))
	{
		dis_printf(
			L_CRITICAL,
			"A problem occurred during the retrieving of metadata. Abort.\n"
		);
		return DIS_RET_ERROR_METADATA_CHECK;
	}

	if(!metadata)
	{
		dis_printf(
			L_CRITICAL,
			"Can't find a valid set of metadata on the disk. Abort.\n"
		);
		return DIS_RET_ERROR_METADATA_CHECK;
	}

	/* Don't use dis_meta->information here as metadata are not validated yet */
	information = metadata;


	/* Checking BitLocker version */
	if(information->version > V_SEVEN)
	{
		dis_printf(
			L_CRITICAL,
			"Program designed only for BitLocker version 2 and less, "
			"the version here is %hd. Abort.\n",
			information->version
		);
		return DIS_RET_ERROR_METADATA_VERSION_UNSUPPORTED;
	}

	dis_printf(L_INFO, "BitLocker metadata found and parsed.\n");

	dis_meta->information = information;

	/* Now that we have the information, get the dataset within it */
	if(get_dataset(metadata, &dataset) != TRUE)
	{
		dis_printf(L_CRITICAL, "Unable to find a valid dataset. Abort.\n");
		return DIS_RET_ERROR_DATASET_CHECK;
	}

	dis_meta->dataset = dataset;


	/* For debug purpose, print the metadata */
	print_information(L_DEBUG, dis_meta);
	print_data(L_DEBUG, dis_meta);

	checkupdate_dis_meta_state(dis_meta_cfg, DIS_STATE_AFTER_BITLOCKER_INFORMATION_CHECK);

	/*
	 * Initialize region to report as filled with zeroes, if asked from the NTFS
	 * layer. This is to mimic BitLocker's behaviour.
	 */
	if((ret = end_compute_regions(dis_meta)) != DIS_RET_SUCCESS)
	{
		dis_printf(L_CRITICAL, "Unable to compute regions. Abort.\n");
		return ret;
	}

	return ret;
}


int dis_metadata_destroy(dis_metadata_t dis_meta)
{
	if(!dis_meta)
		return DIS_RET_ERROR_DISLOCKER_INVAL;

	if(dis_meta->volume_header)
		dis_free(dis_meta->volume_header);

	if(dis_meta->information)
		dis_free(dis_meta->information);

	dis_metadata_config_destroy(dis_meta->cfg);
	dis_free(dis_meta);

	return DIS_RET_SUCCESS;
}



/**
 * Read the beginning of a volume and put it in a volume_header_t structure
 *
 * @param volume_header A volume header structure to complete
 * @param fd A file descriptor to the volume
 * @param offset The initial partition offset
 * @return TRUE if result can be trusted, FALSE otherwise
 */
static int get_volume_header(volume_header_t *volume_header, int fd, off_t offset)
{
	if(!volume_header || fd < 0)
		return FALSE;

	// Go to the beginning
	dis_lseek(fd, offset, SEEK_SET);

	dis_printf(L_DEBUG, "Reading volume header...\n");

	// Read and place data into the volume_header_t structure
	ssize_t nb_read = dis_read(fd, volume_header, sizeof(volume_header_t));

	// Check if we read all we wanted
	if(nb_read != sizeof(volume_header_t))
		return FALSE;

	dis_printf(L_DEBUG, "Volume header read\n");

	return TRUE;
}


/**
 * Get BitLocker's version from the volume header
 *
 * @param volume_header A volume header structure to check
 * @return V_VISTA or V_SEVEN according to the version found, or -1 if not
 * recognized
 */
static inline int get_version_from_volume_header(volume_header_t *volume_header)
{
	if(memcmp(BITLOCKER_SIGNATURE, volume_header->signature,
	          BITLOCKER_SIGNATURE_SIZE) == 0)
	{
		if(volume_header->metadata_lcn == 0)
			return V_SEVEN;

		return V_VISTA;
	}

	return -1;
}


/**
 * Check the volume header
 *
 * @param volume_header A volume header structure to check
 * @param volume_fd The opened file descriptor of the BitLocker volume
 * @param disk_offset The offset of the beginning of the volume
 * @return TRUE if result can be trusted, FALSE otherwise
 */
static int check_volume_header(dis_metadata_t dis_meta, int volume_fd, off_t disk_offset)
{
	if(!dis_meta || volume_fd < 0)
		return FALSE;

	volume_header_t* volume_header = dis_meta->volume_header;
	guid_t volume_guid;

	/* Checking sector size */
	if(volume_header->sector_size == 0)
	{
		dis_printf(L_ERROR, "The sector size found is null.\n");
		return FALSE;
	}

	/* Check the signature */
	if(memcmp(BITLOCKER_SIGNATURE, volume_header->signature,
	          BITLOCKER_SIGNATURE_SIZE) == 0)
	{
		memcpy(volume_guid, volume_header->guid, sizeof(guid_t));
	}
	else if(memcmp(BITLOCKER_TO_GO_SIGNATURE, volume_header->signature,
	               BITLOCKER_TO_GO_SIGNATURE_SIZE) == 0)
	{
		memcpy(volume_guid, volume_header->bltg_guid, sizeof(guid_t));
	}
	else
	{
		dis_printf(
		        L_ERROR,
		        "The signature of the volume (%.8s) doesn't match the "
		        "BitLocker's ones (" BITLOCKER_SIGNATURE " or "
		        BITLOCKER_TO_GO_SIGNATURE "). Abort.\n",
		        volume_header->signature
		);
		return FALSE;
	}


	/*
	 * There's no BitLocker GUID in the volume header for volumes encrypted by
	 * Vista
	 */
	if(get_version_from_volume_header(volume_header) == V_VISTA)
		return TRUE;


	/* Check if we're running under EOW mode */
	extern guid_t INFORMATION_OFFSET_GUID, EOW_INFORMATION_OFFSET_GUID;

	if(check_match_guid(volume_guid, INFORMATION_OFFSET_GUID))
	{
		dis_printf(L_INFO, "Volume GUID (INFORMATION OFFSET) supported\n");
	}
	else if(check_match_guid(volume_guid, EOW_INFORMATION_OFFSET_GUID))
	{
		dis_printf(L_INFO, "Volume has EOW_INFORMATION_OFFSET_GUID.\n");

		// First: get the EOW informations no matter what
		off_t source = (off_t) volume_header->eow_information_off[0];
		void* eow_infos = NULL;

		if(get_eow_information(source, &eow_infos, volume_fd))
		{
			dis_meta->eow_information = eow_infos;

			// Second: print them
			print_eow_infos(L_DEBUG, dis_meta);

			dis_free(eow_infos);
			dis_meta->eow_information = NULL;

			// Third: check if this struct passes checks
			if(get_eow_check_valid(volume_header, volume_fd, &eow_infos, disk_offset))
			{
				dis_printf(L_INFO,
				        "EOW information at offset % " F_OFF_T
				        " passed the tests\n", source);
				dis_free(eow_infos);
			}
			else
			{
				dis_printf(L_ERROR,
				        "EOW information at offset % " F_OFF_T
				        " failed to pass the tests\n", source);
			}
		}
		else
		{
			dis_printf(L_ERROR,
			        "Getting EOW information at offset % " F_OFF_T
			        " failed\n", source);
		}

		if (!dis_meta->cfg->readonly) {
			dis_printf(L_ERROR, "EOW volume GUID not supported for writing.\n");
			return FALSE;
        }
	}
	else
	{
		dis_printf(L_ERROR, "Unknown volume GUID, not supported.\n");
		return FALSE;
	}

	return TRUE;
}


/**
 * This function compute the real offsets when the metadata_lcn doesn't equal 0
 * This is because of Vista which compute offsets differently than Seven
 * This also takes into account BitLocker-to-go's volume header structure
 * difference in the offsets
 *
 * @param vh The volume header structure already taken
 * @param fd The opened file descriptor of the BitLocker volume
 * @param disk_offset Initial partition offset
 * @param regions The 3 offsets of the BitLocker INFORMATION structure (which
 * corresponds to our bitlocker_information_t structure) will be put in the 3
 * first addr member of this array
 * @return TRUE if result can be trusted, FALSE otherwise
 */
static int begin_compute_regions(volume_header_t* vh,
                          int fd,
                          off_t disk_offset,
                          dis_regions_t* regions)
{
	// Check parameters
	if(!vh || fd < 0)
		return FALSE;


	if(memcmp(BITLOCKER_SIGNATURE, vh->signature,
	          BITLOCKER_SIGNATURE_SIZE) == 0)
	{
		/* This is when the volume has been encrypted with W$ 7 or 8 */
		if(get_version_from_volume_header(vh) == V_SEVEN)
		{
			regions[0].addr = vh->information_off[0];
			regions[1].addr = vh->information_off[1];
			regions[2].addr = vh->information_off[2];
			return TRUE;
		}

		/* And when encrypted with W$ Vista: */
		dis_printf(
			L_DEBUG,
			"MetadataLcn = %" PRIu64
			" | SectorsPerCluster = %" PRIu64
			" | SectorSize = %" PRIu64 "\n",
			vh->metadata_lcn,
			vh->sectors_per_cluster,
			vh->sector_size
		);

		uint64_t new_offset = vh->metadata_lcn * vh->sectors_per_cluster * vh->sector_size;
		dis_printf(
			L_DEBUG,
			"Changing first metadata offset from %#" PRIx64
			" to %#" PRIx64 "\n",
			vh->information_off[0],
			new_offset
		);
		regions[0].addr = new_offset;

		/* Now that we have the first offset, go get the others */
		bitlocker_information_t* information = NULL;
		if(!get_metadata(
				(off_t) new_offset + disk_offset,
				(void**) &information, fd
			))
			return FALSE;

		regions[1].addr = information->information_off[1];
		regions[2].addr = information->information_off[2];

		dis_free(information);
	}
	else if(memcmp(BITLOCKER_TO_GO_SIGNATURE, vh->signature,
	               BITLOCKER_TO_GO_SIGNATURE_SIZE) == 0)
	{
		regions[0].addr = vh->bltg_header[0];
		regions[1].addr = vh->bltg_header[1];
		regions[2].addr = vh->bltg_header[2];
	}
	else
	{
		dis_printf(L_ERROR, "Wtf!? Unknown volume signature not supported.");
		return FALSE;
	}

	return TRUE;
}


/**
 * This finalizes the initialization of the regions informations, putting the
 * metadata file sizes in the right place.
 *
 * @param dis_metadata The metadata structure
 * @return DIS_RET_SUCCESS on success, other value on failure
 */
static int end_compute_regions(dis_metadata_t dis_meta)
{
	if(!dis_meta)
		return DIS_RET_ERROR_DISLOCKER_INVAL;

	dis_regions_t*           regions       = dis_meta->virt_region;
	volume_header_t*         volume_header = dis_meta->volume_header;
	bitlocker_information_t* information   = dis_meta->information;

	uint16_t sector_size         = volume_header->sector_size;
	uint8_t  sectors_per_cluster = volume_header->sectors_per_cluster;
	uint32_t cluster_size        = 0;
	uint64_t metafiles_size      = 0;


	/*
	 * Alignment isn't the same for W$ Vista (size-of-a-cluster aligned on
	 * 0x4000) and 7&8 (size-of-a-sector aligned on 0x10000).
	 * This gives the metadata files' sizes in the NTFS layer.
	 */
	if(information->version == V_VISTA)
	{
		cluster_size   = (uint32_t)sector_size * sectors_per_cluster;
		metafiles_size = (uint64_t)(cluster_size+0x3fff) & ~(cluster_size-1);
	}
	else if(information->version == V_SEVEN)
	{
		metafiles_size = (uint64_t)(~(sector_size-1) & (sector_size+0xffff));
	}


	dis_printf(L_DEBUG, "Metadata files size: %#" PRIx64 "\n", metafiles_size);

	/*
	 * The first 3 regions are for INFORMATION metadata, they have the same size
	 */
	regions[0].size = metafiles_size;
	regions[1].size = metafiles_size;
	regions[2].size = metafiles_size;
	dis_meta->nb_virt_region = 3;


	if(information->version == V_VISTA)
	{
		// Nothing special to do
	}
	else if(information->version == V_SEVEN)
	{
		/*
		 * On BitLocker 7's volumes, there's a virtualized space used to store
		 * firsts NTFS sectors. BitLocker creates a NTFS file to not write on
		 * the area and displays a zeroes-filled file.
		 * A second part, new from Windows 8, follows...
		 */
		datum_virtualization_t* datum = NULL;
		if(!get_next_datum(dis_meta, UINT16_MAX,
		    DATUMS_VALUE_VIRTUALIZATION_INFO, NULL, (void**)&datum))
		{
			char* type_str = datumvaluetypestr(DATUMS_VALUE_VIRTUALIZATION_INFO);
			dis_printf(
				L_ERROR,
				"Error looking for the VIRTUALIZATION datum type"
				" %hd (%s). Internal failure, abort.\n",
				DATUMS_VALUE_VIRTUALIZATION_INFO,
				type_str
			);
			dis_free(type_str);
			datum = NULL;
			return DIS_RET_ERROR_VIRTUALIZATION_INFO_DATUM_NOT_FOUND;
		}

		dis_meta->nb_virt_region++;
		regions[3].addr = information->boot_sectors_backup;
		regions[3].size = datum->nb_bytes;

		/* Another area to report as filled with zeroes, new to W8 as well */
		if(information->curr_state == METADATA_STATE_SWITCHING_ENCRYPTION)
		{
			dis_meta->nb_virt_region++;
			regions[4].addr = information->encrypted_volume_size;
			regions[4].size = information->convert_size;
		}

		dis_meta->virtualized_size = (off_t)datum->nb_bytes;

		dis_printf(
			L_DEBUG,
			"Virtualized info size: %#" F_OFF_T "\n",
			dis_meta->virtualized_size
		);


		/* Extended info is new to Windows 8 */
		size_t win7_size   = datum_value_types_prop[datum->header.value_type].size_header;
		size_t actual_size = ((size_t)datum->header.datum_size) & 0xffff;
		if(actual_size > win7_size)
		{
			dis_meta->xinfo = &datum->xinfo;
			dis_printf(L_DEBUG, "Got extended info\n");
		}
	}
	else
	{
		/* Explicitly mark a BitLocker version as unsupported */
		dis_printf(L_ERROR, "Unsupported BitLocker version (%hu)\n", information->version);
		return DIS_RET_ERROR_METADATA_VERSION_UNSUPPORTED;
	}


	return DIS_RET_SUCCESS;
}


/**
 * Read the beginning of one of the BitLocker metadata area and put data in a
 * bitlocker_information_t structure.
 * This also take the dataset header as it's in the bitlocker_information_t.
 * Then includes datums in the read.
 *
 * @param source The beginning address of the header
 * @param metadata One of the BitLocker metadata, beginning at source
 * @param fd A file descriptor to the volume
 * @return TRUE if result can be trusted, FALSE otherwise
 */
static int get_metadata(off_t source, void **metadata, int fd)
{
	if(!source || fd < 0 || !metadata)
		return FALSE;

	// Go to the beginning of the BitLocker header
	dis_lseek(fd, source, SEEK_SET);

	dis_printf(L_DEBUG, "Reading bitlocker header at %#" F_OFF_T "...\n", source);

	bitlocker_information_t information;

	/*
	 * Read and place data into the bitlocker_information_t structure,
	 * this is the metadata's header
	 */
	ssize_t nb_read = dis_read(fd, &information, sizeof(bitlocker_information_t));

	// Check if we read all we wanted
	if(nb_read != sizeof(bitlocker_information_t))
	{
		dis_printf(L_ERROR, "get_metadata::Error, not all bytes read: %d, %d"
				" expected (1).\n", nb_read, sizeof(bitlocker_information_t));
		return FALSE;
	}

	/*
	 * Now that we now the size of the metadata, allocate a buffer and read data
	 * to complete it
	 */
	size_t size = (size_t)(information.version == V_SEVEN ?
	                                  information.size << 4 : information.size);


	if(size <= sizeof(bitlocker_information_t))
	{
		dis_printf(L_ERROR, "get_metadata::Error, metadata size is lesser than the"
				" size of the metadata header\n");
		return FALSE;
	}

	size_t rest_size = size - sizeof(bitlocker_information_t);

	*metadata = dis_malloc(size);

	// Copy the header at the beginning of the metadata
	memcpy(*metadata, &information, sizeof(bitlocker_information_t));

	dis_printf(L_DEBUG, "Reading data...\n");

	// Read the rest, the real data
	nb_read = dis_read(fd, *metadata + sizeof(bitlocker_information_t), rest_size);

	// Check if we read all we wanted
	if((size_t) nb_read != rest_size)
	{
		dis_printf(L_ERROR, "get_metadata::Error, not all bytes read: %d, %d"
				" expected (2).\n", nb_read, rest_size);
		return FALSE;
	}

	dis_printf(L_DEBUG, "End get_metadata.\n");

	return TRUE;
}


/**
 * Get the dataset in the metadata
 * No allocation is performed
 *
 * @param metadata The one to check for a dataset
 * @param dataset The resulting dataset
 * @return TRUE if result can be trusted, FALSE otherwise
 */
static int get_dataset(void* metadata, bitlocker_dataset_t** dataset)
{
	// Check parameters
	if(!metadata)
		return FALSE;

	bitlocker_information_t* information = metadata;
	*dataset = &information->dataset;

	/* Check this dataset validity */
	if(
		(*dataset)->copy_size < (*dataset)->header_size
		|| (*dataset)->size   > (*dataset)->copy_size
		|| (*dataset)->copy_size - (*dataset)->header_size < 8
	)
	{
		dis_printf(L_DEBUG, "size=%#x, copy_size=%#x, header_size=%#x\n");
		return FALSE;
	}

	return TRUE;
}


/**
 * This function reads the EOW information in two phases: first the header, then
 * the payload.
 *
 * @param source The beginning address of the EOW information
 * @param eow_infos One of the EOW information, beginning at source
 * @param fd A file descriptor to the volume
 * @return TRUE if result can be trusted, FALSE otherwise
 */
static int get_eow_information(off_t source, void** eow_infos, int fd)
{
	if(!source || fd < 0 || !eow_infos)
		return FALSE;

	/* Go to the beginning of the EOW Information header */
	dis_lseek(fd, source, SEEK_SET);

	dis_printf(L_DEBUG, "Reading EOW Information header at %#" F_OFF_T "...\n",
	        source);

	bitlocker_eow_infos_t eow_infos_hdr;

	/*
	 * Read and place data into the bitlocker_eow_infos_t structure,
	 * this is the EOW information header
	 */
	ssize_t nb_read = dis_read(fd, &eow_infos_hdr, sizeof(bitlocker_eow_infos_t));

	// Check if we read all we wanted
	if(nb_read != sizeof(bitlocker_eow_infos_t))
	{
		dis_printf(L_ERROR, "get_eow_information::Error, not all bytes read: %d,"
		        " %d expected (1).\n", nb_read, sizeof(bitlocker_eow_infos_t));
		return FALSE;
	}

	size_t size = eow_infos_hdr.infos_size;

	if(size <= sizeof(bitlocker_eow_infos_t))
	{
		dis_printf(L_ERROR, "get_eow_information::Error, EOW information size is"
		        " lesser than the size of the header\n");
		return FALSE;
	}

	size_t rest_size = size - sizeof(bitlocker_eow_infos_t);

	*eow_infos = dis_malloc(size);

	// Copy the header at the beginning of the EOW information
	memcpy(*eow_infos, &eow_infos_hdr, sizeof(bitlocker_eow_infos_t));

	dis_printf(L_DEBUG, "Reading EOW information's payload...\n");

	// Read the rest, the payload
	nb_read = dis_read(fd, *eow_infos + sizeof(bitlocker_eow_infos_t), rest_size);

	// Check if we read all we wanted
	if((size_t) nb_read != rest_size)
	{
		dis_printf(L_ERROR, "get_eow_information::Error, not all bytes read: %d, "
		        "%d expected (2).\n", nb_read, rest_size);
		return FALSE;
	}

	dis_printf(L_DEBUG, "End get_eow_information.\n");


	return TRUE;
}


/**
 * Get metadata/validations one by one, stop at the first valid
 * If a metadata block is forced to be taken, use this one without validation
 *
 * @param volume_header The volume header structure already taken
 * @param fd The opened file descriptor of the volume
 * @param metadata A validated metadata resulting of this function
 * @param disk_offset The offset to the beginning of the volume
 * @param force_block The metadata block to use (0 if any)
 * @param regions Regions used by metadata, mostly the metadata's offsets for
 * use in this function
 * @return TRUE if result can be trusted, FALSE otherwise
 */
static int get_metadata_lazy_checked(
	volume_header_t *volume_header, int fd, void **metadata, off_t disk_offset,
	unsigned char force_block, dis_regions_t *regions)
{
	// Check parameters
	if(!volume_header || fd < 0 || !metadata)
		return FALSE;

	dis_printf(L_DEBUG, "Entering get_metadata_lazy_checked\n");

	bitlocker_information_t* information = NULL;
	unsigned int  metadata_size = 0;
	unsigned char current = 0;
	unsigned int  metadata_crc32 = 0;
	off_t         validations_offset = 0;
	bitlocker_validations_t validations;

	/* If the user wants a specific metadata block */
	if(force_block != 0)
	{
		dis_printf(L_INFO, "Obtaining block n°%d, forced by user...\n", force_block);
		// Get the metadata
		if(!get_metadata((off_t)regions[force_block-1].addr + disk_offset, metadata, fd))
		{
			dis_printf(L_ERROR, "Can't get metadata (n°%d, forced by user)\n", force_block);
			return FALSE;
		}

		dis_printf(L_DEBUG, "Block n°%d obtained\n", force_block);

		return TRUE;
	}

	while(current < 3)
	{
		/* Get the metadata */
		if(!get_metadata((off_t)regions[current].addr + disk_offset, metadata, fd))
		{
			/*
			dis_printf(L_ERROR, "Can't get metadata (n°%d)\n", current+1);
			return FALSE;
			*/
			if (++current >= 3)			//Consider metadata corruption
				return FALSE;
			continue;
		}


		/* Check some small things */


		/* Calculate validations offset */
		validations_offset = 0;
		information = *metadata;
		metadata_size = (unsigned int)(information->version == V_SEVEN ?
		            ((unsigned int)information->size) << 4 : information->size);

		validations_offset = (off_t)regions[current].addr + metadata_size;

		dis_printf(
			L_DEBUG,
			"Reading validations data at offset %#" PRIx64 ".\n",
			validations_offset
		);


		/* Go to the beginning of the BitLocker validation header */
		dis_lseek(fd, validations_offset + disk_offset, SEEK_SET);

		/* Get the validations metadata */
		memset(&validations, 0, sizeof(bitlocker_validations_t));

		ssize_t nb_read = dis_read(fd, &validations, sizeof(bitlocker_validations_t));
		if(nb_read != sizeof(bitlocker_validations_t))
		{
			/*
			dis_printf(L_ERROR, "Error, can't read all validations data.\n");
			return FALSE;
			*/
			if (++current >= 3)		//Consider bad sectors
				return FALSE;
			continue;
		}

		/* Check the validity */
		metadata_crc32 = crc32((unsigned char*)*metadata, metadata_size);

		/*
		 * TODO add the thing with the datum contained in this validation metadata
		 * this provides a better checksum (sha256 hash)
		 *  => This needs the VMK (decrypted)
		 */
		dis_printf(L_DEBUG, "Looking if %#x == %#x for metadata validation\n",
		        metadata_crc32, validations.crc32);

		++current;
		if(metadata_crc32 == validations.crc32)
		{
			dis_printf(L_DEBUG, "We have a winner (n°%d)!\n", current);
			break;
		}
		else
			dis_free(*metadata);
	}

	if(current > 3)
		return FALSE;

	return TRUE;
}


/**
 * Get the EOW information structure one by one, stop at the first valid
 *
 * @param volume_header The volume header structure already taken
 * @param fd The opened file descriptor of the volume
 * @param eow_infos The EOW information resulting of this function
 * @param disk_offset The offset to the beginning of the volume
 * @return TRUE if result can be trusted, FALSE otherwise
 */
static int get_eow_check_valid(
	volume_header_t *volume_header, int fd, void **eow_infos, off_t disk_offset)
{
	// Check parameters
	if(!volume_header || fd < 0 || !eow_infos)
		return FALSE;

	dis_printf(L_DEBUG, "Entering get_eow_check_valid\n");

	bitlocker_eow_infos_t *eow_infos_hdr = NULL;
	unsigned char current = 0;
	unsigned int  eow_infos_size = 0;
	unsigned int  computed_crc32 = 0;
	off_t         curr_offset = 0;
	int           payload_size = 0;

	unsigned char* crc_temp_buffer;

	while(current < 2)
	{
		/* Compute the on-disk offset */
		curr_offset = (off_t)volume_header->eow_information_off[current]
		            + disk_offset;
		++current;

		/* Get the EOW information */
		if(!get_eow_information(curr_offset, eow_infos, fd))
		{
			dis_printf(L_ERROR, "Can't get EOW information (n°%d)\n", current);
			return FALSE;
		}

		eow_infos_hdr = (bitlocker_eow_infos_t*) *eow_infos;


		/* Check some small things */

		/* Check sizes */
		if(eow_infos_hdr->infos_size <= eow_infos_hdr->header_size)
		{
			dis_free(*eow_infos);
			continue;
		}

		/* Check size & number of regions */
		payload_size = eow_infos_hdr->infos_size - eow_infos_hdr->header_size;
		if((payload_size & 7)
			|| eow_infos_hdr->nb_regions != (uint32_t)(payload_size >> 3))
		{
			dis_free(*eow_infos);
			continue;
		}

		/* Check the crc32 validity */
		eow_infos_size = eow_infos_hdr->infos_size;

		crc_temp_buffer = (unsigned char*)dis_malloc(eow_infos_size);
		memcpy(crc_temp_buffer, *eow_infos, eow_infos_size);
		((bitlocker_eow_infos_t*)crc_temp_buffer)->crc32 = 0;
		computed_crc32 = crc32(crc_temp_buffer, eow_infos_size);
		dis_free(crc_temp_buffer);

		dis_printf(L_DEBUG, "Looking if %#x == %#x for EOW information validation\n",
		        computed_crc32, eow_infos_hdr->crc32);

		if(computed_crc32 == eow_infos_hdr->crc32)
		{
			dis_printf(L_DEBUG, "We have a winner (n°%d)!\n", current);
			break;
		}
		else
		{
			dis_free(*eow_infos);
		}
	}

	if(current == 2)
		return FALSE;

	return TRUE;
}


/**
 * Check for dangerous state the BitLocker volume can be in.
 *
 * @param dis_metadata The metadata structure
 * @return TRUE if it's safe to use the volume, FALSE otherwise
 */
int check_state(dis_metadata_t dis_metadata)
{
	// Check parameter
	if(!dis_metadata)
		return FALSE;

	bitlocker_information_t* information = dis_metadata->information;

	char* enc = "enc";
	char* dec = "dec";
	char* unknown = "unknown-";
	char* next_state = NULL;

	if(information->next_state == METADATA_STATE_DECRYPTED)
		next_state = dec;
	else if(information->next_state == METADATA_STATE_ENCRYPTED)
		next_state = enc;
	else
	{
		next_state = unknown;
		dis_printf(L_WARNING,
			"The next state of the volume is currently unknown of " PROGNAME
			", but it would be awesome if you could spare some time to report "
			"this state (%d) to the author and how did you do to have this. "
			"Many thanks.\n",
			information->next_state
		);
	}

	switch(information->curr_state)
	{
		case METADATA_STATE_SWITCHING_ENCRYPTION:
			dis_printf(L_ERROR,
				"The volume is currently being %srypted, which is an unstable "
				"state. If you know what you're doing, pass `-s' to the command"
				" line, but be aware it may result in data corruption.\n",
				next_state
			);
			return FALSE;
		case METADATA_STATE_SWITCH_ENCRYPTION_PAUSED:
			dis_printf(L_WARNING,
				"The volume is currently in a secure state, "
				"but don't resume the %sryption while using " PROGNAME " for "
				"the volume would become instable, resulting in data "
				"corruption.\n",
				next_state
			);
			break;
		case METADATA_STATE_DECRYPTED:
			dis_printf(L_WARNING,
				"The disk is about to get encrypted. Using " PROGNAME " while "
				"encrypting the disk in parallel, this may corrupt your data.\n"
			);
	}

	return TRUE;
}


void dis_metadata_vista_vbr_fve2ntfs(dis_metadata_t dis_meta, void* vbr)
{
	if(!dis_meta || !vbr)
		return;

	volume_header_t* volume_header = (volume_header_t*) vbr;

	dis_printf(
		L_DEBUG,
		"  Fixing sector (Vista): replacing signature "
		"and MFTMirror field by: %#" PRIx64 "\n",
		dis_meta->volume_header->mft_mirror
	);


	/* This is for the NTFS signature */
	memcpy(volume_header->signature, NTFS_SIGNATURE, NTFS_SIGNATURE_SIZE);

	/* And this is for the MFT Mirror field */
	volume_header->mft_mirror = dis_metadata_mftmirror(dis_meta);
}


void dis_metadata_vista_vbr_ntfs2fve(dis_metadata_t dis_meta, void* vbr)
{
	if(!dis_meta || !vbr)
		return;

	volume_header_t* volume_header = (volume_header_t*) vbr;

	/* This is for the BitLocker signature */
	memcpy(
		volume_header->signature,
		BITLOCKER_SIGNATURE,
		BITLOCKER_SIGNATURE_SIZE
	);

	/* And this is for the metadata LCN */
	volume_header->metadata_lcn =
		dis_meta->information->information_off[0] /
		(uint64_t)(
			volume_header->sectors_per_cluster *
			volume_header->sector_size
		);

	dis_printf(
		L_DEBUG,
		"  Fixing sector (Vista): replacing signature "
		"and MFTMirror field by: %#" PRIx64 "\n",
		volume_header->metadata_lcn
	);
}


int dis_metadata_is_overwritten(
	dis_metadata_t dis_meta, off_t offset, size_t size)
{
	if(!dis_meta)
		return DIS_RET_ERROR_DISLOCKER_INVAL;

	off_t metadata_offset = 0;
	off_t metadata_size   = 0;
	size_t virt_loop      = 0;

	for(virt_loop = 0; virt_loop < dis_meta->nb_virt_region; virt_loop++)
	{
		metadata_size = (off_t)dis_meta->virt_region[virt_loop].size;
		if(metadata_size == 0)
			continue;

		metadata_offset = (off_t)dis_meta->virt_region[virt_loop].addr;

		if(offset >= metadata_offset &&
		   offset < metadata_offset + metadata_size)
		{
			dis_printf(L_DEBUG, "In metadata file (1:%#"
			        F_OFF_T ")\n", offset);
			return DIS_RET_ERROR_METADATA_FILE_OVERWRITE;
		}

		if(offset < metadata_offset &&
		   offset + (off_t)size > metadata_offset)
		{
			dis_printf(L_DEBUG, "In metadata file (2:%#"
			        F_OFF_T "+ %#" F_SIZE_T ")\n", offset, size);
			return DIS_RET_ERROR_METADATA_FILE_OVERWRITE;
		}
	}

	return DIS_RET_SUCCESS;
}


/**
 * Retrieve the volume size from the first sector.
 *
 * @param volume_header The partition MBR to look at. NTFS or FVE, np
 * @return The volume size or 0, which indicates the size couldn't be retrieved
 */
uint64_t dis_metadata_volume_size_from_vbr(dis_metadata_t dis_meta)
{
	if(!dis_meta)
		return 0;

	volume_header_t* volume_header = dis_meta->volume_header;
	uint64_t volume_size = 0;

	if(volume_header->nb_sectors_16b)
	{
		volume_size = (uint64_t)volume_header->sector_size
		                         * volume_header->nb_sectors_16b;
	}
	else if(volume_header->nb_sectors_32b)
	{
		volume_size = (uint64_t)volume_header->sector_size
		                         * volume_header->nb_sectors_32b;
	}
	else if(volume_header->nb_sectors_64b)
	{
		volume_size = (uint64_t)volume_header->sector_size
		                         * volume_header->nb_sectors_64b;
	}

	return volume_size;
}


void* dis_metadata_set_dataset(dis_metadata_t dis_meta, void* new_dataset)
{
	if(!dis_meta)
		return NULL;

	if(!new_dataset)
		return dis_meta->dataset;

	void* old_dataset = dis_meta->dataset;
	dis_meta->dataset = new_dataset;
	return old_dataset;
}


void* dis_metadata_set_volume_header(dis_metadata_t dis_meta, void* new_volume_header)
{
	if(!dis_meta)
		return NULL;

	if(!new_volume_header)
		return dis_meta->volume_header;

	void* old_volume_header = dis_meta->volume_header;
	dis_meta->volume_header = new_volume_header;
	return old_volume_header;
}


uint16_t dis_metadata_sector_size(dis_metadata_t dis_meta)
{
	return dis_meta->volume_header->sector_size;
}


version_t dis_metadata_information_version(dis_metadata_t dis_meta)
{
	return dis_meta->information->version;
}


uint64_t dis_metadata_encrypted_volume_size(dis_metadata_t dis_meta)
{
	return dis_meta->information->encrypted_volume_size;
}

uint64_t dis_metadata_ntfs_sectors_address(dis_metadata_t dis_meta)
{
	return dis_meta->information->boot_sectors_backup;
}
uint64_t dis_metadata_mftmirror(dis_metadata_t dis_meta)
{
	return dis_meta->information->mftmirror_backup;
}


uint32_t dis_metadata_backup_sectors_count(dis_metadata_t dis_meta)
{
	return dis_meta->information->nb_backup_sectors;
}

int dis_metadata_is_decrypted_state(dis_metadata_t dis_meta) {
	return dis_meta->information->curr_state == METADATA_STATE_DECRYPTED;
}

#ifdef _HAVE_RUBY
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


static VALUE rb_cDislockerMetadata_has_clearkey(VALUE self)
{
	void* vmk_datum = NULL;
	dis_metadata_t dis_meta = DATA_PTR(self);

	if(dis_metadata_has_clear_key(dis_meta, &vmk_datum) == TRUE &&
	   vmk_datum != NULL)
	{
		return Qtrue;
	}

	return Qfalse;
}


static void rb_cDislockerMetadata_free(dis_metadata_t dis_meta)
{
	dis_close(dis_meta->cfg->fve_fd);
	if(dis_metadata_destroy(dis_meta) != DIS_RET_SUCCESS)
	{
		rb_raise(
			rb_eRuntimeError,
		   "Wrong metadata, object cannot be cleanly freed."
		);
	}
}

static VALUE rb_cDislockerMetadata_alloc(VALUE klass)
{
	dis_metadata_t dis_meta = NULL;

	return Data_Wrap_Struct(
		klass,
		NULL,
		rb_cDislockerMetadata_free,
		dis_meta
	);
}

static VALUE rb_cDislockerMetadata_init(int argc, VALUE *argv, VALUE self)
{
	int fd = -1;
	char cForceBlock = 0;
	dis_metadata_config_t dis_meta_cfg = NULL;

	if(argc < 1)
	{
		rb_raise(
			rb_eArgError,
		   "initialize: fvevol_path [offset] [force_block]"
		);
	}

	Check_Type(argv[0], T_STRING);
	fd = open(StringValuePtr(argv[0]), O_RDWR|O_LARGEFILE);

	dis_meta_cfg = dis_metadata_config_new();
	dis_meta_cfg->fve_fd = fd;

	if(argc > 1)
	{
		Check_Type(argv[1], T_FIXNUM);
		dis_meta_cfg->offset = NUM2OFFT(argv[1]);
	}

	if(argc > 2)
	{
		Check_Type(argv[2], T_FIXNUM);
		cForceBlock = (char) NUM2CHR(argv[2]);
		if(cForceBlock >= 1 && cForceBlock <= 3)
			dis_meta_cfg->force_block = (unsigned char) cForceBlock;
		else
			dis_meta_cfg->force_block = 0;
	}

	DATA_PTR(self) = dis_metadata_new(dis_meta_cfg);

	if(dis_metadata_initialize(DATA_PTR(self)) != DIS_RET_SUCCESS)
		rb_raise(rb_eRuntimeError, "Couldn't retrieve metadata");

	return Qnil;
}

void Init_metadata(VALUE rb_mDislocker)
{
	VALUE rb_cDislockerMetadata = rb_define_class_under(
		rb_mDislocker,
		"Metadata",
		rb_cObject
	);
	extern VALUE dis_rb_classes[DIS_RB_CLASS_MAX];
	dis_rb_classes[DIS_RB_CLASS_METADATA] = rb_cDislockerMetadata;

	rb_define_alloc_func(rb_cDislockerMetadata, rb_cDislockerMetadata_alloc);
	rb_define_method(
		rb_cDislockerMetadata,
		"initialize",
		rb_cDislockerMetadata_init,
		-1
	);

	rb_define_method(
		rb_cDislockerMetadata,
		"has_clearkey?",
		rb_cDislockerMetadata_has_clearkey,
		0
	);


	Init_datum(rb_cDislockerMetadata);
	Init_guid(rb_cDislockerMetadata);
}
#endif /* _HAVE_RUBY */
