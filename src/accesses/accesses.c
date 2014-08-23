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


#include "accesses.h"
#include "bek/bekfile.h"
#include "rp/recovery_password.h"
#include "user_pass/user_pass.h"

#include "metadata/vmk.h"
#include "metadata/fvek.h"


int dis_get_access(dis_context_t* dis_ctx, bitlocker_dataset_t* dataset)
{
	void* vmk_datum = NULL;
	void* fvek_datum = NULL;
	
	datum_key_t* fvek_typed_datum = NULL;
	
	
	/*
	 * First, get the VMK datum using either any necessary mean
	 */
	while(dis_ctx->cfg.decryption_mean)
	{
		if(dis_ctx->cfg.decryption_mean & USE_CLEAR_KEY)
		{
			if(!get_vmk_from_clearkey(dataset, &vmk_datum))
			{
				dis_ctx->cfg.decryption_mean &= (unsigned) ~USE_CLEAR_KEY;
			}
			else
			{
				xprintf(L_INFO, "Used clear key decryption method\n");
				dis_ctx->cfg.decryption_mean = USE_CLEAR_KEY;
				break;
			}
		}
		else if(dis_ctx->cfg.decryption_mean & USE_USER_PASSWORD)
		{
			if(!get_vmk_from_user_pass(dataset, &dis_ctx->cfg, &vmk_datum))
			{
				dis_ctx->cfg.decryption_mean &= (unsigned) ~USE_USER_PASSWORD;
			}
			else
			{
				xprintf(L_INFO, "Used user password decryption method\n");
				dis_ctx->cfg.decryption_mean = USE_USER_PASSWORD;
				break;
			}
		}
		else if(dis_ctx->cfg.decryption_mean & USE_RECOVERY_PASSWORD)
		{
			if(!get_vmk_from_rp(dataset, &dis_ctx->cfg, &vmk_datum))
			{
				dis_ctx->cfg.decryption_mean &= (unsigned) ~USE_RECOVERY_PASSWORD;
			}
			else
			{
				xprintf(L_INFO, "Used recovery password decryption method\n");
				dis_ctx->cfg.decryption_mean = USE_RECOVERY_PASSWORD;
				break;
			}
		}
		else if(dis_ctx->cfg.decryption_mean & USE_BEKFILE)
		{
			if(!get_vmk_from_bekfile(dataset, &dis_ctx->cfg, &vmk_datum))
			{
				dis_ctx->cfg.decryption_mean &= (unsigned) ~USE_BEKFILE;
			}
			else
			{
				xprintf(L_INFO, "Used bek file decryption method\n");
				dis_ctx->cfg.decryption_mean = USE_BEKFILE;
				break;
			}
		}
		else if(dis_ctx->cfg.decryption_mean & USE_FVEKFILE)
		{
			if(!build_fvek_from_file(&dis_ctx->cfg, &fvek_datum))
			{
				dis_ctx->cfg.decryption_mean &= (unsigned) ~USE_FVEKFILE;
			}
			else
			{
				xprintf(L_INFO, "Used FVEK file decryption method\n");
				dis_ctx->cfg.decryption_mean = USE_FVEKFILE;
				break;
			}
		}
		else
		{
			xprintf(L_CRITICAL, "Wtf!? Abort.\n");
			dis_destroy(dis_ctx);
			return EXIT_FAILURE;
		}
	}
	
	if(!dis_ctx->cfg.decryption_mean)
	{
		xprintf(
			L_CRITICAL,
			"None of the provided decryption mean is "
			"decrypting the keys. Abort.\n"
		);
		dis_destroy(dis_ctx);
		return EXIT_FAILURE;
	}
	
	dis_ctx->io_data.vmk = vmk_datum;
	
	checkupdate_dis_state(dis_ctx, AFTER_VMK);
	
	
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
	if(dis_ctx->cfg.decryption_mean != USE_FVEKFILE)
	{
		if(!get_fvek(dataset, vmk_datum, &fvek_datum))
		{
			dis_destroy(dis_ctx);
			return EXIT_FAILURE;
		}
	}
	
	
	/* Just a check of the algo used to crypt data here */
	fvek_typed_datum = (datum_key_t*) fvek_datum;
	fvek_typed_datum->algo &= 0xffff;
	
	if(fvek_typed_datum->algo < AES_128_DIFFUSER ||
	   fvek_typed_datum->algo > AES_256_NO_DIFFUSER)
	{
		xprintf(
			L_CRITICAL,
			"Can't recognize the encryption algorithm used: %#x. Abort\n",
			fvek_typed_datum->algo
		);
		dis_destroy(dis_ctx);
		return EXIT_FAILURE;
	}
	
	dis_ctx->io_data.fvek = fvek_typed_datum;
	
	checkupdate_dis_state(dis_ctx, AFTER_FVEK);
	
	return EXIT_SUCCESS;
}
