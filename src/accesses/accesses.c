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


#include "dislocker/dislocker.priv.h"
#include "dislocker/accesses/accesses.h"
#include "dislocker/accesses/bek/bekfile.h"
#include "dislocker/accesses/rp/recovery_password.h"
#include "dislocker/accesses/user_pass/user_pass.h"

#include "dislocker/metadata/vmk.h"
#include "dislocker/metadata/fvek.h"

#include "dislocker/return_values.h"


int dis_get_access(dis_context_t dis_ctx)
{
	void* vmk_datum = NULL;
	void* fvek_datum = NULL;

	datum_key_t* fvek_typed_datum = NULL;


	/*
	 * First, get the VMK datum using either any necessary mean
	 */
	while(dis_ctx->cfg.decryption_mean)
	{
		if(dis_ctx->cfg.decryption_mean & DIS_USE_CLEAR_KEY)
		{
			if(!get_vmk_from_clearkey(dis_ctx->metadata, &vmk_datum))
			{
				dis_ctx->cfg.decryption_mean &= (unsigned) ~DIS_USE_CLEAR_KEY;
			}
			else
			{
				dis_printf(L_INFO, "Used clear key decryption method\n");
				dis_ctx->cfg.decryption_mean = DIS_USE_CLEAR_KEY;
				break;
			}
		}
		else if(dis_ctx->cfg.decryption_mean & DIS_USE_USER_PASSWORD)
		{
			if(!get_vmk_from_user_pass(dis_ctx->metadata, &dis_ctx->cfg, &vmk_datum))
			{
				dis_ctx->cfg.decryption_mean &= (unsigned) ~DIS_USE_USER_PASSWORD;
			}
			else
			{
				dis_printf(L_INFO, "Used user password decryption method\n");
				dis_ctx->cfg.decryption_mean = DIS_USE_USER_PASSWORD;
				break;
			}
		}
		else if(dis_ctx->cfg.decryption_mean & DIS_USE_RECOVERY_PASSWORD)
		{
			if(!get_vmk_from_rp(dis_ctx->metadata, &dis_ctx->cfg, &vmk_datum))
			{
				dis_ctx->cfg.decryption_mean &= (unsigned) ~DIS_USE_RECOVERY_PASSWORD;
			}
			else
			{
				dis_printf(L_INFO, "Used recovery password decryption method\n");
				dis_ctx->cfg.decryption_mean = DIS_USE_RECOVERY_PASSWORD;
				break;
			}
		}
		else if(dis_ctx->cfg.decryption_mean & DIS_USE_BEKFILE)
		{
			if(!get_vmk_from_bekfile(dis_ctx->metadata, &dis_ctx->cfg, &vmk_datum))
			{
				dis_ctx->cfg.decryption_mean &= (unsigned) ~DIS_USE_BEKFILE;
			}
			else
			{
				dis_printf(L_INFO, "Used bek file decryption method\n");
				dis_ctx->cfg.decryption_mean = DIS_USE_BEKFILE;
				break;
			}
		}
		else if(dis_ctx->cfg.decryption_mean & DIS_USE_FVEKFILE)
		{
			if(!build_fvek_from_file(&dis_ctx->cfg, &fvek_datum))
			{
				dis_ctx->cfg.decryption_mean &= (unsigned) ~DIS_USE_FVEKFILE;
			}
			else
			{
				dis_printf(L_INFO, "Used FVEK file decryption method\n");
				dis_ctx->cfg.decryption_mean = DIS_USE_FVEKFILE;
				break;
			}
		}
		else
		{
			dis_printf(L_CRITICAL, "Wtf!? Abort.\n");
			return EXIT_FAILURE;
		}
	}

	if(!dis_ctx->cfg.decryption_mean)
	{
		dis_printf(
			L_CRITICAL,
			"None of the provided decryption mean is "
			"decrypting the keys. Abort.\n"
		);
		return DIS_RET_ERROR_VMK_RETRIEVAL;
	}

	dis_ctx->io_data.vmk = vmk_datum;

	checkupdate_dis_state(dis_ctx, DIS_STATE_AFTER_VMK);


	/*
	 * NOTE -- We could here validate the information buffer in a more precise
	 * way using the VMK and the validations structure (the one after the
	 * information one, see bitlocker_validations_t in metadata/metadata.h)
	 *
	 * NOTE -- We could here get all of the other key a user could use
	 * using the VMK and the reverse encrypted data
	 */


	/*
	 * And then, use the VMK to decrypt the FVEK
	 */
	if(dis_ctx->cfg.decryption_mean != DIS_USE_FVEKFILE)
	{
		if(!get_fvek(dis_ctx->metadata, vmk_datum, &fvek_datum))
			return DIS_RET_ERROR_FVEK_RETRIEVAL;
	}


	/* Just a check of the algo used to crypt data here */
	fvek_typed_datum = (datum_key_t*) fvek_datum;
	fvek_typed_datum->algo &= 0xffff;

	if(fvek_typed_datum->algo < AES_128_DIFFUSER ||
	   fvek_typed_datum->algo > AES_256_NO_DIFFUSER)
	{
		dis_printf(
			L_CRITICAL,
			"Can't recognize the encryption algorithm used: %#hx. Abort\n",
			fvek_typed_datum->algo
		);
		return DIS_RET_ERROR_CRYPTO_ALGORITHM_UNSUPPORTED;
	}

	dis_ctx->io_data.fvek = fvek_typed_datum;

	checkupdate_dis_state(dis_ctx, DIS_STATE_AFTER_FVEK);

	return DIS_RET_SUCCESS;
}
