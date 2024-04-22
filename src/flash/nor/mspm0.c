// SPDX-License-Identifier: GPL-2.0-or-later

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <helper/bits.h>
#include "imp.h"

#define FLASHCTL_BASE		(0x400CD000UL)
#define FLASHCTL_CMDEXEC	(FLASHCTL_BASE + 0x1100)
#define FLASHCTL_CMDTYPE	(FLASHCTL_BASE + 0x1104)
#define FLASHCTL_CMDADDR	(FLASHCTL_BASE + 0x1120)
#define FLASHCTL_CMDBYTEN	(FLASHCTL_BASE + 0x1124)
#define FLASHCTL_CMDDATA0	(FLASHCTL_BASE + 0x1130)
#define FLASHCTL_CMDDATA1	(FLASHCTL_BASE + 0x1134)
#define FLASHCTL_CMDWEPROTA	(FLASHCTL_BASE + 0x11D0)
#define FLASHCTL_CMDWEPROTB	(FLASHCTL_BASE + 0x11D4)
#define FLASHCTL_CMDWEPROTC	(FLASHCTL_BASE + 0x11D8)
#define FLASHCTL_STATCMD	(FLASHCTL_BASE + 0x13D0)

#define CMDTYPE_SIZE_SECTOR	(0x04 << 3)
#define CMDTYPE_SIZE_WORD	(0x00 << 3) // one word of flash is 64 bits

#define CMDTYPE_COMMAND_NOOP			0x00
#define CMDTYPE_COMMAND_PROGRAM			0x01
#define CMDTYPE_COMMAND_ERASE			0x02
#define CMDTYPE_COMMAND_READ_VERIFY		0x03
#define CMDTYPE_COMMAND_BLANK_VERIFY	0x04

#define STATCMD_FAILMISC		BIT(12)
#define STATCMD_FAILMODE		BIT(7)
#define STATCMD_FAILILLADDR		BIT(6)
#define STATCMD_FAILVERIFY		BIT(5)
#define STATCMD_FAILWEPROT		BIT(4)
#define STATCMD_CMDINPROGRESS	BIT(2)
#define STATCMD_CMDPASS			BIT(1)
#define STATCMD_CMDDONE			BIT(0)

#define CPUSS_BASE	(0x40400000)
#define CPUSS_CTL	(CPUSS_BASE + 0x1300)
#define SECTOR_SIZE	1024

FLASH_BANK_COMMAND_HANDLER(mspm0_flash_bank_command)
{
	bank->sectors = NULL;
	return ERROR_OK;
}

static int mspm0_unprotect_sector(struct flash_bank *bank, uint32_t sector)
{
	struct target *target = bank->target;
	int err;

	if (sector < 32)
		err = target_write_u32(target, FLASHCTL_CMDWEPROTA, ~BIT(sector));
	else if (sector < (32 + 256))
		err = target_write_u32(target, FLASHCTL_CMDWEPROTB, ~BIT((sector - 32) / 8));
	else
		err = target_write_u32(target, FLASHCTL_CMDWEPROTC, ~BIT((sector - 288) / 8));

	return err;
}

static int mspm0_protect_main(struct flash_bank *bank)
{
	struct target *target = bank->target;
	int err;

	err = target_write_u32(target, FLASHCTL_CMDWEPROTA, 0xffffffff);
	if (err != ERROR_OK)
		return err;

	err = target_write_u32(target, FLASHCTL_CMDWEPROTB, 0xffffffff);
	if (err != ERROR_OK)
		return err;

	err = target_write_u32(target, FLASHCTL_CMDWEPROTC, 0xffffffff);
	return err;
}

static int mspm0_disable_cache(struct flash_bank *bank)
{
	return target_write_u32(bank->target, CPUSS_CTL, 0);
}

static int mspm0_enable_cache(struct flash_bank *bank)
{
	return target_write_u32(bank->target, CPUSS_CTL, 0x7);
}

static int mspm0_flash_wait(struct flash_bank *bank)
{
	struct target *target = bank->target;
	uint32_t statcmd;

	do {
		target_read_u32(target, FLASHCTL_STATCMD, &statcmd);
	} while ((statcmd & STATCMD_CMDDONE) == 0);

	if (statcmd & STATCMD_FAILWEPROT)
		return ERROR_FLASH_PROTECTED;

	if (statcmd & (STATCMD_FAILVERIFY | STATCMD_FAILMISC))
		return ERROR_FLASH_OPERATION_FAILED;

	if (statcmd & STATCMD_FAILILLADDR)
		return ERROR_FLASH_SECTOR_INVALID;

	if (statcmd & STATCMD_FAILMODE)
		return ERROR_FLASH_BUSY;

	if (statcmd != (STATCMD_CMDDONE | STATCMD_CMDPASS))
		return ERROR_FLASH_OPERATION_FAILED;

	return ERROR_OK;
}

int mspm0_erase(struct flash_bank *bank, unsigned int first, unsigned int last)
{
	struct target *target = bank->target;
	int err;

	err = mspm0_disable_cache(bank);
	if (err != ERROR_OK)
		return err;

	for (unsigned int sector = first; sector <= last; sector++) {
		err = mspm0_unprotect_sector(bank, (uint32_t)sector);
		if (err != ERROR_OK)
			return err;

		err = target_write_u32(target, FLASHCTL_CMDTYPE, CMDTYPE_SIZE_SECTOR | CMDTYPE_COMMAND_ERASE);
		if (err != ERROR_OK)
			return err;

		err = target_write_u32(target, FLASHCTL_CMDADDR, bank->base + bank->sectors[sector].offset);
		if (err != ERROR_OK)
			return err;

		err = target_write_u32(target, FLASHCTL_CMDEXEC, 1);
		if (err != ERROR_OK)
			return err;

		err = mspm0_flash_wait(bank);
		if (err != ERROR_OK)
			return err;
	}

	err = mspm0_protect_main(bank);
	return err;
}

static int mspm0_write_word(struct flash_bank *bank, uint32_t addr, uint32_t *data)
{
	struct target *target = bank->target;
	int err;

	err = mspm0_unprotect_sector(bank, addr / SECTOR_SIZE);
	if (err != ERROR_OK)
		return err;

	err = target_write_u32(target, FLASHCTL_CMDTYPE, CMDTYPE_SIZE_WORD | CMDTYPE_COMMAND_PROGRAM);
	if (err != ERROR_OK)
		return err;

	err = target_write_u32(target, FLASHCTL_CMDADDR, addr);
	if (err != ERROR_OK)
		return err;

	err = target_write_u32(target, FLASHCTL_CMDBYTEN, 0xFFFFFFFF);
	if (err != ERROR_OK)
		return err;

	err = target_write_u32(target, FLASHCTL_CMDDATA0, data[0]);
	if (err != ERROR_OK)
		return err;

	err = target_write_u32(target, FLASHCTL_CMDDATA1, data[1]);
	if (err != ERROR_OK)
		return err;

	err = target_write_u32(target, FLASHCTL_CMDEXEC, 1);
	if (err != ERROR_OK)
		return err;

	err = mspm0_flash_wait(bank);
	return err;
}

int mspm0_write(struct flash_bank *bank, const uint8_t *buffer, uint32_t offset, uint32_t count)
{
	uint32_t data[2];
	int err;

	err = mspm0_erase(bank, offset / SECTOR_SIZE, (offset + count) / SECTOR_SIZE);
	if (err != ERROR_OK)
		return err;

	err = mspm0_disable_cache(bank);
	if (err != ERROR_OK)
		return err;

	for (uint32_t i = 0; i < count; i += 8) {
		memcpy(data, buffer + i, 8);
		err = mspm0_write_word(bank, offset + i, data);
		if (err != ERROR_OK)
			return err;
	}

	err = mspm0_protect_main(bank);
	if (err != ERROR_OK)
		return err;

	err = mspm0_enable_cache(bank);
	return err;
}

static int mspm0_check_device_info(uint32_t device_id, uint32_t user_id)
{
	/* check ALWAYS_1 and START bits are set before anything else */
	if (!(device_id & BIT(0)) || !(user_id & BIT(31)))
		return ERROR_FAIL;

	uint32_t family_id = device_id & 0x0FFFFFFE;
	const char *family_str = NULL;

	/* family definitions extracted from CCS .gel files */
	switch (family_id) {
	case 0x0BB8202E:
		family_str = "MSPM0L11xx/MSPM0L13xx";
		break;
	case 0x0BB8802E:
		family_str = "MSPM0G1x0x/MSPM0G3x0x";
		break;
	case 0x0BB9F02E:
		family_str = "MSPM0L122x/MSPM0L222x";
		break;
	case 0x0BBA102E:
		family_str = "MSPM0C110x";
		break;
	default:
		LOG_ERROR("Unknown MSPM0 family 0x%08" PRIx32 "", family_id);
		return ERROR_FAIL;
	}

	uint32_t version = (device_id >> 28);
	uint32_t major_rev = (user_id >> 28) & 0x7;
	uint32_t minor_rev = (user_id >> 24) & 0xF;
	uint32_t variant = (user_id >> 16) & 0xFF;
	uint32_t part = user_id & 0xFFFF;

	LOG_INFO("Identified %s, version %d, rev %d.%d, part 0x%04" PRIx16 ", variant 0x%02" PRIx8 "",
			family_str,
			(int)(version),
			(int)(major_rev),
			(int)(minor_rev),
			part,
			variant);

	return ERROR_OK;
}

int mspm0_probe(struct flash_bank *bank)
{
	struct target *target = bank->target;
	uint32_t sram_flash, device_id, user_id;
	int err;

	err = target_read_u32(target, 0x41C40004, &device_id);
	if (err != ERROR_OK)
		return err;

	err = target_read_u32(target, 0x41C40008, &user_id);
	if (err != ERROR_OK)
		return err;

	LOG_DEBUG("mspm0 read factory DEVICEID = 0x%08" PRIx32 " USERID = 0x%08" PRIx32 "", device_id, user_id);

	err = mspm0_check_device_info(device_id, user_id);
	if (err != ERROR_OK)
		return err;

	bank->bank_number = 0;
	bank->base = 0x00000000;
	bank->chip_width = 8;
	bank->bus_width = 4;

	err = target_read_u32(target, 0x41C40018, &sram_flash);
	if (err != ERROR_OK)
		return err;

	bank->size = (sram_flash & 0xFFF) * 1024;
	bank->num_sectors = bank->size / SECTOR_SIZE;

	bank->sectors = malloc(sizeof(struct flash_sector) * bank->num_sectors);
	if (!bank->sectors)
		return ERROR_FAIL;

	for (unsigned int sector = 0; sector < bank->num_sectors; sector++) {
		bank->sectors[sector] = (struct flash_sector){
			.offset = bank->base + (SECTOR_SIZE * sector),
			.size = SECTOR_SIZE,
			.is_erased = false,
			.is_protected = false,
		};
	}

	bank->num_prot_blocks = 0;
	bank->next = NULL;

	return ERROR_OK;
}

int mspm0_auto_probe(struct flash_bank *bank)
{
	if (bank->sectors)
		return ERROR_OK;

	return mspm0_probe(bank);
}

const struct flash_driver mspm0_flash = {
	.name				= "mspm0",
	.commands			= NULL,
	.flash_bank_command	= mspm0_flash_bank_command,
	.erase				= mspm0_erase,
	.protect			= NULL,
	.write				= mspm0_write,
	.read				= default_flash_read,
	.verify				= default_flash_verify,
	.probe				= mspm0_probe,
	.erase_check		= default_flash_blank_check,
	.protect_check		= NULL,
	.info				= NULL,
	.auto_probe			= mspm0_auto_probe,
	.free_driver_priv	= default_flash_free_driver_priv,
};
