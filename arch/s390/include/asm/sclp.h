/*
 *    Copyright IBM Corp. 2007
 *    Author(s): Heiko Carstens <heiko.carstens@de.ibm.com>
 */

#ifndef _ASM_S390_SCLP_H
#define _ASM_S390_SCLP_H

#include <linux/types.h>
#include <asm/chpid.h>
#include <asm/cpu.h>

#define SCLP_CHP_INFO_MASK_SIZE		32

struct sclp_chp_info {
	u8 recognized[SCLP_CHP_INFO_MASK_SIZE];
	u8 standby[SCLP_CHP_INFO_MASK_SIZE];
	u8 configured[SCLP_CHP_INFO_MASK_SIZE];
};

#define LOADPARM_LEN 8

struct sclp_ipl_info {
	int is_valid;
	int has_dump;
	char loadparm[LOADPARM_LEN];
};

struct sclp_cpu_entry {
	u8 core_id;
	u8 reserved0;
	u8 : 4;
	u8 sief2 : 1;
	u8 : 3;
	u8 : 3;
	u8 siif : 1;
	u8 : 4;
	u8 reserved2[10];
	u8 type;
	u8 reserved1;
} __attribute__((packed));

struct sclp_cpu_info {
	unsigned int configured;
	unsigned int standby;
	unsigned int combined;
	int has_cpu_type;
	struct sclp_cpu_entry cpu[MAX_CPU_ADDRESS + 1];
};

struct zpci_report_error_header {
	u8 version;	/* Interface version byte */
	u8 action;	/* Action qualifier byte
			 * 0: Adapter Reset Request
			 * 1: Deconfigure and repair action requested
			 *	(OpenCrypto Problem Call Home)
			 * 2: Informational Report
			 *	(OpenCrypto Successful Diagnostics Execution)
			 */
	u16 length;	/* Length of Subsequent Data (up to 4K – SCLP header */
	u8 data[0];	/* Subsequent Data passed verbatim to SCLP ET 24 */
} __packed;

int sclp_get_cpu_info(struct sclp_cpu_info *info);
int sclp_cpu_configure(u8 cpu);
int sclp_cpu_deconfigure(u8 cpu);
unsigned long long sclp_get_rnmax(void);
unsigned long long sclp_get_rzm(void);
unsigned int sclp_get_max_cpu(void);
unsigned int sclp_get_mtid(u8 cpu_type);
unsigned int sclp_get_mtid_max(void);
unsigned int sclp_get_mtid_prev(void);
int sclp_sdias_blk_count(void);
int sclp_sdias_copy(void *dest, int blk_num, int nr_blks);
int sclp_chp_configure(struct chp_id chpid);
int sclp_chp_deconfigure(struct chp_id chpid);
int sclp_chp_read_info(struct sclp_chp_info *info);
void sclp_get_ipl_info(struct sclp_ipl_info *info);
bool __init sclp_has_linemode(void);
bool __init sclp_has_vt220(void);
int sclp_pci_configure(u32 fid);
int sclp_pci_deconfigure(u32 fid);
int sclp_pci_report(struct zpci_report_error_header *report, u32 fh, u32 fid);
int memcpy_hsa(void *dest, unsigned long src, size_t count, int mode);
unsigned long sclp_get_hsa_size(void);
void sclp_early_detect(void);
int sclp_has_siif(void);
int sclp_has_sief2(void);
int sclp_has_diag318(void);
void sclp_ocf_cpc_name_copy(char *dst);

#endif /* _ASM_S390_SCLP_H */
