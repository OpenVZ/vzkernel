#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/printk.h>

/* Display a shadowman logo on the console screen */
static int __init rh_shadowman(char *str)
{
	pr_info("RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR\n");
	pr_info("RRRRRRRRRRRRRRRRRRrrrrrrrrrrrrrrrORHRrrHRRRRRRRRRRRRRRRRRRRR\n");
	pr_info("RRRRRRRRRRRRRRRRHrr8rrrrrrrrrrrrrrrrrrrrhRRRRRRRRRRRRRRRRRRR\n");
	pr_info("RRRRRHRRRRRRRRRRRrrHRHRRRHHHrrrrrrrrrrrrrHRRRRRRRRRRRRRRRRRR\n");
	pr_info("RRRRRRRRRRRRRRRHrrrrrHrrrrrrrrrrrrrrrrrrrrRRRRRRRRRRRRRRRRRR\n");
	pr_info("RRRRRRRRRHh88hhRHrrrrrrrrrrrrrrrrrrrrrrrrrrHRRRRRRRRRRRRRRRR\n");
	pr_info("RRRRRRrrrrrrrrrRHRH8rrrrrrrrrrrrrrrrrrrrrrr8RRRRRRRRRRRRRRRR\n");
	pr_info("RRRRH8rrrrrrrrrrRHRRRRRRRRRHrrrrrrrrrrrrrrrrRrhHRHRRRRRRRRRR\n");
	pr_info("RRRRRROrrrrrrrrrrrORRRRRRRRRRRrrrrrrrrrrrrrHrrrrrrhRRRRRRRRR\n");
	pr_info("RRRRRRRROrrrrrrrrrrrrrrr8RRRRHRrrrrrrrrrrrrrrrrrrrrrHRRRRRRR\n");
	pr_info("RRRRRRRRRRRRRHhrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrRRRRRRRR\n");
	pr_info("RRRRRRRRRRRRH. .HHHrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrRRRRRRRRR\n");
	pr_info("RRRRRRRRRRRR.    .RRhRRHH8rrrrrrrrrrrrrrrrrrrrr8RRRRRRRRRRRR\n");
	pr_info("RRRRRRRRRRRRR~       .RRRRRRRRRHHh8OOOOO8HRRHRRRRRRRRRRRRRRR\n");
	pr_info("R,````      RRR8        .hHRRRh\\hHH:=HRh.RRRRRRRRRRRRRRRRRR\n");
	pr_info("RR                                       ORRRRRRRRRRRRRRRRRR\n");
	pr_info("RRR                           ,HHtaa     HRRRRRRRRRRRRRRRRRR\n");
	pr_info("RRRRO.                                 .RRRRO. .    .RRRRRRR\n");
	pr_info("RRRRRR                                ,RRHh,       :RRRRRRRR\n");
	pr_info("RRRRRRRR                             HRR         :RRRRRRRRRR\n");
	pr_info("RRRRRRRRRRr                         ..        ,RRRRRRRRRRRRR\n");
	pr_info("RRRRRRRRRRRRRt .                           .HRRRRRRRRRRRRRRR\n");
	pr_info("RRRRRRRRRRRRRRRRRr.                    =RRRRRRRRRRRRRRRRRRRR\n");
	pr_info("RRRRRRRRRRRRRRRRRRRRRRRRHHr: .:tRhRRRRRRRRRRRRRRRRRRRRRRRRRR\n");
	return 1;
}

__setup("shadowman", rh_shadowman);
