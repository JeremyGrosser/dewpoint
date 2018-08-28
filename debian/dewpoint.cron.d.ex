#
# Regular cron jobs for the dewpoint package
#
0 4	* * *	root	[ -x /usr/bin/dewpoint_maintenance ] && /usr/bin/dewpoint_maintenance
