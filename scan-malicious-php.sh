#!/bin/bash
# Script find malicious string in code file
# Author : Quach Chi Cuong
# Version : 1
# Updated : 11/08/2016


### Variable to set
## Directory to scan, you can use with $1 variable
DIR_SCAN=$1
DIR_SCAN_TITLE=$(echo ${DIR_SCAN} | sed 's/\//-/g' | sed 's/^\-//; s/\-$//')

### Local hostname ###
HOSTNAME=$(hostname)

## Choose short list keyword to scan or long list keyword to scan
## Just set one list, other list have to be disable
## 1: enable
## 0: disable
## For example : 
## + use short list : SHORTL_SET=1 ; LONGL_SET=0
## + use long list : SHORTL_SET=0 ; LONGL_SET=1
# pcregrep -rnlHM '\<\?php.*\n.*\$GLOBAL'

SHORTL_SET="1"
LONGL_SET="0"


DIR_WK=/usr/local/src/scan-mal-file-vinahost

KEYWORD_LIST="${DIR_WK}/list.vinahost.keyword-scan.txt"
DATE_TIME=$(date +%y%m%d_%H.%M.%S)
REPORT_SUSPICIOUS_CODE_FILE="${HOSTNAME}.${DIR_SCAN_TITLE}.suspicious_code.${DATE_TIME}.txt"
REPORT_SPAM_FILE="${HOSTNAME}.${DIR_SCAN_TITLE}.scaned_spam.${DATE_TIME}.txt"
REPORT_SHELLNAME_FILE="${HOSTNAME}.${DIR_SCAN_TITLE}.scaned_shell_name.${DATE_TIME}.txt"

###########################################################################
###########################################################################

pre_scripts()
{
	echo
}
suspicous_spam_file_name()
{
	LIST_SUSPICIOUS_SPAM_NAME="/tmp/${HOSTNAME}.suspicious_spam.filename.list"

cat << EOF > ${LIST_SUSPICIOUS_SPAM_NAME}
wp-config|post|include|general|akismet|cacheplugin|xml|session|files|list|template|inc|dirs|diff|ini|ajax|alias|gallery|plugin|themes|lib|press|article|global|sql|dump|utf|javascript|cache|model|proxy|error|demo|menu|help|footer|blog|view|title|db|sytem|stats|css|user
EOF
}

suspicous_shell_file_name()
{
	LIST_SHELL_SPAM_NAME="/tmp/${HOSTNAME}.suspicious_shell.filename.list"

cat << EOF > ${LIST_SHELL_SPAM_NAME}
12309.php|404.php|404super.php|529.php|ASPYDrvsInfo.php|Ani-Shell.php|Antichat_Shell_v1.3.php|Dive_Shell_1.0_Emperor_Hacking_Team.php|Dx.php|DxShell.php|GFS_web-shell_ver_3.1.7_PRiV8.php|JFIF.php|KAdot_Universal_Shell_v0.1.6.php|Moroccan_Spamers_Ma-EditioN_By_GhOsT.php|MySQL_Web_Interface_Version_0.8.php|Mysql_interface_v1.0.php|NCC-Shell.php|NGH.php|NGHshell.php|NetworkFileManagerPHP.php|Non-alphanumeric.php|PHANTASMA.php|PHPRemoteView.php|PHVayv.php|PH_Vayv.php|Predator.php|Rootshell.v.1.0.php|SPS-3.php|Safe_Mode_Bypass_PHP_4.4.2_and_PHP_5.1.2.php|SimShell_1.0_-_Simorgh_Security_MGZ.php|Simple_PHP_backdoor_by_DK.php|Simshell.css|Simshell.php|Super-Crystal.php|Uploader.php|Uploading.php|WebShell.php|ZyklonShell.php|aZRaiLPhp_v1.0.php|accept_language.php|angel.php|b374k-mini-shell-php.php.php|b374k.php|b374k.php.php|backdoor.php|backupsql.php|bd.php|bdshell.php|boffmax_v1.0.php|bug.php|c100.php|c100sh.php|c100shell.php|c99.php|c999shell.php|c99_locus7s.php|c99_madnet.php|c99_webshell.php|c99sh.php|c99shell.php|casus15.php|cpanel.php|ct.php|ct_sh.php|ct_shell.php|ctsh.php|ctshell.php|ctt.php|cw.php|cybershell.php|dC3_Security_Crew_Shell_PRiV.php|devilzShell.php|dingen.php|dtool.php|dx.php|dxshell.php|erne.php|ex0shell.php|fatal.php|ftpsearch.php|g00nshell-v1.3.php|gfs_sh.php|gif89a.php|grp_repair.php|h4ntu.php|h4ntu_shell.php|hello.php|iMHaPFTP.php|iMHaPFtp.php|imhapftp.php|ironshell.php|jspwebshell.php|kral.php|lamashell.php|load.php|load_shell.php|lolipop.php|lostDC.php|matamu.php|megabor.php|miniinc.php|myshell.php|mysql_tool.php|newfile.php|nghshell.php|nsTView.php|nshell.php|nstview.php|pHpINJ.php|pas.php|php-backdoor.php|php-findsock-shell.php|php-include-w-shell.php|php-reverse-shell.php|phpRemoteView.php|phpemoteview.php|phpinfo.php|phpinj.php|phpshell.php|pws.php|qsd-php-backdoor.php|r57.php|r57_Mohajer22.php|r57_iFX.php|r57_kartal.php|r57shell.php|r57shell127.php|root.php|rootshell.php|ru24.php|ru24_post.php|ru24_post_sh.php|ru24shell.php|s72.php|include91.php|s72_Shell_v1.1_Coding.php|s72shell.php|safe0ver.php|sh.php|shell.php|simattacker.php|simple-backdoor.php|simple_cmd.php|small.php|soldierofallah.php|sosyete.php|spygrup.php|stres.php|super-crystal.php|t57shell.php|tryag.php|www.zjjv.com.php|xnonymoux_webshell_ver_1.0.php|zaco.php|zacosmall.php
EOF
}
create_short_list_file()
{
	LIST_CODE_SUSPICIOUS_PATTEN="/tmp/${HOSTNAME}.suspicious_code.in_file.list"

cat << EOF > ${LIST_CODE_SUSPICIOUS_PATTEN}
shell_exec *(
base64_decode *(
edoced_46esab *(
eval *(
eval(g
eval(
eval(base64
base64_decode(eval(
passthru
shell_exec
EOF
}

create_long_list_file()
{
	LIST_CODE_SUSPICIOUS_PATTEN="/tmp/${HOSTNAME}.suspicious_code.in_file.list"

cat << EOF > ${LIST_CODE_SUSPICIOUS_PATTEN}
tcpflood
udpflood
php_uname
edoced_46esab
mkdir
shell_exec *(
base64_decode *(
phpinfo *(
system *(
php_uname *(
chmod *(
fopen *(
fclose *(
readfile *(
edoced_46esab *(
eval *(
eval(g
eval(
eval(base64
base64_decode(eval(
include()
include_once()
require()
require_once()
assert()
preg_replace
passthru
gzinflate *(
shell_exec
EOF
}

scan_progress()
{
	#$GLOBALS
	cat /dev/null > ${REPORT_SUSPICIOUS_CODE_FILE}.tmp
	cat /dev/null > ${REPORT_SUSPICIOUS_CODE_FILE}

	if [[ -f ${LIST_CODE_SUSPICIOUS_PATTEN} && ! -z ${LIST_CODE_SUSPICIOUS_PATTEN} ]];then
		echo "--- Scan malicious code file $(date -I) in ${DIR_SCAN} ----" >> ${REPORT_SUSPICIOUS_CODE_FILE}
		while read CODE
		do
			echo ${CODE}
			#find ${DIR_SCAN} -type f -exec grep -Hn "${LINE}" {} \; -print >> ${REPORT_FILE}
			grep -rHn "${CODE}" "${DIR_SCAN}" >> ${REPORT_SUSPICIOUS_CODE_FILE}.tmp
		done < ${KEYWORD_LIST}
		pcregrep -rHnM '\<\?php.*\n.*\$GLOBALS' "${DIR_SCAN}" >> ${REPORT_SUSPICIOUS_CODE_FILE}.tmp

		echo "------------- END SCANNING -------------" >> ${REPORT_SUSPICIOUS_CODE_FILE}
	fi

	## Scan malicious spamming file php ##
	if [[ -f ${LIST_SUSPICIOUS_SPAM_NAME} && ! -z ${LIST_SUSPICIOUS_SPAM_NAME} ]];then
		find ${DIR_SCAN} -type f -iname "*.php" >> ${REPORT_SPAM_FILE}.php.list
		for BAD_SPAMNAME in `cat ${LIST_SUSPICIOUS_SPAM_NAME} | tr -s '|' '\n'`
		do
			grep -w "${BAD_SPAMNAME}.php$" ${REPORT_SPAM_FILE}.php.list >> ${REPORT_SPAM_FILE}.tmp
			grep -w "${BAD_SPAMNAME}[0-9][0-9].php$" ${REPORT_SPAM_FILE}.php.list >> ${REPORT_SPAM_FILE}.tmp
			grep -w "${BAD_SPAMNAME}[0-9].php$" ${REPORT_SPAM_FILE}.php.list >> ${REPORT_SPAM_FILE}.tmp
			grep "w[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]n.php$" ${REPORT_SPAM_FILE}.php.list >> ${REPORT_SPAM_FILE}.tmp
			grep "w[0-9][0-9][0-9][0-9][0-9][0-9][0-9]n.php$" ${REPORT_SPAM_FILE}.php.list >> ${REPORT_SPAM_FILE}.tmp
			grep "[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9].php$" ${REPORT_SPAM_FILE}.php.list >> ${REPORT_SPAM_FILE}.tmp
			grep "w[0-9][0-9][0-9][0-9][0-9][0-9][0-9].php$" ${REPORT_SPAM_FILE}.php.list >> ${REPORT_SPAM_FILE}.tmp
		done
		cat ${REPORT_SPAM_FILE}.tmp | sort | uniq > ${REPORT_SPAM_FILE}
	fi
}

end_script()
{
	if [ -f ${KEYWORD_LIST} ];then
		rm -f ${KEYWORD_LIST}
	fi
}

### Main Function ###
if [[ ${SHORTL_SET} -eq 1 && ${LONGL_SET} -eq 0 ]];then
create_short_list_file
elif [[ ${LONGL_SET} -eq 1 ]];then
create_long_list_file
else
create_long_list_file
fi

scan_progress
end_script

exit 0
