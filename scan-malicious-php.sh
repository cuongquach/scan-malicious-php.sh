#!/bin/bash
# Script find malicious string in code file
# Author : Quach Chi Cuong
# Version : 1
# Updated : 11/08/2016


### Variable to set
## Directory to scan, you can use with $1 variable
DIR_SCAN=$1
#DIR_SCAN=/path

### IP local ###
IP_LOCAL=x.x.x.x

## Choose short list keyword to scan or long list keyword to scan
## Just set one list, other list have to be disable
## 1: enable
## 0: disable
## For example : 
## + use short list : SHORTL_SET=1 ; LONGL_SET=0
## + use long list : SHORTL_SET=0 ; LONGL_SET=1

SHORTL_SET="1"
LONGL_SET="0"


DIR_WK=/usr/local/src/scan-mal-file-vinahost

KEYWORD_LIST="${DIR_WK}/list.vinahost.keyword-scan.txt"
DATE_TIME=$(date +%y-%m-%d_%H.%M.%S)
REPORT_FILE="${DIR_WK}/report-scan-malicious.${DATE_TIME}.txt"

create_short_list_file()
{
cat << EOF > ${KEYWORD_LIST}
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
cat << EOF > ${KEYWORD_LIST}
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

	if [ -f ${KEYWORD_LIST} ];then
		echo "--- Scan malicious file $(date -I) ----" >> ${REPORT_FILE}
		while read LINE
		do
			echo $LINE
			find ${DIR_SCAN} -type f -exec grep -Hn "${LINE}" {} \; -print >> ${REPORT_FILE}
		done < ${KEYWORD_LIST}
		echo "------------- END SCANNING -------------" >> ${REPORT_FILE}
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
elif [[ ${LONGL_SET} -eq 1 && ${SHORTL_SET} -eq 0 ]];then
create_long_list_file
fi

scan_progress
end_script

exit 0