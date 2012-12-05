#!/bin/bash
START=$(date +%s)
cd /home/giova/tools/filescan

echo "Goodware;sha1;time;risk;InfectedDex;InfectedElf;HiddenApk;HiddenElf;HiddenText;EmbeddedApk;Shell;ShellInstall;ShellPrivilege;ShellOther" > filescan_results.tmp
python test_filescan_class.py -d /home/giova/samples/goodware/ >> filescan_results.tmp
echo "Generating goodware report..."
cp filescan_results.tmp /home/giova/tools/filescan/report-goodware.csv

echo "Malware;sha1;time;risk;InfectedDex;InfectedElf;HiddenApk;HiddenElf;HiddenText;EmbeddedApk;Shell;ShellInstall;ShellPrivilege;ShellOther" > filescan_results.tmp
for apk in /home/giova/samples/genome/*/;
do
    python test_filescan_class.py -d "$apk" >> filescan_results.tmp
done
echo "Generating malware report..."
cp filescan_results.tmp /home/giova/tools/filescan/report-malware.csv


END=$(date +%s)
DIFF=$(( $END - $START ))
DIFF_MIN=$(( $DIFF / 60 ))
DIFF_SEC=$(( $DIFF % 60 ))
echo "Execution time: $DIFF_MIN:$DIFF_SEC"
rm -f filescan_results.tmp
