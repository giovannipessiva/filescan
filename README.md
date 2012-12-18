filescan
========

Filescan is a Python script that can analyse all the files contained inside an Android application (apk file).
It is able to identify textual files (checked for URLs, phone numbers, shell commands), compressed archives (recursively analysed), Dalvik code (dex files) and native executable and libraries (ELF files) (checked against the hash codes of known malware), and then produce a final score which express the danger posed by that application.
