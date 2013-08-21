mallodroid
==========

Find broken SSL certificate validation in Android Apps. MalloDroid is a small tool built on top of the androguard (https://code.google.com/p/androguard/) reverse engineering framework for Android applications. Hence, androguard is required to use MalloDroid.

===============================

### Usage
./mallodroid.py --help

usage: mallodroid.py [-h] -f FILE [-j] [-x] [-d DIR]

Analyse Android Apps for broken SSL certificate validation.

optional arguments:
	-h,	--help				show this help message and exit
	-f FILE, --file FILE	APK File to check
	-j,	--java				Show Java code for results for non-XML output
	-x,	--xml				Print XML output
	-d DIR,	--dir DIR		Store decompiled App's Java code for further analysis in dir

===============================

### Contact
Please do not hesitate to contact me if you have comments or questions.
