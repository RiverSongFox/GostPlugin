# GostPlugin
Enables KeePass 2.x to encrypt databases using the GOST 28147-89 algorithm.

> The plugin has not been widely tested yet, so we strictly recommend you create backup of your KeePass database before using the plugin for the first time.

## Features

 - The GOST block cipher, a Soviet and Russian government standard symmetric key block cipher, developed in 1970s and still relevant nowadays
 - Uses 256-bit key and operates on 64-bit blocks of data within 32 rounds
 - This implementation uses Cipher Feedback (CFB) mode

## Installation

 1. Download [latest release](https://github.com/yaruson/GostPlugin/releases)
 2. Make sure that calculated checksum for `GostPlugin.zip` matches specified on release page
 3. Unzip and verify digital signature of `GostPlugin.dll` assembly
 4. Simply copy `GostPlugin.dll` to your KeePass directory and restart the application

## Usage

 1. Make sure that `GOST 28147-89 Plugin` is listed in **Tools → Plugins...** dialog
 2. Switch encryption algorithm in your database's options dialog as described in [Database Settings](http://keepass.info/help/v2/dbsettings.html) section of KeePass documentation

## Acknowledgements

 - Reddit community and PolyPill for their commitment to quality of the code by conducting code review
 - Habrahabr community, sftp, milabs for their feedback and valuable support in performance optimization techniques
 - Michael Ospanov for reporting and resolving Addition Modulo 2^32 bug and performance improvement suggestions
