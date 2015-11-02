# GostPlugin

Enables KeePass 2.x to encrypt databases using the GOST R 34.12-2015 algorithm.

[![GitHub license](https://img.shields.io/github/license/yaruson/GostPlugin.svg)]()
[![GitHub release](https://img.shields.io/github/release/yaruson/GostPlugin.svg)]()
[![Github Releases](https://img.shields.io/github/downloads/yaruson/GostPlugin/latest/total.svg)]()
[![Join the chat at https://gitter.im/yaruson/GostPlugin](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/yaruson/GostPlugin?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
[![Flattr this git repo](http://api.flattr.com/button/flattr-badge-large.png)](https://flattr.com/submit/auto?user_id=Yaruson&url=https://github.com/yaruson/GostPlugin&title=GostPlugin&category=software)

> Latest 2.0 release is incompatible with older 1.x versions and then should be used with caution

## Features

 - Implementation of two ciphers defined within GOST R 34.12-2015: Kuznyechik and Magma (formely GOST 28147-89)
 - Both ciphers use 256-bit key; Kuznyechik handles 128-bit blocks and Magma – 64-bit blocks
 - This implementation uses Cipher Feedback (CFB) mode

## Installation

 1. Download [latest release](https://github.com/yaruson/GostPlugin/releases)
 2. Make sure that calculated checksum for `GostPlugin.zip` matches specified on release page
 3. Unzip and verify digital signature of `GostPlugin.dll` assembly
 4. Simply copy `GostPlugin.dll` to your KeePass directory and restart the application

> If you're migrating from  1.x version, then change database encryption algorithm to AES before replacing plugin DLL.

## Usage

 1. Make sure that `GOST R 34.12-2015 Plugin` is listed in **Tools → Plugins...** dialog
 2. Switch encryption algorithm in your database's options dialog as described in [Database Settings](http://keepass.info/help/v2/dbsettings.html) section of KeePass documentation

## Acknowledgements

 - Reddit community and PolyPill for their commitment to quality of the code by conducting code review
 - Habrahabr community, sftp, milabs for their feedback and valuable support in performance optimization techniques
 - Michael Ospanov for reporting and resolving Addition Modulo 2^32 bug and performance improvement suggestions
 - Markku-Juhani O. Saarinen for [Kuznyechik implementation](https://github.com/mjosaarinen/kuznechik)
