## about `adb backup`
`adb backup` and `adb restore` are obscure (not mentioned in `adb --help`) and depracated features of `adb` but **no root needed**

`adb backup` and `adb restore` commands documented [here](https://manpages.ubuntu.com/manpages/jammy/man1/adb.1.html)

file generated by `adb backup` is optionally compressed, optinally encrypted tar (pax (kinda) format (don't confuse with `pax` command)) container

files and pax headers in tar archive need to be be in secific order and have specific names, so extracting and creating archive probably won't work (`adb restore` silently fails)

you can `u`pdate files in tar archive without extracting everything using [`7zz` (7-Zip for Linux: console version)](https://7-zip.org/download.html) [`u` command](https://sevenzip.osdn.jp/chm/cmdline/commands/update.htm)

here is [help for old version of `7z.exe`](https://sevenzip.osdn.jp/chm/cmdline/index.htm) but most command line options are same as `7zz`

## `abpy.py` is python3 script for files generated by `adb backup`
`abpy.py` depends on [PyCryptodome](https://www.pycryptodome.org/src/installation) if using encryption

## example: modify `/data/data/com.gdpsedi.geometrydashsubzero/CCLocalLevels.dat` on android no root using linux computer
<ol>
<li>backup <code>com.gdpsedi.geometrydashsubzero</code>'s files into <code>backup.ab</code>:<pre lang="console">$ adb backup com.gdpsedi.geometrydashsubzero&#10;WARNING: adb backup is deprecated and may be removed in a future release</pre></li>
<li>convert <code>backup.ab</code> to <code>backup.tar</code>:<pre lang="console">$ python3 abpy.py ab2tar if=backup.ab of=backup.tar</pre></li>
<li>find <code>CCLocalLevels.dat</code> path in <a href="https://sevenzip.osdn.jp/chm/cmdline/commands/list.htm"><code>l</code>ist</a> of files in <code>backup.tar</code>:<pre lang="console">$ 7zz l backup.tar | grep -F CCLocalLevels.dat&#10;2023-04-13 11:11:51 .....          733         1024  apps/com.gdpsedi.geometrydashsubzero/r/CCLocalLevels.dat</pre></li>
<li><a href="https://sevenzip.osdn.jp/chm/cmdline/commands/extract_full.htm">e<code>x</code>tract with full path</a> <code>apps/com.gdpsedi.geometrydashsubzero/r/CCLocalLevels.dat</code> from <code>backup.tar</code>:<pre lang="console">$ 7zz x backup.tar apps/com.gdpsedi.geometrydashsubzero/r/CCLocalLevels.dat&#10;&#10;7-Zip (z) 22.01 (x64) : Copyright (c) 1999-2022 Igor Pavlov : 2022-07-15&#10; 64-bit locale=en_US.UTF-8 Threads:12, ASM&#10;&#10;Scanning the drive for archives:&#10;1 file, 6880256 bytes (6719 KiB)&#10;&#10;Extracting archive: backup.tar&#10;--&#10;Path = backup.tar&#10;Type = tar&#10;Physical Size = 6880256&#10;Headers Size = 14336&#10;Code Page = UTF-8&#10;Characteristics = POSIX PREFIX PAX path ASCII&#10;&#10;Everything is Ok&#10;&#10;Size:       733&#10;Compressed: 6880256</pre></li>
<li>edit <code>apps/com.gdpsedi.geometrydashsubzero/r/CCLocalLevels.dat</code></li>
<li><a href="https://sevenzip.osdn.jp/chm/cmdline/commands/update.htm"><code>u</code>pdate</a> <code>apps/com.gdpsedi.geometrydashsubzero/r/CCLocalLevels.dat</code> to <code>backup.tar</code>:<pre lang="console">$ 7zz u backup.tar apps/com.gdpsedi.geometrydashsubzero/r/CCLocalLevels.dat&#10;&#10;7-Zip (z) 22.01 (x64) : Copyright (c) 1999-2022 Igor Pavlov : 2022-07-15&#10; 64-bit locale=en_US.UTF-8 Threads:12, ASM&#10;&#10;Open archive: backup.tar&#10;--&#10;Path = backup.tar&#10;Type = tar&#10;Physical Size = 6880256&#10;Headers Size = 14336&#10;Code Page = UTF-8&#10;Characteristics = POSIX PREFIX PAX path ASCII&#10;&#10;Scanning the drive:&#10;1 file, 824 bytes (1 KiB)&#10;&#10;Updating archive: backup.tar&#10;&#10;Keep old data in archive: 6 folders, 17 files, 6861172 bytes (6701 KiB)&#10;Add new data to archive: 1 file, 824 bytes (1 KiB)&#10;&#10;    &#10;Files read from disk: 1&#10;Archive size: 6880256 bytes (6719 KiB)&#10;Everything is Ok</pre></li>
<li>get info about <code>backup.ab</code>:<pre lang="console">$ python3 abpy.py abinfo if=backup.ab&#10;ver=5&#10;compr</pre></li>
<li>convert <code>backup.tar</code> to <code>backup.ab</code> with that info:<pre lang="console">$ python3 abpy.py tar2ab if=backup.tar of=backup.ab compr ver=5</pre></li>
<li>restore the new <code>backup.ab</code>:<pre lang="console">$ adb restore backup.ab&#10;WARNING: adb restore is deprecated and may be removed in a future release&#10;Now unlock your device and confirm the restore operation.</pre></li>
</ol>

## stuff I found related to `adb backup`
* https://github.com/nelenkov/android-backup-extractor/
* https://nelenkov.blogspot.com/2012/06/unpacking-android-backups.html
* https://forum.xda-developers.com/t/guide-how-to-extract-create-or-edit-android-adb-backups.2011811/
* https://sourceforge.net/projects/android-backup-processor/files/