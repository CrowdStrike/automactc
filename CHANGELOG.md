# AutoMacTC Changelog

## Main v. 1.0.0.5 (2019-04-12)

* Fixed bug with output debug log messages.
* Added some additional checks to pull hostname successfully.
* Added functionality to capture last known IP address from wifi.log off forensic images.
* Added exception handling if OSVersion can't be pulled from SystemVersion.plist successfully on a live system.
* Added handling for removing output files OR directories after successfully adding to the tar archive.
* Added handling for use of forensic mode against a mount point that wasn't successfully mounted (i.e. has none of the expected directories underneath).
* Added handling for exceptions thrown when we can't find OSVersion correctly on live or dead images. Also updated Safari, Quicklooks, and CoreAnalytics to account for the change. Now, if OSVersion can't be found, it will be marked and handled as None in comparison tests.
* Fixed a bug where the program would hang if it couldn't obtain the serial number. 
* Added ability to try to get last IP in forensic mode from wifi.log, including bz2 historical logs.
* Switched precedence of LocalHostName and HostName when pulling together the output file prefix.
* Added argument to override the mount point error.

## Systeminfo v. 1.0.4 (2019-07-30)

* Added a check for the resolve location of /etc/localtime to find the timezone on forensic images.
* If no timezone is found in GlobalPreferences or /etc/localtime it will gracefully fail.
* Added Gatekeeper status and SIP status for live system analysis.

## Chrome v. 1.0.4 (2019-05-28)
* Added more verbose debug messages. Fix for Issue #1.
* Added a fix for pulling the correct User profile when using forensic mode and a mount point under /Users/.
* Per Issue #4, adjusted logic to handle errors gracefully when a table is not present in a History database. Also made column-missing debug messages more verbose.

## Safari v. 1.0.3 (2019-03-28)
* Added more verbose debug messages. Fix for Issue #1.
* Added a fix for pulling the correct User profile when using forensic mode and a mount point under /Users/.
* Handle OSVersion cleanly if not detected at initial runtime.
* Added logic to capture history from any users directories in /private/var/.
* Added logic to produce a debug message when a History.db file is not found, rather than a "database could not be parsed" one.

## Firefox v. 1.0.2 (2019-07-30)
* Fixed a bug where the sqlite error thrown by places.sqlite was not triggering the module to try to copy the file and then read.

## Quicklook v 1.0.1 (2019-03-22)
* Handle OSVersion cleanly if not detected at initial runtime.

## CoreAnalytics v. 1.0.2 (2019-03-22)
* Fixed a bug where multi-line aggregate files weren't being parsed.
* Handle OSVersion cleanly if not detected at initial runtime.

## SSH v. 1.0.2 (2019-03-28)
* Now handling error messages if parsing fails with ssh-keyge (reporting "not an authorized key file"). Fix for Issue #1.
* Added logic to capture known_hosts and authorized_keys from any users directories in /private/var/.

## ASL v. 1.0.2 (2019-05-28)
* Now handling ASL files that cannot be parsed due to "Invalid Data Store" errors.
* Bugfix for handling of invalid ASL files, will now skip failed files correctly.

## Users v. 1.1.0 (2019-04-12)
* Throw an error if the admin.plist can't be parsed from a forensic image indicating that admins could not be determined.
* Reworked logic to collect all users, including normal system users comprehensively.

## Dirlist v. 1.0.2 (2019-05-28)
* Fixed a bug with default directory exclusions in forensic mode. 
* Added file owner metadata to output.

## Autoruns v. 1.0.2 (2019-06-03)
* Added parsing for user profiles under /private/var.
* Added logic to correctly pull program name with location from launch agent plists that have both Program and ProgramArguments (frequently found in /System/Library/LaunchDaemons). This fix eliminates several file-not-found errors on hashing and code signa

## Bash v. 1.0.2 (2019-06-03)
* Added parsing for user profiles under /private/var.
* Reduced volume of debug messages produced when history files were NOT found under a user profile.

## MRU v. 1.0.2 (2019-05-28)
* Added parsing for user profiles under /private/var.
* Now extracting and adding username to output, based on MRU file location.

## Quarantines v. 1.0.2 (2019-06-03)
* Added parsing for user profiles under /private/var.
* Added a fix for pulling the correct User profile when using forensic mode and a mount point under /Users/.
* Bugfixes, added import for multiglob from functions.py.

## Spotlight v. 1.0.2 (2019-04-12)
* Added parsing for user profiles under /private/var.
* Reduced volume of debug messages produced when spotlight history files were NOT found under a user profile.

## Terminalstate v. 1.0.0 (2019-04-12)
* Added new module to parse Terminal savedState files under each user profile. 

## Auditlog v. 1.0.0 (2019-05-06)
* Added new module to parse audit log files under /private/var/audit. 

## common/functions.py (2019-05-28)
* Improved logic for the stats2 function.
* Added logic to stats2 to pull file owner metadata.

