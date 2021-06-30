# AutoMacTC Changelog
All significant changes to this project will be documented in this file.

## [1.2.0] - 2021-06-30

### Added
- **--rtr** flag for reducing verbosity of some modules to display nicely on CrowdStrike RTR console
- automactc.py flag **-is** for System drive input if using forensic mode on a 10.15+ image.
- Dirlist module support for 10.15+ style Data and System volume recursion.
- SystemInfo module support for 10.15+ location of required input. Checks input from **-i** and **-is** flags as needed.
- UnifiedLogs live module to collect the Unified Audit Logs from a live system as the syslog format into a file using the log show command.
- Ability to include non-data_writer generated files with output.
- Added datawriter support for buffered output writing
    * Fixed Unicode string issues with python 2
    * Fixed JSON write bytes issue with python 3
- Added .Office and .blacklight file type exclusion to dirlist
- Added /System/Volumes/Data/private/var/folders/kb/* and /System/Volumes/Data/private/var/folders/zz/* filepath exclusion to dirlist
### Changed
- Behavior of include and exclude dirlist command line flags updated to support 10.15+ split Data and System volume.
- Fixed common/functions.py SQLite query_db function issue where extra chars were appended to input file path string, resulting in incorrect output for various modules.
- Updated browser (chrome,firefox,cookies) modules to use SQLite3 wrappers.
- Updated mac_alisas library to fix issue [10](https://github.com/al45tair/mac_alias/issues/10) for ARM64 inodes (to do with M1 Mac).
- Bump Dirlist module to v2
    * Added multiprocessing wrapper
    * Use buffered output writing
    * Update xattr parsing
- Update modules to use docstring comments and bump minor versions
- Fixed syntax and deprecation issues

## [1.0.0.6] - 2020-10-15
### Added
- Python 3 support.
- macOS 10.15 support for live systems.

## [1.0.0.5] - 2019-07-30
### Changed
- Bumped SystemInfo module version to 1.0.3.
#### Systeminfo v. 1.0.3
- Added a check for the resolve location of /etc/localtime to find the timezone on forensic images.
- If no timezone is found in GlobalPreferences or /etc/localtime it will gracefully fail.
- Added Gatekeeper status and SIP status for live system analysis.

## [Historic Below]

## [1.0.0.5] - 2019-05-28
### Changed
- Bumped Chrome module version to 1.0.4
#### Chrome v. 1.0.4
- Added more verbose debug messages. Fix for Issue #1.
- Added a fix for pulling the correct User profile when using forensic mode and a mount point under /Users/.
- Per Issue #4, adjusted logic to handle errors gracefully when a table is not present in a History database. Also made column-missing debug messages more verbose.

## Safari v. 1.0.4 (2020-06-29)
- Refactored creation of temporary sqlite file.

## Firefox v. 1.0.2 (2020-08-04)
- Bugfix for handling dates.

## Quicklook v 1.0.1 (2019-03-22)
- Handle OSVersion cleanly if not detected at initial runtime.

## CoreAnalytics v. 1.0.3 (2020-06-30)
- Fixed error when running on macOS 10.15.
- Added experimental parsing module for macOS 10.15.

## SSH v. 1.0.2 (2019-03-28)
- Now handling error messages if parsing fails with ssh-keyge (reporting "not an authorized key file"). Fix for Issue #1.
- Added logic to capture known_hosts and authorized_keys from any users directories in /private/var/.

## ASL v. 1.0.3 (2020-08-05)
- Bugfix for handling of invalid ASL files.

## Users v. 1.1.0 (2019-04-12)
- Throw an error if the admin.plist can't be parsed from a forensic image indicating that admins could not be determined.
- Reworked logic to collect all users, including normal system users comprehensively.

## Dirlist v. 1.0.3 (2020-06-30)
- Fixed a bug with Python 3 support.

## Autoruns v. 1.0.2 (2019-06-03)
- Added parsing for user profiles under /private/var.
- Added logic to correctly pull program name with location from launch agent plists that have both Program and ProgramArguments (frequently found in /System/Library/LaunchDaemons). This fix eliminates several file-not-found errors on hashing and code signa

## Bash v. 1.0.2 (2019-06-03)
- Added parsing for user profiles under /private/var.
- Reduced volume of debug messages produced when history files were NOT found under a user profile.

## MRU v. 1.0.2 (2019-05-28)
- Added parsing for user profiles under /private/var.
- Now extracting and adding username to output, based on MRU file location.

## Quarantines v. 1.0.2 (2019-06-03)
- Added parsing for user profiles under /private/var.
- Added a fix for pulling the correct User profile when using forensic mode and a mount point under /Users/.
- Bugfixes, added import for multiglob from functions.py.

## Spotlight v. 1.0.2 (2019-04-12)
- Added parsing for user profiles under /private/var.
- Reduced volume of debug messages produced when spotlight history files were NOT found under a user profile.

## Terminalstate v. 1.0.1 (2020-06-29)
- Updated to exit upon finding no files to parse.

## Auditlog v. 1.0.0 (2019-05-06)
- Added new module to parse audit log files under /private/var/audit.

## Netconfig v 1.0.0 (2019-08-13)
- Added new module that parses the airport and network interfaces plists.

## Eventtaps v 1.0.0 (2019-08-13)
- Added new module that parses event taps.

## Cookies v 1.0.1 (2020-06-29)
- Fixed local variable reference before assignment.
- Updated Chrome cookies headers.

## common/functions.py (2019-05-28)
- Improved logic for the stats2 function.
- Added logic to stats2 to pull file owner metadata.

## common/Crypto (2020-06-30)
- Updated dependencies.
