# AutoMacTC Changelog

## Main v. 1.0.0.4 (2019-04-27)

* Implementing modules as classes to remove code execution at import time.
* Introducing ModuleRegistry for storing and accessing module classes.
* Refactoring the CLI to reduce the use of globals and removing usage of `__main__` imports from modules.
* Migrating python package files to within a top-level `automactc` folder to better support packaging.
* Adding setuptools support (`setup.py`) to allow for installing via pip. This will result in a `automactc` executable being installed.

## Main v. 1.0.0.3 (2019-03-26)

* Fixed bug with output debug log messages.
* Added some additional checks to pull hostname successfully.
* Added functionality to capture last known IP address from wifi.log off forensic images.
* Added exception handling if OSVersion can't be pulled from SystemVersion.plist successfully on a live system.
* Added handling for removing output files OR directories after successfully adding to the tar archive.
* Added handling for use of forensic mode against a mount point that wasn't successfully mounted (i.e. has none of the expected directories underneath).
* Added handling for exceptions thrown when we can't find OSVersion correctly on live or dead images. Also updated Safari, Quicklooks, and CoreAnalytics to account for the change. Now, if OSVersion can't be found, it will be marked and handled as None in comparison tests.
* Fixed a bug where the program would hang if it couldn't obtain the serial number.
* Added ability to try to get last IP in forensic mode from wifi.log, including bz2 historical logs.

## Systeminfo v. 1.0.2 (2019-03-26)

* Fixed a bug where module failed due to an AttributeError produced when computer_name was None but still tried to encode it.
* Will now pull LocalHostName from the preferences.plist rather than from the full output filename prefix (in case the latter fails for some reason)
* Fixed a bug where the module would fail if it couldn't successfully get the serial number.
* Added logic to try to pull timezone from .GlobalPreferences.plist if running in forensic mode against a mounted image.

## Chrome v. 1.0.2 (2019-03-22)
* Added more verbose debug messages. Fix for Issue #1.
* Added a fix for pulling the correct User profile when using forensic mode and a mount point under /Users/.

## Safari v. 1.0.2 (2019-03-22)
* Added more verbose debug messages. Fix for Issue #1.
* Added a fix for pulling the correct User profile when using forensic mode and a mount point under /Users/.
* Handle OSVersion cleanly if not detected at initial runtime.

## Firefox v. 1.0.1 (2019-03-22)
* Added a fix for pulling the correct User profile when using forensic mode and a mount point under /Users/.

## Quicklook v 1.0.1 (2019-03-22)
* Handle OSVersion cleanly if not detected at initial runtime.

## CoreAnalytics v. 1.0.2 (2019-03-22)
* Fixed a bug where multi-line aggregate files weren't being parsed.
* Handle OSVersion cleanly if not detected at initial runtime.

## SSH v. 1.0.1 (2019-03-19)
* Now handling error messages if parsing fails with ssh-keyge (reporting "not an authorized key file"). Fix for Issue #1.

## ASL v. 1.0.1 (2019-03-19)
* Now handling ASL files that cannot be parsed due to "Invalid Data Store" errors.

## Users v. 1.0.1 (2019-03-22)
* Throw an error if the admin.plist can't be parsed from a forensic image indicating that admins could not be determined.

## Dirlist v. 1.0.1 (2019-03-26)
* Fixed a bug with default directory exclusions in forensic mode.
