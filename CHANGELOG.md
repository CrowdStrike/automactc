# AutoMacTC Changelog

## Main v. 1.0.0.1 (2019-03-19)

* Fixed bug with output debug log messages.
* Added some additional checks to pull hostname successfully.
* Added functionality to capture last known IP address from wifi.log off forensic images.
* Added exception handling if OSVersion can't be pulled from SystemVersion.plist successfully on a live system.
* Added handling for removing output files OR directories after successfully adding to the tar archive. 

## Systeminfo v. 1.0.1 (2019-03-19)

* Fixed a bug where module failed due to an AttributeError produced when computer_name was None but still tried to encode it.
* Will now pull LocalHostName from the preferences.plist rather than from the full output filename prefix (in case the latter fails for some reason)

## Chrome v. 1.0.1 (2019-03-19)
* Added more verbose debug messages. Fix for Issue #1.

## Safari v. 1.0.1 (2019-03-19)
* Added more verbose debug messages. Fix for Issue #1.

## CoreAnalytics v. 1.0.1 (2019-03-19)
* Fixed a bug where multi-line aggregate files weren't being parsed.

## SSH v. 1.0.1 (2019-03-19)
* Now handling error messages if parsing fails with ssh-keyge (reporting "not an authorized key file"). Fix for Issue #1.

## ASL v. 1.0.1 (2019-03-19)
* Now handling ASL files that cannot be parsed due to "Invalid Data Store" errors.
