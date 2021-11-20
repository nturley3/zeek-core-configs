## Purpose
Additional scripts for configuring or logging to Zeek and Corelight.
Not all scripts are useful in every environment. 

| Script Name | Description |
| -- | -- |
| extendNTLM.zeek | Extend the NTLM log to record the NTLM and LM negotiation flags. |
| httpcookies.zeek | Extracts and logs variable names from cookies sent by clients. |
| registerports.zeek | Force Zeek to try using the HTTP analyzer on a nonstandard HTTP port. |
| software_load.zeek | Loads additional softawre scripts that Corelight does not enabled by default. |
| ssh.zeek | Extends the SSH log to faciliate authentication threat hunting. |

## Installation/Upgrade

This is easiest to install through the Zeek package manager:

	zkg refresh
	zkg install https://github.com/nturley3/zeek-core-configs

If you need to upgrade the package:

	zkg refresh
	zkg upgrade https://github.com/nturley3/zeek-core-configs 

See the [Zeek Package Manager Docs](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html) for more information.

## Configuration

Review each script and determine which ones should be loaded for your environment. Some of the scripts are specific for Corelight instances,  others are for analyzing decrypted traffic, and still more for exte4nding logs.

## Usage



## About

Written by [@nturley3](https://github.com/nturley3)
