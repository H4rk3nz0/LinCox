# WHAT IS THIS?

A messy assembly of tools and scripts to automate generating some dummy attack data for use in AD, Network and Endpoint alert testing/hunting.
Logging of all actions will be appended verbosely to `debug_log.log` while non-verbose will be appended to `attack_log.log`.

! Important:

I am not a developer and will likely not maintain or update this project. 
While attempts to sanitize outputs from commands such as DcSync and Password Dumping was made this is NOT recommended for use in a production environment.

Note: The script will attempt to Sync local Kali host time with Specified Domain Time using NTP

# PROJECT NOTES

> Some Inconsistency In Menu Selection (Might Need to Enter Same Number Twice)
> Run LinCox As Sudo/Root (Certain modules such as Network Spoofing require elevated Local System permissions)
> Must have Local Admin and Privileged Domain Admin user creds to perform certain tests and clear logs on DC
> Commands and behaviours executed on Clients will be run as HOST$ (machine account) 
	due to atexec assuming high integrity with admin creds == SYSTEM

# INSTALLATION

```
cd LinCox
python3 -m pip install -r requirements.txt
python3 lincox.py
```
