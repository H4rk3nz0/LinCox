<!-- PROJECT NOTES -->

```
- Some Inconsistency In Menu Selection (Might Need to Enter Same Number Twice)
- Run LinCox As Sudo/Root (Certain modules such as Network Spoofing require elevated Local System permissions)
- Must have Local Admin and Privileged Domain Admin user creds to perform certain tests and clear logs on DC
- Commands and behaviors executed on Clients will be run as HOST$ (machine account) 
	due to atexec assuming high integrity with admin creds == SYSTEM
```

<!-- GETTING STARTED -->

### Dependency Installation:

```
python3 -m pip install -r requirements.txt
sudo python3 lincox.py
```
