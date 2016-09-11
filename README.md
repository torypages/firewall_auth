# firewall_auth

* This provides a mechanism which will allow IP whitelisting within iptables via email
* This is useful for when your services should not be available by default

# general process
* firewall_auth starts and sets some default firewall rules
* firewall_auth waits and monitors IMAP email address for new messages
* when changes occur unseen/unread messages will be processed
* an email is processed like so...
* only emails from authorized addresses will be considered
* only emails encrypted using the monitored email's public key will be considered
* only emails containing authorized pgp fingerprints will be considered
* IP address will be extracted from header
* IP address can be overwritten by by supplying it in the instructions
* all instructions must be on the first line of the email
* first line can contain a single IP, the numbers (ports), 22 or 443 and/or a keyword of "rm"
* supplied rules on first line must be separated by spaces
* firewall rules will be added (deleted if rm exists) based on IP from header or explicitly supplied for any of the ports supplied
* default is to add
* default is to use port 443
* if any port is supplied th default will not be used
* thus, a blank signed and encrypted email will yield an added firewall rule using the IP from the header and for port 443
* adding an existing rule or removing a non existent rule is considered a success
* if successful you will receive an email of success to the email you used to initiate the process
* it not successful you will get an error sent to the email you used to initiate the process
* response emails can only be sent to authorized addresses
* sent emails are encrypted

# key security features
* by default, it would appear that no server exists at all since everything is blocked except whitelisted addresses
* the email address that this process monitors is obscure
* the email server can have inbox rules to filter out unauthorized addresses
* public key of the monitored address is kept secret and must be used
* only authorized pgp fingerprints are allowed
* only emailing from authorized email addresses is allowed
* all of this is simply an extra layer since the services that sit behind this would likely be secure on their own

# gotchas
* gnupg is a bit confusing as it is pretty distinct from this
* must setup the keys and the gnupg home using GNU Privacy Guard
* must sign key of users