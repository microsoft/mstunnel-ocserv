# Mise for Ocserv

Adding in Changes to add mise to Ocserv.
What these changes do:
- pam.c: Add in logic for pam init and sets up our struct. sets up our "use token" variable which controls if we are using pam or not. This config is set by tenant config from background service on the Tunnel VM
- pam.h: adds the use_token struct for use throughout code flow logic
- sec-mod-auth.c: If we're using pam and use-token is enabled, we'll set username to confidential because we are using token auth, there is no username
- subconfig.c: reads our use_token value from config
- worker-auth.c: sets logic to use token auth vs username/password auth
- Testing framework lacks module support to bring in a mise library to do token only auth.  igot around this by passing a fake password so the input wouldn't complain, but the username is replaced with a test token during the test pass. E2E tests were done locally to test functionality

Original PR [here](https://gitlab.com/openconnect/ocserv/-/merge_requests/454#9f621eb5fd3bcb2fa5c7bd228c9b1ad42edc46c8) from Gitlab

Mise Work [item](https://msazure.visualstudio.com/Intune/_workitems/edit/31852027)