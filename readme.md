# openhaystack-ecdh-js

Decrypt openhaystack payloads directly in JS on the browser. Looking at the code for openhaystack and macless-haystack they both used dart with `pointycastle`, however I maybe want to implement some of this functionallity into a project that does not use dart but typescript and run it on the browser without any extra packages.

The code for the ecdh comes from: https://asecuritysite.com/encryption/js08/
The experiment.js file I have written myself and I have tested it with multiple payloads (it accounts for the 89 byte payloads) and it seams to work. 

If this is used in any other project the code should be made more prettier and translated to typescript. 

https://github.com/seemoo-lab/openhaystack
https://github.com/dchristl/macless-haystack