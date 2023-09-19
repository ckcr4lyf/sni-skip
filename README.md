# sni-skip

An attempt to bypass SNI blocking by dropping the TLS extension.

## NOTE: THIS DOES NOT WORK!

I had the initial idea for this project when observing SNI based blocking. I thought "hmm - if MiTM can observe this value, would it be possible to drop it as well?". Following this, I tried to play around with the ClientHello using NFQUEUE to modify packets in userspace. 

I was able to parse out the SNI, splice the ClientHello to remove it, and even add back some TLS padding to compensate for the TCP sequence numbers (see https://github.com/ckcr4lyf/sni-skip/issues/3).

Unfortunately, I was jumping the gun. When I actually tried to use it, it seemed to work - at least for the ClientHello. The packet capture showed that the SNI was not sent over the wire, so it looked good! Unfortunately, in my TLS pre-reading, I skipped the final step of the handshake - the Client & Server's []"Handshake Finished" messages](https://tls12.xargs.org/#client-handshake-finished/annotated), which contain a hash of all the bytes sent so far (as per them). This helps ensure TLS clients/servers that the handshake was not tampered with - ironically exactly what I was trying to do.

This was a good lesson for me, but I did learn a lot about NFQUEUE packet modification, as well as needing to keep consideration for TCP sequence numbers (and checksums! a lot of checksums...) while modifying packets, so it was fun.

# Alternatives

If you stumble across this project interested in NFQUEUE or packet modification, the stuff in here may be of help.

Otherwise, for SNI related stuff, https://github.com/quininer/nosni-proxy may be interesting. I am planning to play around with it myself!

