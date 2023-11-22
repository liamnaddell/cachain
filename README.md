Instructions for running inside mininet:
* use commands like `h1 alacritty` to spawn terminals in the hosts
* somehow we need to start a DNS server inside of mininet later to accomplish some BS
* How to set up DNS: 
    configure /etc/hosts to have a.com,b.com,c.com point to their addresses in mininet
    start mininet


# Requirements

## Not understood yet

Code Quality???
Ask marcelo
Do we need a design document?
How do we submit our code? How do we demo it?
Testing requirements???
How do we handle cut corners?
Re-certification?

## Code/Formatting requirements

* Ensure consistent formatting (likely using rustfmt)
* Add comments to explain code

## Functional requirements

1.  Clients must produce a list of ca-certificates for browser use
2.  The CA certs must be valid (according to a browser)
3.  New servers joining the network must be able to request ca-certificates, this must work even with difficult network topologies (e.g. verifier not directly connected to server attempting to become verified)
4.  Servers must actually verify challenges, not fake the completion of challenges
5.  Servers and clients and must stay updated on the state of the network by periodically requesting updates from peers
6.  Chain integrety must be verified via hash checking, signature checking, past-url checking, correct-verifier checking, including for incoming blocks
7.  Must deal with multiple cert requests occurring at the same time, fastest verifier wins, same process for dealing with conflicting updates.
8. Adverts for ChainEntries must only be broadcasted once you actually have the block

## Stretch Goals

