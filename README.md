## Sample Forwarding Module

This sample OpenDaylight module reacts to any new
TCP or UDP connection that is to be established
between two hosts. Any of the hosts can act as
server or client.

## TCP Case

For TCP traffic the controller checks if the des-
tination port is within the (user-defined) range
5000-6000. If so, flow entries are installed
that forward such traffic to port 5050 and handle
packets sent back to the client. Otherwise,
a "DROP" rule is installed preventing further
connections to the target destination port.

## UDP Case
For UDP traffic there is no port checking and
rules with wildcarded UDP source/destination port
are installed into the switch.




