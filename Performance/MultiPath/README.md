# Multi path tests

In this folder are all the files that are required to test secret sharing on a multiple hosts. 

## sss_forwarder.py

Forwards shares received to a predefined remote. Meant to be used to control the flow of information as either a distributor or a receiver. 

## sss_sender.py

Creates a set of shares and spreads these across the REMOTES. Also responsible for taking the time, which ends as the receiver responds with the correct secret. Also tests unencrypted and with AES 128 for a comparison of the performance. 

## sss_receiver.py

Receives the shares from the sender, interpolates the shares and responds with the secret to the sender. Obviously this is not good behavior for real useage but used to allow for better accuracy. 

## aes.py

Helper file to allow for comparison with AES 128 in terms of performance. Used by both the receiver and the sender.