# Single path tests

In this folder are all the files that are required to test secret sharing on a single host or over a single path. 

## sss_gendec.py

Runs locally. Creates a set of shares and uses these to reobtain the secret. Contains a profiler setup to test the implementation. Not meant to be used in concrete tests.

## sss_sender.py

Runs over a single path, but can be local ports. Creates a set of shares and sends these to the REMOTE. Also responsible for taking the time, which ends as the receiver responds with the correct secret. Also tests unencrypted and with AES 128 for a comparison of the performance. 

## sss_receiver.py

Receives the shares from the sender, interpolates the shares and responds with the secret to the sender. Obviously this is not good behavior for real useage but used to allow for better accuracy. 

## aes.py

Helper file to allow for comparison with AES 128 in terms of performance. Used by both the receiver and the sender.