This directory contains an implementation in Sage of attacks in '_Lattice Attacks on Digital Signature Schemes_' by N.A. Howgrave-Graham and N.P. Smart. The actual application that is attacked is an old OpenSSL implementation of ECDSA, as demonstrated in '_Remote Timing Attacks are Still Practical_', by B.B. Brumley and N. Tuveri.

The attack works by measuring the execution time of several ECDSA signing operations when operating on the B-163 NIST Binary Curve. These measurements (together with the signature values and message digests) are combined so we can run a near vector algorithm (on an LLL-reduced lattice based on this information) that (hopefully) results in the private key. For more details on the mathematics, you can read the papers `:-)` (The original paper by Howgrave-Graham and Smart contains most of the mathematics; Brumley and Tuveri's paper mostly describes a practical use of this attack.)

# How to run this attack?
## Initial set-up
* Run `./setup.sh`, which will fetch OpenSSL's git, checkout a vulnerable version, and builds it. Optionally you can comment out the lines that correspond to checking out and building the successor commit, which has the vulnerability fixed.
* checkout my sage-extra-bindings repository https://github.com/bcoppens/sage-extra-bindings somewhere, it contains functionality from NTL that I need in Sage (for finding Near Vectors)
* edit attack-ecdsa-hgs.sage to let it point to the `NearVector.spyx` file in the repository you just checked out (this is somewhat ugly, one day I'll look into making this cleaner)

## Reliable timing measurements
As this is a timing-attack, you need reliable timings. However, modern Intel systems have a plethora of performance-enhancing and power-saving features that make accurate timing measurements *very* unreliable. You'll need to disable these as follows (It's possible that you can still run the attack, it will just take much more time):
* Boot your Linux kernel with the following additional argument: 'intel_pstate=disable'. This disables Intel's advanced but completely unconfigurable power-save modes, and gives back control to the older but more controlable CPU governors.
* Of course you'll then need to set the CPU governors to ignore power-saving and optimize for performance, by running
```
echo -n "performance" | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
```
as root.
* Of course, if you'd do this manually, you really want to pin the attacked program to a fixed core with `taskset --cpu-list 0`, but luckily for you my script already does this for you :-)

## Make some timing measurements
The command ``./time.sh`` will automatically build a small binary that performs some ECDSA computations, and links it against the vulnerable copy of OpenSSL built in the previous step. This executable does the following:
* Create an ECDSA public/private key pair for the B-163 NIST Binary Curve. The public key is written to `publickey`, the private key is written to `privatekey`.
* Compute 10.000 ECDSA signing operations, and it times them. This means that this binary measures the timing of the vulnerable routine that it executes itself. This is rather unrealistic, of course, but it makes for very reliable measurements :-)
* For each of these 10.000 signing operations, it writes to standard output the following
```message digest,r,s,time```
This output is redirected to `timings.csv` by the shell script.

## Compute the private key from the timings
Run sage, and attach the `attack-ecdsa-hgs.sage` file. Type:
```python
find_private()
```
This will spawn different parallel threads that run a LLL Lattice Reduction and perform a Near Vector computation to find the private key. However, this operation is *not* guaranteed to return the correct result. Luckily, we can verify whether the returned result is correct by checking if this private key corresponds to the public key we read. This means the output will look somewhat like the following:
```
LLL reducing...
Finding near vector...
Computed the private key as: 396863325212753405354279068633098493901758437701
... but it was not the correct private key, continuing to search
LLL reducing...
Finding near vector...
Computed the private key as: 1992492012936166803801437449573779036229133337686
... but it was not the correct private key, continuing to search
LLL reducing...
Finding near vector...
Computed the private key as: 2445207057541222720157002061399830121383577854245
... FOUND IT! private key is 2445207057541222720157002061399830121383577854245!
... you can Ctrl+C now to stop the computation
LLL reducing...
Finding near vector...
```

For now, the different threads do not stop once the correct key is found, but that doesn't sound like too much of an issue. You can, if you want, verify that the code is not lying to you by verifying against the private key in the `privatekey` file.

In my experience, on my machines, it never takes too long to find the correct key. However, you can always modify the `time_own_execution.c` file to do more than 10.000 computations, or you can try to tweak the randomized subset of measurements each LLL reduction uses as input by modifying the Sage file as follows. The line
```python
      subset = random.sample(inputs[0:50], 40)
```
Says that we take a random subset of 40 elements from the fastest 50 measurements. Increasing these might help (but it will slow down the computations).