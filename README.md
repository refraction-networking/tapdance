High performance implementation of the Tapdance decoy routing design.

# Building and Running the Tapdance Station

These instructions are for the standard build, which includes
drivers for Intel i40e- and ixgbe-based NICs.

## Station installation

 1. Install Ubuntu 16.04.1 for amd64
 1. Run `sudo apt-get update`
 1. Clone this repo into `$HOME/tapdance`
 1. In `$HOME/tapdance`, run `./scripts/tapdance-prereqs.sh` (NOT sudo/as root)
 1. In `$HOME/tapdance`, run `./scripts/tapdance-build.sh` (NOT sudo/as root)
 1. In `$HOME/tapdance/libtapdance`, run `./genkey` (unless you already have
    a keypair you're planning to use for this station).
 1. Copy the generated 'pubkey' file to your client: `gotapdance/assets/station_pubkey`
 1. Installing the PF_RING zero-copy license can wait until you confirm
    everything is working properly. Even without the license, you can use
    PF_RING-ZC-enabled programs for 5 minutes at a time.
 1. Double-check that the interface for the tunneled traffic is running at the expected rate (1Gb or better, usually)

## Once-per-reboot setup

Do this after the above station installation process, as well as after
every reboot.

 1. In `$HOME/tapdance`, run `sudo ./startup.sh`. The output should include
    the following instructions on running the station.

## Running the station

If you want to recompile before running:
 1. In `$HOME/tapdance`, run `./scripts/tapdance-build.sh` (NOT sudo/as root)

Run these three programs in separate screens, in this order.
 1. In `$HOME/tapdance/pfring-framework/userland/examples_zc`, run
    `sudo ./zbalance_ipc -i zc:$INTERFACE -c 99 -n 4 -m 1 -g 1`.
 1. (Optional) In `$HOME/tapdance/gobbler`, run `./gobbler` after building with
    `go build gobbler.go`. If gobbler isn't run, the station will still work;
    the Gobbler's purpose is to collect and report statistics.
 1. In `$HOME/tapdance/pfring-framework/userland/examples`, run
    `sudo RUST_BACKTRACE=1 ./zc_tapdance -c 99 -n 4 -K /path/to/privkey`.

The -n and -c arguments are number of processes to split over, and cluster ID.
You can safely change them (-n must be no more than number of logical CPU
cores on the host machine), but you must give zbalance_ipc and zc_tapdance the
same values.

## Registering PF_RING ZC for the network interface

### Getting an order ID for the license(s)

 1. Go to this page: https://shop.ntop.org/cart.php
 2. Scroll down to the PF_RING section, and find the 10/40 Gbit PF_RING
    ZC Intel [Linux] driver, and on the right side of the table put as
    many licenses as you need.  (The price was 149.95 euros at the time
    of writing)
 3. Scroll down the bottom of the page and click on the "go to next
    page" button
 4. From this point on it's just filling out info and paying, which
    should be straightforward

### Once you have an order ID:

After completing the previous steps, you should have an email from an
ntop employee, giving you an OrderId.

 1. Try both tap interfaces (their names in ifconfig should look something like
    enp5s0f0 and enp5s0f1) to figure out which one is getting traffic. Get the
    traffic-getting one's MAC address. To check for traffic, you can try running
    our station program, or even just `./zcount -i theIFname`
 1. In examples_zc, run `./zcount -h` to get PF_RING ZC version.
 1. Go to http://shop.ntop.org/mkzclicense/
 1. Fill in the MAC address, OrderId, and PF_RING ZC Version.
    Select Product Family PF_RING ZC 10/40/100 Gbit [Intel].
 1. Click the "Create PF_RING License" button.
 1. Follow the next page's instructions. (After putting the license key string
    in the MAC-address-named file, you're all set - don't even need to reboot!)
    You can verify the registration with `sudo ./zcount -C -i zc:enp5s0f0`

# Running the station without zero-copy

If you have previously configured the station for ZC operation, *you must reboot
in order to run non-ZC!* (You can run non-ZC and then switch to ZC without
rebooting).

To run the non-zero-copy multi-process TapDance station, follow the installation
and setup instructions as above, but:

 1. Rather than `sudo ./startup.sh`, run `sudo ./startup.sh --nozerocopy`.
 1. Rather than `./scripts/tapdance-build.sh`, run `./scripts/tapdance-build.sh --nozerocopy`.
 1. When running the station, you do not need `zbalance_ipc` at all.
 1. Run the station with `sudo RUST_BACKTRACE=1 ./tapdance -i $INTERFACE -c 7 -o 0 -n 4 -K /path/to/privkey`.

The gobbler remains the same. Running tapdance-prereqs.sh remains the same.
n and c are the same as in the ZC version; -o is core id offset. (So, -o 3 -n 4
would use cores 3,4,5,6).
