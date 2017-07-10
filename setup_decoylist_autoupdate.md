# Make station auto-update with daily decoy list

As tapdance-prod, clone git@gitlab.decoyrouting.com:decoy/decoy-lists.git into /home/tapdance-prod/. Make sure that the tapdance-prod user can `git pull` inside of the cloned repo non-interactively. (The station is supposed to be already configured to allow tapdance-prod to pull from our repos.)

Set the update_decoy_list.sh script in that repo to run once every 5 minutes:

`sudo crontab -e`

add the following line:

`*/5 * * * * /home/tapdance-prod/decoy-lists/update_decoy_list.sh`

TODO: puppet? I see a couple of machines' root crontab files have stuff about "managed by puppet, it's ok to make your own changes here, but maybe avoid that"
