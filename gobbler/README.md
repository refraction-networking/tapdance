Tapdance Statistics Reporting (Gobble Gobble)
===

Gobbler is a separate process to monitor the status of a tapdance station and
report statistics to a centralized collector using the graphite protocol.

Reports are sent using the graphite plaintext (newline separated) protocol
over a TLS socket.

The collector should be configured to map the graphite reports into tagged groups,
using the following mapping:

```
tapdance.gobbler.*.*.*.count
name="tapdance_gobbler_total"
hostname="$1"
core="$2"
action="$3"

tapdance.gobbler.*.*.*.count_ps
name="tapdance_gobbler_rate"
hostname="$1"
core="$2"
action="$3"
```

If you create any new .go files in this directory, please be sure to add them
as dependencies in the Makefile.
