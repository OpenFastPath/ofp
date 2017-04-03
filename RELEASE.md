# OpenFastPath Angelfish 2.0.1

Repository                          | Branch    | Tag
------------------------------------|-----------|------
https://github.com/OpenFastPath/ofp | angelfish | 2.0.1

## Dependencies

OpenDataPlane v1.11.0.0 Monarch.

## Changes (since 2.0.0)

### Highlights

* Various TCP fixes and performance improvements.

### Resolved Issues

* #85 Adding new rules is inefficient
* #93 Data corruption - tcp packets dropped in the receive path
* #98 TCP timers problems
* #101 Wrong netmask when configuring interface address through CLI
* #112 OFP TCP crash with sigevent
* #114 ofp_rt_rule_find_prefix_match mix use of big-endian data
* #115 ofp_rt_rule_find_prefix_match use incorrect masklen to
* #116 ofp_rtl_remove will re-insert the route it just
* #118 NODEALLOC does not reset next pointer and lead to
* #119 Left bit shift result in UB
* #142 fpm command line option -c doesn't work
* #144 Hard coded TCP MSS value to 960 bytes
* #146 mcasttest thread terminate once startup

### API and ABI Changes

#### Library Version Changes

* libofp.so: 2.0.0 -> 2.0.1

## Unit Testing

Environment | ODP Variant | Test Cases Total | Pass | Fail
------------|-------------|------------------|------|-----
x86-64      | odp-linux   | 105              | 105  | 0

## For More Information

See project home page http://www.openfastpath.org
