#!/bin/sh

[ $# -eq 1 ] || { cat << EOUSE ; exit 1 ; }
  Usage: $0 [major | minor | patch]

Release mailin.
EOUSE

cargo release --execute --tag-prefix mailin- $1
