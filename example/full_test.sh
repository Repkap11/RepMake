#!/bin/bash
make clean
rm -f RepDep.d

echo
echo "### Iterative Build ###"
echo

while ! make; do :; done
make

echo
echo "### Full Build ###"
echo
make clean
make
