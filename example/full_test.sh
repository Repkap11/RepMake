#!/bin/bash
make clean
rm .RepDep

echo
echo "### Iterative Build ###"
echo

while ! make; do :; done

echo
echo "### Full Build ###"
echo
make clean
make
