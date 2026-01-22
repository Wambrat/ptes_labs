#!/bin/bash

cd /tmp/
tar -xzf ptes-lab-complete.tar.gz
for vma in vzdump-*.vma.zst; do
  qmrestore \$vma \$(echo \$vma | grep -o '[0-9]*') --storage local-lvm
done
