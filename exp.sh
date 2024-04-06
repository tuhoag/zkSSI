#!/bin/zsh

set -x
MODE=1
HEIGHT=16
CONDITIONS=10
{ set +x; } 2>/dev/null

if [ $MODE -eq 0 ]
then
    set -x
    hh noir generate-verifier-contract --circuit vcp_generation
    { set +x; } 2>/dev/null
else
    set -x
    hh noir generate-verifier-contract --circuit mono_vcp_generation
    { set +x; } 2>/dev/null
fi

for networkName in iota
do
    if [ $MODE -eq 0 ]
    then
        set -x
        h=$HEIGHT c=$CONDITIONS m=$MODE hh run scripts/estimate_gas.ts  --network $networkName
        { set +x; } 2>/dev/null
    else
        set -x
        h=$HEIGHT c=10 m=$MODE hh run scripts/estimate_gas.ts  --network $networkName
        { set +x; } 2>/dev/null
    fi
done