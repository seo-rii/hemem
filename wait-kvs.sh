#!/bin/bash

while [[ $( grep "Starting" $1 ) -eq "" ]]
do
        sleep 1
        #echo "Waiting for graph setup"
done

echo "FlexKVS setup"
