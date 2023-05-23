#!/bin/bash

while [[ $( grep "Initialization" $1 ) -eq "" ]]
do
        sleep 1
        #echo "Waiting for graph setup"
done

echo "GUPS Ready"
