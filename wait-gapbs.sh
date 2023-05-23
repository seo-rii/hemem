#!/bin/bash

while [[ $( grep "source" $1 ) -eq "" ]]
do
        sleep 1
        #echo "Waiting for graph setup"
done

echo "Graph setup"
