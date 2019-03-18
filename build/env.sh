#!/bin/sh

set -e

if [ ! -f "build/env.sh" ]; then
    echo "$0 must be run from the root of the repository."
    exit 2
fi

checkGoVersion()
{
    #Recommended Version 1.10.1
    V1=1
    V2=10
    V3=1

    echo The minimum golang version required is: $V1.$V2.$V3

    #Get golang current version
    CV1=`go version 2>&1|awk '{print $3}'|awk -F '.' '{print $1}'|awk -F, '{print substr($1,length($1)-0)}'`
    CV2=`go version 2>&1|awk '{print $3}'|awk -F '.' '{print $2}'`
    CV3=`go version 2>&1|awk '{print $3}'|awk -F '.' '{print $3}'`

    echo Your current golang version is : $CV1.$CV2.$CV3

    if [ $CV1 -lt $V1 ];then
        echo 'Please update to version 1.10 or higher'
        exit 1
    elif [ $CV1 -eq $V1 ];then
        if [ $CV2 -lt $V2 ];then
            echo 'Please update to version 1.10 or higher'
            exit 1
        elif [ $CV2 -eq $V2 ];then
            if [ $CV3 -lt $V3 ];then
                echo 'Please update to version 1.10 or higher'
                exit 1
            fi
        fi
    fi
}
checkGoVersion
echo Your golang version is OK!

# Create fake Go workspace if it doesn't exist yet.
workspace="$PWD/build/_workspace"
root="$PWD"
usedir="$workspace/src/github.com/usechain"
if [ ! -L "$usedir/go-usechain" ]; then
    mkdir -p "$usedir"
    cd "$usedir"
    ln -s ../../../../../. go-usechain
    cd "$root"
fi

# Set up the environment to use the workspace.
GOPATH="$workspace"
export GOPATH

# Run the command inside the workspace.
cd "$usedir/go-usechain"
PWD="$usedir/go-usechain"

# Launch the arguments with the configured environment.
exec "$@"
