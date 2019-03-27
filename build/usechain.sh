#!/bin/bash
# prepair test configuration files, certifications and keys for user
# zhouhh@usechain.net 
# 2018.07.30
#
OS="LINUX"
LinuxConfigDir="${HOME}/.usechain"
OSXConfigDir=${HOME}/Library/usechain
WindowsConfigDir=${HOME}/AppData/Roaming/usechain
ConfigDir="$LinuxConfigDir"

case "$OSTYPE" in
  solaris*) OS="SOLARIS" ;;
  linux*)   OS="LINUX" ;;
  bsd*)     OS="BSD" ;; 
  darwin*)  OS="OSX" ; ConfigDir=$OSXConfigDir;; # Mac 
  msys*)    OS="WINDOWS" ; ConfigDir=$WindowsConfigDir;;# Git Bash/msysGit
  cygwin*)  OS="WINDOWS" ; ConfigDir=$WindowsConfigDir;; # Cygwin
  *)        OS="UNKNOWN"; echo "unknown: $OSTYPE" ;;
esac

echo 
echo "OS:$OS"
echo "Usechain ConfigDir: $ConfigDir"
if [ ${OS}x == "UNKNOWN"x ]; then
    echo "error OS $OSTYPE not supported, exit ..."
    exit;
fi

cur_dir=$(cd "$(dirname "$0")"; pwd)

# make config directory for user
if [ ! -d $ConfigDir ]; then
    echo "mkdir $ConfigDir"
    mkdir -p $ConfigDir 
fi

echo "prepare configure files...."

usercrt=$ConfigDir/user.crt
if [ ! -f "$usercrt" ]; then
    cp  $cur_dir/config/profile/user.crt $ConfigDir/.
fi

rcacrt=$ConfigDir/rca.crt
if [ ! -f "$rcacrt" ]; then
    cp  $cur_dir/config/profile/rca.crt $ConfigDir/.
fi

rcacrt=$ConfigDir/mainnet.pem
if [ ! -f "$rcacrt" ]; then
    cp  $cur_dir/config/profile/mainnet.pem $ConfigDir/.
fi

committee=$ConfigDir/committee.cfg
if [ ! -f "$committee" ]; then
    cp  $cur_dir/config/profile/committee.cfg $ConfigDir/.
fi

userrsaprv=$ConfigDir/userrsa.prv
if [ ! -f "$userrsaprv" ]; then
    cp  $cur_dir/config/profile/userrsa.prv $ConfigDir/.
fi

userrsapub=$ConfigDir/userrsa.pub
if [ ! -f "$userrsapub" ]; then
    cp  $cur_dir/config/profile/userrsa.pub $ConfigDir/.
fi

cd $ConfigDir 

echo "ls $ConfigDir:"
ls $ConfigDir

echo
echo "Done!"
