#!/bin/bash

# Script used with Drone CI to upload docs 

set -o errexit

if [ -z "$SSH_KEY" ]; then
    echo -e "\n\n\n\e[31;1mUnable to upload debs: SSH_KEY not set\e[0m"
    # Just warn but don't fail, so that this doesn't trigger a build failure for untrusted builds
    exit 0
fi

# First argument passed to the script
language="$1"

if [ "$language" == "cpp" ] || [ "$language" == "c" ]; then
    upload_to="/home/apidocs/www/libsession-util-$language/"
else
    echo "Invalid argument. Please specify either 'cpp' or 'c'"
    exit 1
fi

echo "$SSH_KEY" >~/ssh_key

set -o xtrace  # Don't start tracing until *after* we write the ssh key

chmod 600 ~/ssh_key


sftp -i ~/ssh_key -b - -o StrictHostKeyChecking=off apidocs@chianina.oxen.io <<SFTP
put -r ./api/* $upload_to
SFTP

set +o xtrace

echo -e "\n\n\n\n\e[32;1mUploaded docs to https://${upload_to}/\e[0m\n\n\n"

