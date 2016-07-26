#!/usr/bin/env bash

set -xe

PROJECT_NAME=neutron-dynamic-routing
GATE_DEST=$BASE/new
NEUTRON_PATH=$GATE_DEST/neutron
DR_PATH=$GATE_DEST/$PROJECT_NAME
DEVSTACK_PATH=$GATE_DEST/devstack

VENV=${1:-"dsvm-functional"}


if [[ "$VENV" == dsvm-functional* ]]
then
    # The following need to be set before sourcing
    # configure_for_func_testing.
    GATE_STACK_USER=stack
    IS_GATE=True

    source $DEVSTACK_PATH/functions
    source $NEUTRON_PATH/devstack/lib/ovs
    source $NEUTRON_PATH/tools/configure_for_func_testing.sh

    enable_plugin $PROJECT_NAME https://git.openstack.org/openstack/$PROJECT_NAME

    # Make the workspace owned by the stack user
    sudo chown -R $STACK_USER:$STACK_USER $BASE

elif [[ "$VENV" == dsvm-api* ]] || [[ "$VENV" == dsvm-scenario* ]]
then
    if ! pip freeze | grep ryu > /dev/null
    then
        sudo pip install ryu
    fi
    RYU_PATH=`pip show ryu | grep Location | cut -d' ' -f2`/ryu
    source $DEVSTACK_PATH/functions
    sudo usermod -aG sudo tempest
    bash $RYU_PATH/tests/integrated/common/install_docker_test_pkg.sh --sudo-pip

    $GATE_DEST/devstack-gate/devstack-vm-gate.sh
fi
