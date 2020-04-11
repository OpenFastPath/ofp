#!/bin/bash

export ROOT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

export OFP_NETWRAP_ENV_DEFAULT="-i eth1 -f ${ROOT_DIR}/ofp_netwrap.cli"
export OFP_NETWRAP_ENV="${OFP_NETWRAP_ENV:-${OFP_NETWRAP_ENV_DEFAULT}}"

LD_PRELOAD=libofp_netwrap_crt.so.0.0.0:libofp_netwrap_proc.so.0.0.0:libofp.so.0.0.0 $@
