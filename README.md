# Hydrangea

## Overview

This repository is a usecase of a unikernel-based cloud operating system.
Recently, in order to provide services, telecommunication companies are changing from the existing hardware equipment-based to network function virtualization (NFV). In this environment, existing VM-based virtualization is heavy and vulnerable to security, so it is necessary to build an environment based on unikernel and SGX.
Hydrangea provides VNF as a unikernel based on the Intel SGX platform. Software Guard Extension (SGX) is a Trusted Execution Environment (TEE) technology that protects applications from highly privileged software and hardware. In particular, it provides system call-level access control based on a white list, so it has fast performance and strong security features.

This usecase require a sgx kernel and a web servers engine, however, this repo only corresponds to the kernel part of them.

This project is proviced under the terms of the GNU General Public License v3.0.

## Environments

- OS : Ubuntu 18.04
- Intel SGX Driver : sgx_linux_x64_driver_2.11.0_2d2b795.bin
- Intel DCAP Driver : sgx_linux_x64_driver_1.41.bin
- SGX PSW Driver : 2.15.101.1-bionic1
- Software : Python 3.6.9, Docker 20.10.10, Django 3.2.9

## How to build

1. Clone base kernel codes from sgx-lkl
```
# git clone https://github.com/lsds/sgx-lkl.git
```
2. Clone and copy of the developed codes
```
# git clone https://github.com/oslab-swrc/Hydrangea.git
# cp -R Hydrangea/src/* sgx-lkl/
```
3. Build according to the sgx-lkl installation guide
4. Install SGX, DCAP, and PSW drivers
5. Execute after installing web engine.

## Reference 

Youtube: [Secure Virtual Network Services](https://youtu.be/w7xDt8hplo8)
