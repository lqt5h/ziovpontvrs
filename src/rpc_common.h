#pragma once

#include <windows.h>
#include <rpc.h>

/* ALPC transport + well-known endpoint shared by client and server. */
#define ZIOVPONTVRS_RPC_PROTSEQ   ((RPC_WSTR)L"ncalrpc")
#define ZIOVPONTVRS_RPC_ENDPOINT  ((RPC_WSTR)L"ZiovpontvrsRpcEndpoint")
