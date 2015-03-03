/*
  This program is a re-implementation of the telnet console enabler utility
  for use with Netgear wireless routers.

  The original Netgear Windows binary version of this tool is available here:
  http://www.netgear.co.kr/Support/Product/FileInfo.asp?IDXNo=155

  Per DMCA 17 U.S.C. §1201(f)(1)-(2), the original Netgear executable was
  reverse engineered to enable interoperability with other operating systems
  not supported by the original windows-only tool (MacOS, Linux, etc).

        Netgear Router - Console Telnet Enable Utility
        Release 0.1 : 25th June 2006
        Copyright (C) 2006, yoshac @ member.fsf.org
        Release 0.2 : 20th August 2012
        dj bug fix on OS X
        Release 0.3 : 8th October 2012
        keithr-git bug fix to send entire packet in one write() call,
          strcpy->strncpy, clean up some whitespace

        This program is free software; you can redistribute it and/or modify
        it under the terms of the GNU General Public License as published by
        the Free Software Foundation; either version 2 of the License, or
        (at your option) any later version.

        This program is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        GNU General Public License for more details.

        You should have received a copy of the GNU General Public License along
        with this program; if not, write to the Free Software Foundation, Inc.,
        51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.


  The RSA MD5 and Blowfish implementations are provided under LGPL from
  http://www.opentom.org/Mkttimage
*/

#include <arpa/inet.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "md5.h"
#include "blowfish.h"

static char output_buf[0x640];
static BLOWFISH_CTX ctx;

struct PAYLOAD
{
  char signature[0x10];
  char mac[0x10];
  char username[0x10];
  char password[0x21];
  char reserved[0x2F];
} payload;

int usage(char * progname)
{
  printf("\nVersion: 0.4, 2015/02/12\n");
  printf("Modified to work with newer Negear routers R7000 R7500 by insanid\n");
  printf("\nUsage:\n%s <host ip> <host mac> <user name> <password>\n\n",progname);
  return -1;
}

int socket_connect(char * host, char * port)
{
  struct addrinfo hints;
  struct addrinfo * results;
  struct addrinfo * i;
  struct sockaddr_in addr;
  int sock = -1;
  int status;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;

  status = getaddrinfo(host, port, &hints, &results);
  if (status != 0)
  {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
    return -1;
  }

  for (i = results; i != NULL; i = i->ai_next)
  {
    sock = socket(i->ai_family, i->ai_socktype, i->ai_protocol);
    if (sock == -1)
    {
      perror("socket");
      continue;
    }

    status = connect(sock, i->ai_addr, i->ai_addrlen);
    if (status != -1)
      break;
    else
    {
      perror("connect");
      close(sock);
    }
  }

  freeaddrinfo(results);
  return sock;
}

int GetOutputLength(unsigned long lInputLong)
{
  unsigned long lVal = lInputLong % 8;

  if (lVal!=0)
    return lInputLong+8-lVal;
  else
    return lInputLong;
}

int EncodeString(BLOWFISH_CTX *ctx,char *pInput,char *pOutput, int lSize)
{
  int SameDest = 0;
  int lCount;
  int lOutSize;
  int i=0;

  lOutSize = GetOutputLength(lSize);
  lCount=0;
  while (lCount<lOutSize)
    {
      char *pi=pInput;
      char *po=pOutput;
      for (i=0;i<8;i++)
        *po++=*pi++;
      Blowfish_Encrypt(ctx,(uint32_t *)pOutput,(uint32_t *)(pOutput+4));
      pInput+=8;
      pOutput+=8;
      lCount+=8;
    }

  return lCount;
}


int fill_payload(int argc, char * input[])
{
  MD5_CTX MD;
  char MD5_key[0x10];
  char secret_key[0x400]="AMBIT_TELNET_ENABLE+";
  int encoded_len;

  memset(&payload, 0, sizeof(payload));
  // NOTE: struct has .mac behind .signature and is filled here
  strcpy(payload.mac, input[2]);
  strcpy(payload.username, input[3]);

  if (argc==5)
    strcpy(payload.password, input[4]);


  MD5Init(&MD);
  MD5Update(&MD,payload.mac,0x70);
  MD5Final(MD5_key,&MD);

  strncpy(payload.signature, MD5_key, sizeof(payload.signature));
  // NOTE: so why concatenate outside of the .signature boundary again
  //       using strcat? deleting this line would keep the payload the same and not
  //       cause some funky abort() or segmentation fault on newer gcc's
  // dj: this was attempting to put back the first byte of the MAC address
  // dj: which was getting stomped by the strcpy of the MD5_key above
  // dj: a better fix is to use strncpy to avoid the stomping in the 1st place
  //  strcat(payload.signature, input[2]);

  if (argc==5)
    strncat(secret_key,input[4],sizeof(secret_key) - strlen(secret_key) - 1);

  Blowfish_Init(&ctx,secret_key,strlen(secret_key));

  encoded_len = EncodeString(&ctx,(char*)&payload,(char*)&output_buf,0x80);

  return encoded_len;
}

int main(int argc, char * argv[])
{
  char * telnet_port = "23";
  int datasize;
  int sock;
  int i;

  if (argc != 5)
    return usage(argv[0]);

  datasize = fill_payload(argc, argv);
  if (datasize == -1)
    return -1;

  sock = socket_connect(argv[1], telnet_port);
  write(sock, output_buf, datasize);
  close(sock);

  printf("\nPayload has been sent to Netgear router.\n");
  printf("Telnet should be enabled.\n\n");

  return 0;
}
