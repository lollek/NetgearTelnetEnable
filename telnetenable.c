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

#ifdef _WIN32
/* Will add this later. For now, use telnetenable-win.c */
#endif

#ifdef __gnu_linux__
#include <arpa/inet.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "md5.h"
#include "blowfish.h"

#define SIGNATURE_LEN 0x10
#define MAC_LEN 0x10
#define USERNAME_LEN 0x10
#define PASSWORD_LEN 0x21

struct PAYLOAD
{
  char signature[SIGNATURE_LEN];
  char mac[MAC_LEN];
  char username[USERNAME_LEN];
  char password[PASSWORD_LEN];
  char reserved[0x2F];
};

static int
sanitize_argv(int argc, char * argv[])
{
  if (argc != 5)
  {
    fprintf(stderr,
           "\nVersion: 0.4.1, 2015/03/03\n"
           "Modified to work with newer Negear routers R7000 R7500 by insanid\n"
           "\nUsage:\n%s <host ip> <host mac> <user name> <password>\n\n", argv[0]);
    return -1;
  }

  if (strlen(argv[2]) > MAC_LEN)
  {
    fprintf(stderr,
            "%s: %s: The mac address should be the MAC address of the "
            "LAN port on your Netgear device, WITHOUT the \":\". e.g. "
            "\"00:40:5E:21:14:4E\" would be written as \"00405E21144E\"\n",
            argv[0], argv[2]);
    return -1;
  }

  if (strlen(argv[3]) > USERNAME_LEN)
  {
    fprintf(stderr,
            "%s: %s: Too long username. Max length is %d characters.\n"
            "The username should probably be 'admin'\n",
            argv[0], argv[3], USERNAME_LEN);
    return -1;
  }

  if (strlen(argv[4]) > PASSWORD_LEN)
  {
    fprintf(stderr,
            "%s: %s: Too long password. Max length is %d characters\n",
            argv[0], argv[4], PASSWORD_LEN);
    return -1;
  }

  return 0;
}

static int
socket_connect(char * host, char * port)
{
  struct addrinfo hints;
  struct addrinfo * results;
  struct addrinfo * i;
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

static int
get_output_length(unsigned long l)
{
  unsigned long mod8 = l % 8;
  return mod8 ? l + 8 - mod8 : l;
}

static int
encode_string(BLOWFISH_CTX * ctx, char * pInput, char * pOutput, int lSize)
{
  int lCount;
  int lOutSize;
  int i=0;

  lOutSize = get_output_length(lSize);
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


static int
fill_payload(char * input[], char * output)
{
  BLOWFISH_CTX blowfish_context;
  MD5_CTX md5_context;
  struct PAYLOAD payload;
  char secret_key[0x400] = "AMBIT_TELNET_ENABLE+";

  memset(&payload, 0, sizeof(payload));

  strcpy(payload.mac, input[2]);
  strcpy(payload.username, input[3]);
  strcpy(payload.password, input[4]);

  MD5Init(&md5_context);
  MD5Update(&md5_context, (unsigned char *)payload.mac, 0x70);
  MD5Final((unsigned char *)payload.signature, &md5_context);

  strncat(secret_key, input[4], sizeof(secret_key) - strlen(secret_key) - 1);

  Blowfish_Init(&blowfish_context, (unsigned char *)secret_key, strlen(secret_key));
  return encode_string(&blowfish_context, (char *)&payload, output, 0x80);
}

int
main(int argc, char * argv[])
{
  char * telnet_port = "23";
  char buf[0x640];
  int datasize;
  int sock;

  memset(buf, 0, sizeof(buf));

  if (sanitize_argv(argc, argv) != 0)
    return -1;

  datasize = fill_payload(argv, buf);
  if (datasize == -1)
    return -1;

  sock = socket_connect(argv[1], telnet_port);
  write(sock, buf, datasize);
  close(sock);

  printf("\nPayload has been sent to Netgear router.\n");
  printf("Telnet should be enabled.\n\n");

  return 0;
}
