#! /usr/bin/env perl

use strict;
use warnings;

use IO::Handle;
use IO::Socket;
$| = 1;

sub test_server {
  sub start_listening {
    my $sock = new IO::Socket::INET (
      LocalPort => 50023,
      Proto => "udp",
      Reuse => 1
    ) or die "socket server: $!\n";
    return $sock;
  }

  sub socket_getdata {
    my $sock = $_[0];
    my $buf;
    $sock->recv($buf, 1024);
    return $buf;
  }

  sub check_data {
    my $filename = $_[0];
    my $string = $_[1];
    my $data;

    open my $fh, "<", $filename or die "$filename: $!\n";
    {
      local $/;
      $data = <$fh>;
    }
    close $fh;
    die "test for $filename failed!\n" if $data ne $string;
  }

  my $wait_for_pid = $_[0];

  my $sock = &start_listening();
  &check_data("test_1.bin", &socket_getdata($sock));

  $sock->close();
  waitpid $wait_for_pid, 0;
  exit 0;
}

sub test_client {
  sub telnetenable {
    my $ip = $_[0];
    my $mac = $_[1];
    my $username = $_[2];
    my $password = $_[3];
    my $results = qx "./telnetenable $ip $mac $username $password 2>&1";
    return $results;
  }

  my $expected_response;
  sleep 1;

  $expected_response = "\nPayload has been sent to Netgear router.\nTelnet should be enabled.\n\n";
  if (&telnetenable("DEBUG", "AABBCCDDEEFF", "user", "passwd") ne $expected_response) {
    printf "Test 1 (Successfull Usage) failed\n";
  }

  $expected_response = "./telnetenable: 0123456789ABCDEF: The mac address should be the MAC address of the LAN port on your Netgear device, WITHOUT the \":\". e.g. \"00:40:5E:21:14:4E\" would be written as \"00405E21144E\"\n";
  if (&telnetenable("DEBUG", "0123456789ABCDEF", "user", "passwd") ne $expected_response) {
    printf "Test 2 (MAC Length) failed\n";
  }

  $expected_response = "./telnetenable: 0123456789ABCDEF: Too long username. Max length is 15 characters.\nThe username should probably be 'admin'\n";
  if (&telnetenable("DEBUG", "AABBCCDDEEFF", "0123456789ABCDEF", "passwd") ne $expected_response) {
    printf "Test 3 (Username Length) failed\n";
  }

  $expected_response = "./telnetenable: 0123456789ABCDEF0123456789ABCDEF0: Too long password. Max length is 32 characters\n";
  if (&telnetenable("DEBUG", "A", "A", "0123456789ABCDEF0123456789ABCDEF0") ne $expected_response) {
    printf "Test 4 (Password Length) failed\n";
  }

  exit 0;
}

# Main
my $pid = fork();
if (!defined $pid) {
  die "fork: $!\n";

} elsif ($pid == 0) {
  &test_client();

} else {
  &test_server($pid);
}

