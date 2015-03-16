#! /usr/bin/env perl

use strict;
use warnings;

use IO::Handle;
use IO::Socket;
$| = 1;

sub test_server {
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
  my $buf;
  my $sock = new IO::Socket::INET (
    LocalPort => 50023,
    Proto => "udp",
    Reuse => 1
  ) or die "socket server: $!\n";

  $sock->recv($buf, 1024);
  &check_data("tests/test_1.bin", $buf);

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

  sub assert {
    my $title = $_[0];
    my $left = $_[1];
    my $right = $_[2];

    printf "$title";
    if ($left eq $right) {
      printf "[OK]\n";
    } else {
      printf "FAILED!\nExpected: '%s'\nWas: '%s'\n", $right, $left;
      exit 1;
    }
  }

  my $generic_good_response = "\nPayload has been sent to Netgear router.\nTelnet should be enabled.\n\n";
  my $response;
  my $expected_response;
  sleep 1;

  # Generic good usage
  $response = &telnetenable("DEBUG", "AABBCCDDEEFF", "user", "passwd");
  &assert("Test 1 (Successful Usage):\t", $response, $generic_good_response);

  # Too long MAC
  $response = &telnetenable("DEBUG", "0123456789ABCDEF", "user", "passwd");
  $expected_response = "./telnetenable: 0123456789ABCDEF: The mac address should be the MAC address of the LAN port on your Netgear device, WITHOUT the \":\". e.g. \"00:40:5E:21:14:4E\" would be written as \"00405E21144E\"\n";
  &assert("Test 2 (Too Long MAC):\t\t", $response, $expected_response);

  # Long, but still ok MAC (Why not?)
  $response = &telnetenable("DEBUG", "0123456789ABCDE", "user", "passwd");
  &assert("Test 3 (Pretty Long MAC):\t", $response, $generic_good_response);

  # Too long username
  $response = &telnetenable("DEBUG", "AABBCCDDEEFF", "0123456789ABCDEF", "passwd");
  $expected_response = "./telnetenable: 0123456789ABCDEF: Too long username. Max length is 15 characters.\nThe username should probably be 'admin'\n";
  &assert("Test 4 (Too Long Username):\t", $response, $expected_response);

  # Good username length
  $response = &telnetenable("DEBUG", "AABBCCDDEEFF", "0123456789ABCDE", "passwd");
  &assert("Test 5 (Good Username Length):\t", $response, $generic_good_response);

  #Too long password
  $response = &telnetenable("DEBUG", "A", "A", "0123456789ABCDEF0123456789ABCDEF0");
  $expected_response = "./telnetenable: 0123456789ABCDEF0123456789ABCDEF0: Too long password. Max length is 32 characters\n";
  &assert("Test 6 (Too Long Password):\t", $response, $expected_response);

  # Good length password
  $response = &telnetenable("DEBUG", "A", "A", "0123456789ABCDEF0123456789ABCDEF");
  &assert("Test 7 (OK Length Password):\t", $response, $generic_good_response);

  printf "\nAll tests OK\n";
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

