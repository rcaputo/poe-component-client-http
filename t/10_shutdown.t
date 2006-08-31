#!/usr/bin/perl -w
# $Id$
# vim: filetype=perl

use strict;

use HTTP::Request::Common qw(GET POST);

sub POE::Kernel::ASSERT_DEFAULT () { 1 }
use POE qw(Component::Client::HTTP Component::Client::Keepalive);

sub DEBUG () { 0 }

use Test::More tests => 1;

# Create a weeble component.
POE::Component::Client::HTTP->spawn( Timeout => 60 );

# Create a session that will make some requests.
POE::Session->create(
  inline_states => {
    _start              => \&client_start,
    _stop               => \&client_stop,
    got_response        => \&client_got_response,
    do_shutdown         => \&client_got_shutdown,
    do_setup            => \&client_got_setup,
  },
);

# Run it all until done.
$poe_kernel->run();

exit;

sub client_start {
  my ($kernel, $heap) = @_[KERNEL, HEAP];

  DEBUG and warn "client starting...\n";

  $kernel->yield("do_setup");
  $kernel->yield("do_shutdown");
}

sub client_got_setup {
  my $kernel = $_[KERNEL];
  DEBUG and warn "client got setup...\n";

  for (1..2) {
    $kernel->post(
      weeble => request => got_response =>
      GET('http://poe.perl.org/misc/test.html', Connection => 'close'),
    );
  }
}

sub client_got_shutdown {
  my $kernel = $_[KERNEL];
  DEBUG and warn "client got shutdown...\n";
  $kernel->post(weeble => "shutdown");
}

sub client_stop {
  my $heap = $_[HEAP];
  DEBUG and warn "client stopped...\n";

  is_deeply(
    $heap->{got_response},
    { 408 => 2 },
    "Got two 408s (time outs)"
  );
}

sub client_got_response {
  my ($heap, $kernel, $request_packet, $response_packet) = @_[
    HEAP, KERNEL, ARG0, ARG1
  ];
  my $http_request  = $request_packet->[0];
  my $http_response = $response_packet->[0];

  DEBUG and do {
    warn "client got response...\n";

    warn $http_request->as_string;
    my $response_string = $http_response->as_string();
    $response_string =~ s/^/| /mg;

    warn ",", '-' x 78, "\n";
    warn $response_string;
    warn "`", '-' x 78, "\n";
  };

  # Track how many of each response code we get.
  # Should be two 408s, indicating two connection timeouts.
  $heap->{got_response}{$http_response->code()}++;
}
