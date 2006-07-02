#!/usr/bin/perl -w
# $Id$
# vim: filetype=perl

use strict;

use HTTP::Request::Common qw(GET POST);

use lib '/home/troc/perl/poe';
sub POE::Kernel::ASSERT_DEFAULT () { 1 }
use POE qw(Component::Client::HTTP Component::Client::Keepalive);

sub DEBUG () { 0 }

sub MAX_BIG_REQUEST_SIZE  () { 4096 }
sub MAX_STREAM_CHUNK_SIZE () { 1024 }  # Needed for agreement with test CGI.

use Test::More tests => 1;

# Create the HTTP client session.

POE::Component::Client::HTTP->spawn(
  Streaming => MAX_STREAM_CHUNK_SIZE,
  Alias     => "streamer",
);

# Create a session that will make and handle some requests.

POE::Session->create(
  inline_states => {
    _start        => \&client_start,
    _stop         => \&client_stop,
    got_response  => \&client_got_response,
  }
);

# Run it all until done.

POE::Kernel->run();
exit;

### Event handlers begin here.

sub client_start {
  my ($kernel, $heap) = @_[KERNEL, HEAP];

  DEBUG and warn "client starting...\n";

  $kernel->post(
    streamer => request => got_response =>
    GET(
      'http://poe.perl.org/misc/chunk-test.cgi',
      Connection => 'close',
    ),
  );
}

sub client_stop {
  DEBUG and warn "client stopped...\n";
}

my $total_octets_got = 0;
my $chunk_buffer = "";
my $next_chunk_character = "A";

sub client_got_response {
  my ($heap, $request_packet, $response_packet) = @_[HEAP, ARG0, ARG1];
  my $http_request = $request_packet->[0];
  my ($http_headers, $chunk) = @$response_packet;

  DEBUG and do {
    warn "client got stream request...\n";

    my $response_string = $http_headers->as_string();
    $response_string =~ s/^/| /mg;

    warn ",", '-' x 78, "\n";
    warn $response_string;
    warn "`", '-' x 78, "\n";
    warn ($chunk ? $chunk : "(undef)"), "\n";
    warn "`", '-' x 78, "\n";
  };

  if (defined $chunk) {
    $chunk_buffer .= $chunk;
    $total_octets_got += length($chunk);
    while (length($chunk_buffer) >= MAX_STREAM_CHUNK_SIZE) {
      my $next_chunk = substr($chunk_buffer, 0, MAX_STREAM_CHUNK_SIZE);
      substr($chunk_buffer, 0, MAX_STREAM_CHUNK_SIZE) = "";
      $next_chunk_character++;
    }
    $_[KERNEL]->post( streamer => cancel => $_[ARG0][0] );
    return;
  }

  $total_octets_got += length($chunk_buffer);
  ok (
    ($total_octets_got == MAX_STREAM_CHUNK_SIZE),
    "wanted total(" . MAX_STREAM_CHUNK_SIZE . ") got $total_octets_got"
  );
}
