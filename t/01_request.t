#!/usr/bin/perl -w
# $Id$

use strict;

use HTTP::Request::Common qw(GET POST);

use lib '/home/troc/perl/poe';
sub POE::Kernel::ASSERT_DEFAULT () { 1 }
use POE qw(Component::Client::HTTP);

sub DEBUG () { 0 }

sub MAX_BIG_REQUEST_SIZE  () { 4096 }
sub MAX_STREAM_CHUNK_SIZE () { 1024 }  # Needed for agreement with test CGI.

$| = 1;
print "1..8\n";

my @test_results = ( 'not ok 1', 'not ok 2', 'not ok 3', 'not ok 4',
                     'ok 5', 'not ok 6', 'not ok 7', 'not ok 8',
                   );

BEGIN {
  my $has_ssl = 0;
  eval { require Net::SSLeay::Handle;
         $has_ssl = 1;
       };
  eval "sub HAS_SSL () { $has_ssl }";
}

#------------------------------------------------------------------------------

sub client_start {
  my ($kernel, $heap) = @_[KERNEL, HEAP];

  DEBUG and warn "client starting...\n";

  $kernel->post( weeble => request => got_response =>
                 GET 'http://poe.perl.org/misc/test.html'
               );

  $kernel->post( weeble => request => got_response =>
                 ( POST 'http://poe.perl.org/misc/test.cgi',
                   [ cgi_field_one => '111',
                     cgi_field_two => '222',
                     cgi_field_six => '666',
                     cgi_field_ten => 'AAA',
                   ]
                 )
               );

  $kernel->post( weeble => request => got_response =>
                 GET 'http://poe.perl.org/misc/test.cgi?cgi_field_fiv=555',
               );

  if (HAS_SSL) {
    my $secure_request = GET 'https://sourceforge.net/projects/poe/';
    $kernel->post( weeble => request => got_response =>
                   $secure_request,
                 );
  }
  else {
    $test_results[3] = 'ok 4 # skipped: need Net::SSLeay::Handle to test SSL';
  }

  $kernel->post( weeble => request => got_response =>
                 GET 'http://poe.perl.org',
               );

  $kernel->post( weeble => request => got_response =>
                 GET 'http://foo.poe.perl.org/'
               );

  $kernel->post( weeble => request => got_big_response =>
                 GET 'http://poe.perl.org/misc/stream-test.cgi'
               );

  $kernel->post( streamer => request => got_stream_response =>
                 GET 'http://poe.perl.org/misc/stream-test.cgi'
               );
}

sub client_stop {
  DEBUG and warn "client stopped...\n";
  foreach (@test_results) {
    print "$_\n";
  }
}

sub client_got_response {
  my ($heap, $request_packet, $response_packet) = @_[HEAP, ARG0, ARG1];
  my $http_request  = $request_packet->[0];
  my $http_response = $response_packet->[0];

  DEBUG and do {
    warn "client got request...\n";

    my $response_string = $http_response->as_string();
    $response_string =~ s/^/| /mg;

    warn ",", '-' x 78, "\n";
    warn $response_string;
    warn "`", '-' x 78, "\n";
  };

  my $request_path = $http_request->uri->path . ''; # stringify

  if (defined $http_response->code) {
    my $response_string = $http_response->as_string();
    if ($http_response->code == 200) {
      $test_results[0] = 'ok 1' if $request_path =~ m/\/test\.html$/;
      $test_results[1] = 'ok 2' if $response_string =~ /cgi_field_six/;
      $test_results[2] = 'ok 3' if $response_string =~ /cgi_field_fiv/;
    }
    elsif ($http_response->code == 302) {
      $test_results[3] = 'ok 4' if $response_string =~ /projects\/poe/;
    }
    elsif ($http_response->code == 500) {
      $test_results[5] = 'ok 6' if $response_string =~ /foo\.poe\.perl\.org/;
      $test_results[3] = 'ok 4 # recent Net::SSL required to test https'
        if $response_string =~ /https/;
    }
  }
  else {
    $test_results[4] = 'not ok 5';
  }
}

sub client_got_big_response {
  my ($heap, $request_packet, $response_packet) = @_[HEAP, ARG0, ARG1];
  my $http_request  = $request_packet->[0];
  my $http_response = $response_packet->[0];

  DEBUG and do {
    warn "client got big request...\n";

    my $response_string = $http_response->as_string();
    $response_string =~ s/^/| /mg;

    warn ",", '-' x 78, "\n";
    warn $response_string;
    warn "`", '-' x 78, "\n";
  };

  if ( (defined $http_response->code) and
       ($http_response->code == 200) and
       (length($http_response->content()) == MAX_BIG_REQUEST_SIZE)
     ) {
    $test_results[6] = 'ok 7';
  }
}

my $total_octets_got = 0;
my $chunk_buffer = "";
my $next_chunk_character = "A";
my $test_8_failed = 0;

sub client_got_stream_response {
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
    warn $chunk, "\n";
    warn "`", '-' x 78, "\n";
  };

  return if $test_8_failed;

  if (defined $chunk) {
    $chunk_buffer .= $chunk;
    $total_octets_got += length($chunk);
    while (length($chunk_buffer) >= MAX_STREAM_CHUNK_SIZE) {
      my $next_chunk = substr($chunk_buffer, 0, MAX_STREAM_CHUNK_SIZE);
      substr($chunk_buffer, 0, MAX_STREAM_CHUNK_SIZE) = "";
      $test_8_failed++
        unless( $next_chunk eq
                ($next_chunk_character x MAX_STREAM_CHUNK_SIZE)
              );
      $next_chunk_character++;
    }
  }
  else {
    $test_results[7] = 'ok 8'
      if ( ($total_octets_got == 26 * MAX_STREAM_CHUNK_SIZE)
           and ($next_chunk_character eq "AA")
           and (length($chunk_buffer) == 0)
         );
  }
}

#------------------------------------------------------------------------------

# Create a weeble component.
POE::Component::Client::HTTP->spawn
  ( MaxSize => MAX_BIG_REQUEST_SIZE,
    Timeout => 180,
  );

# Create one for streaming.
POE::Component::Client::HTTP->spawn
  ( Streaming => MAX_STREAM_CHUNK_SIZE,
    Alias     => "streamer",
  );

# Create a session that will make some requests.
POE::Session->create
  ( inline_states =>
    { _start              => \&client_start,
      _stop               => \&client_stop,
      got_response        => \&client_got_response,
      got_big_response    => \&client_got_big_response,
      got_stream_response => \&client_got_stream_response,
    }
  );

# Run it all until done.
$poe_kernel->run();

exit;
