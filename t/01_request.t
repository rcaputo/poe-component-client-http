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

use Test::More tests => 14;
$| = 1;

my $cm1 = POE::Component::Client::Keepalive->new;
#my $cm2 = POE::Component::Client::Keepalive->new;

my $resp_count = 0;


sub client_start {
  my ($kernel, $heap) = @_[KERNEL, HEAP];

  DEBUG and warn "client starting...\n";

  $kernel->post(
    weeble => request => got_response =>
    GET('http://poe.perl.org/misc/test.html', Connection => 'close'),
  );


  $kernel->post(
    weeble => request => got_response => (
      POST(
        'http://poe.perl.org/misc/test.cgi',
        [
          cgi_field_one => '111',
          cgi_field_two => '222',
          cgi_field_six => '666',
          cgi_field_ten => 'AAA',
        ] # , Connection => 'close',
      ),
    ),
  );

  $kernel->post(
    weeble => request => got_response =>
    GET(
      'http://poe.perl.org/misc/test.cgi?cgi_field_fiv=555',
      Connection => 'close',
    ),
  );


  my $secure_request = GET(
    'https://sourceforge.net/projects/poe/',
    Connection => 'close',
  );
  $kernel->post(
    weeble => request => got_response =>
    $secure_request,
  );

  $kernel->post(
    weeble => request => got_response =>
    GET(
      'http://poe.perl.org',
      Connection => 'close',
    ),
  );

  $kernel->post(
    weeble => request => got_response =>
    GET(
      'http://foo.poe.perl.org/',
      Connection => 'close',
    ),
  );

  $kernel->post(
    weeble => request => got_big_response =>
    GET(
      'http://poe.perl.org/misc/stream-test.cgi',
      Connection => 'close',
    ),
  );

  $kernel->post(
    streamer => request => got_stream_response =>
    GET(
      'http://poe.perl.org/misc/stream-test.cgi',
      Connection => 'close',
    ),
  );

  $kernel->post(
    redirector => request => got_redir_response =>
    GET(
      'http://poe.perl.org/misc/redir-test.cgi',
      Connection => 'close',
    ),
  );
  
  # this uses a call instead of yield
  # so that the error response it propagates
  # is sent before check_counts is called
  $kernel->call(
    weeble => request => got_response =>
    GET( 
      'http:withouthost',
    )
  );

  $kernel->yield( check_counts => 8 );
}


sub client_check_counts {
  my ($kernel, $expected_count) = @_[KERNEL, ARG0, ARG1];

  # a better test would be to also keep track of the responses we are
  # receiving and checking that pending_requests_count decrements properly.
  my $count = $kernel->call( weeble => 'pending_requests_count' ) + $resp_count;
  is ($count, $expected_count, "have enough requests pending");
}

sub client_stop {
  DEBUG and warn "client stopped...\n";
  $cm1->shutdown;
  #  $cm2->shutdown;
  $cm1 = undef;
  #  $cm2 = undef;
}

sub client_got_response {
  my ($heap, $kernel, $request_packet, $response_packet) = @_[
    HEAP, KERNEL, ARG0, ARG1
  ];
  my $http_request  = $request_packet->[0];
  my $http_response = $response_packet->[0];

  ++$resp_count;

  DEBUG and do {
    warn "client got request...\n";

    warn $http_request->as_string;
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
      ok(1, 'request 1') if $request_path =~ m/\/test\.html$/;
      ok(1, 'request 2') if $response_string =~ /cgi_field_six/;
      ok(1, 'request 3') if $response_string =~ /cgi_field_fiv/;
      ok(1, 'request 5') if $request_path eq '';
      ok(1, 'request 4') if $request_path =~ m/projects\/poe/;
    }
    elsif ($http_response->code == 500) {
      like($response_string, qr/foo\.poe\.perl\.org/, 'request 6');
    }
    elsif ($http_response->code == 400) {
      ok("" eq $http_request->uri->host, '400 for malformed request 10');
    }
  }
}

sub client_got_big_response {
  my ($heap, $request_packet, $response_packet) = @_[HEAP, ARG0, ARG1];
  my $http_request  = $request_packet->[0];
  my $http_response = $response_packet->[0];

  ++$resp_count;

  DEBUG and do {
    warn "client got big request...\n";

    my $response_string = $http_response->as_string();
    $response_string =~ s/^/| /mg;

    warn ",", '-' x 78, "\n";
    warn $response_string;
    warn "`", '-' x 78, "\n";
  };

  is ($http_response->code, 200, "got OK response for request 7");
  is (
    length($http_response->content), MAX_BIG_REQUEST_SIZE,
    "content of correct length for request 7"
  );
}

sub client_got_redir_response {
  my ($heap, $request_packet, $response_packet) = @_[HEAP, ARG0, ARG1];
  my $http_request  = $request_packet->[0];
  my $http_response = $response_packet->[0];

  DEBUG and do {
    warn "client got redirected response...\n";

    my $response_string = $http_response->as_string();
    $response_string =~ s/^/| /mg;

    warn ",", '-' x 78, "\n";
    warn $response_string;
    warn "`", '-' x 78, "\n";
  };


  is ($http_response->code, 200, "Got OK response for request 9");
  is (
    $http_response->base, "http://poe.perl.org/misc/test.cgi",
    "response for redirected uri"
  );
  is (
    $http_response->previous->base, "http://poe.perl.org/misc/redir-test.cgi",
    "original request uri matches previous response"
  );
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
    warn ($chunk ? $chunk : "(undef)"), "\n";
    warn "`", '-' x 78, "\n";
  };

  return if $test_8_failed;
  #warn "haven't failed yet";

  if (defined $chunk) {
    $chunk_buffer .= $chunk;
    $total_octets_got += length($chunk);
    while (length($chunk_buffer) >= MAX_STREAM_CHUNK_SIZE) {
      my $next_chunk = substr($chunk_buffer, 0, MAX_STREAM_CHUNK_SIZE);
      substr($chunk_buffer, 0, MAX_STREAM_CHUNK_SIZE) = "";
      $test_8_failed++ unless(
        $next_chunk eq ($next_chunk_character x MAX_STREAM_CHUNK_SIZE)
      );
      $next_chunk_character++;
    }
  }
  else {
    #warn "total: $total_octets_got is ", 26 * MAX_STREAM_CHUNK_SIZE;
    #warn "next: $next_chunk_character";
    #warn "length: ", length($chunk_buffer);
    ok (
      (
        ($total_octets_got == 26 * MAX_STREAM_CHUNK_SIZE)
        and ($next_chunk_character eq "AA")
        and (length($chunk_buffer) == 0)
      ),
      'request 8'
    );
  }
}

#------------------------------------------------------------------------------

# Create a weeble component.
POE::Component::Client::HTTP->spawn(
  MaxSize           => MAX_BIG_REQUEST_SIZE,
  Timeout           => 60,
  Protocol          => 'HTTP/1.1',
  ConnectionManager => $cm1,
);

# Create one for streaming.
POE::Component::Client::HTTP->spawn(
  Streaming         => MAX_STREAM_CHUNK_SIZE,
  Alias             => "streamer",
  ConnectionManager => $cm1,
);

# Create one for redirection.
POE::Component::Client::HTTP->spawn(
  FollowRedirects   => 5,
  Alias             => "redirector",
  Protocol          => 'HTTP/1.1',
  ConnectionManager => $cm1,
);

# Create a session that will make some requests.
POE::Session->create(
  inline_states => {
    _start              => \&client_start,
    _stop               => \&client_stop,
    got_response        => \&client_got_response,
    got_big_response    => \&client_got_big_response,
    got_stream_response => \&client_got_stream_response,
    got_redir_response  => \&client_got_redir_response,
    check_counts        => \&client_check_counts,
  }
);

# Run it all until done.
$poe_kernel->run();

exit;
