#!/usr/bin/perl -w
# $Id$

use strict;

use HTTP::Request::Common qw(GET POST);

use lib '/home/troc/perl/poe';
sub POE::Kernel::ASSERT_DEFAULT () { 1 }
use POE qw(Component::Client::HTTP);

sub DEBUG () { 0 };

$| = 1;
print "1..2\n";

my @test_results = ( 'not ok 1', 'not ok 2' );

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

    print ",", '-' x 78, "\n";
    print $response_string;
    print "`", '-' x 78, "\n";
  };

  my $request_path = $http_request->uri->path . ''; # stringify

  if ($http_response->code == 200) {
    $test_results[0] = 'ok 1' if $request_path =~ m/\/test\.html$/;
    $test_results[1] = 'ok 2' if $request_path =~ m/\/test\.cgi$/;
  }
}

#------------------------------------------------------------------------------

# Create a weeble component.
POE::Component::Client::HTTP->spawn();

# Create a session that will make some requests.
POE::Session->create
  ( inline_states =>
    { _start       => \&client_start,
      _stop        => \&client_stop,
      got_response => \&client_got_response,
    }
  );

# Run it all until done.
$poe_kernel->run();

exit;
