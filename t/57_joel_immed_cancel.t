#!perl
# $Id$

use strict;
use warnings;
use HTTP::Request;
use Test::More tests => 2;

use POE qw(Component::Client::HTTP);

POE::Component::Client::HTTP->spawn( Alias => 'ua' );

POE::Session->create(
  inline_states => {
    _start   => \&client_start,
    response => \&response_handler,
  }
);

POE::Kernel->run();
pass("nothing died");
exit;

sub client_start {
  my $request = HTTP::Request->new('GET', "http://www.google.com/");
  $_[KERNEL]->post( ua => request => response => $request );
  $_[KERNEL]->post( ua => cancel => $request );
}


sub response_handler {
  my $response = $_[ARG1][0];
  is( $response->code, 408, "timeout on a canceled request" );
  $_[KERNEL]->post( ua => "shutdown" );
}
