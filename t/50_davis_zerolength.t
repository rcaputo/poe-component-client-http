#!/usr/bin/perl
# $Id$
# vim: filetype=perl

# Dave Davis' test case for rt.cpan.org ticket #13557:
# "Zero length content header causes request to not post back".

use warnings;
use strict;

use Test::More tests => 2;
use POE qw(Component::Client::HTTP);
use HTTP::Request::Common qw(GET);

POE::Component::Client::HTTP->spawn( Alias => 'ua' );

POE::Session->create(
  inline_states => {
    _start => sub {
      # Fetch a URL that has no content.
      $_[KERNEL]->post(
        'ua', 'request', 'zero_length_response',
        GET 'http://poe.perl.org/misc/no-content.html'
      );

      # Control test: Fetch a URL that has some content.
      $_[KERNEL]->post(
        'ua', 'request', 'nonzero_length_response',
        GET 'http://poe.perl.org/misc/test.html'
      );
    },

    zero_length_response => sub {
      my ($request_packet, $response_packet) = @_[ARG0, ARG1];
      my $request_object  = $request_packet->[0];
      my $response_object = $response_packet->[0];

      $_[HEAP]->{got_zero_length_response} = 1;
    },

    nonzero_length_response => sub {
      my ($request_packet, $response_packet) = @_[ARG0, ARG1];
      my $request_object  = $request_packet->[0];
      my $response_object = $response_packet->[0];

      $_[HEAP]->{got_nonzero_length_response} = 1;
    },

    _stop => sub {
      ok(
        $_[HEAP]->{got_zero_length_response},
        "received zero-length response"
      );

      ok(
        $_[HEAP]->{got_nonzero_length_response},
        "received nonzero-length response"
      );
    },
  },
);

POE::Kernel->run();
exit;
