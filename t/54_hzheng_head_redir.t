#! /usr/bin/perl
# $Id$
# vim: filetype=perl

# Test case for POE::Component::Client::HTTP failing to redirect HEAD
# requests.

use strict;
use warnings;

use Test::More tests => 1;
use POE qw(Component::Client::HTTP);
use HTTP::Request::Common qw(HEAD);

POE::Component::Client::HTTP->spawn( Alias => 'ua' );

POE::Session->create(
	inline_states => {
		_start => sub {
			$_[KERNEL]->post(
				ua => request => response => HEAD 'http://google.com/'
			);
		},
		response => sub {
			my $code = $_[ARG1][0]->code();
			ok( $code =~ /^3/, "got response code $code (wanted 3xx)" );
		},
		_stop => sub { },
	}
);

POE::Kernel->run();
exit;
