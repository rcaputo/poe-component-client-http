#! /usr/bin/perl
# $Id$
# vim: filetype=perl

# Test case for POE::Component::Client::HTTP failing to redirect HEAD
# requests.

use strict;
use warnings;

use Test::More tests => 2;
use POE qw(Component::Client::HTTP);
use HTTP::Request::Common qw(HEAD);

POE::Component::Client::HTTP->spawn( Alias => 'ua' );

POE::Session->create(
	inline_states => {
		_start => sub {
			$_[KERNEL]->post(
				ua => request => first_response => HEAD 'http://google.com/'
			);
		},
		first_response => sub {
			my $code = $_[ARG1][0]->code();
			ok( $code =~ /^3/, "got first response code $code (wanted 3xx)" );

			$_[KERNEL]->post(
				ua => request => second_response => HEAD 'http://www.google.com/'
			);
		},
		second_response => sub {
			my $code = $_[ARG1][0]->code();
			ok( $code == 200, "got second response code $code (wanted 200)" );
		},
		_stop => sub { },
	}
);

POE::Kernel->run();
exit;
