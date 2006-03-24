#! /usr/bin/perl
# $Id$
# vim: filetype=perl

use strict;
use warnings;

use Test::More tests => 2;
use POE qw(Component::Client::HTTP);
use HTTP::Request::Common qw(GET);

POE::Component::Client::HTTP->spawn( Alias => 'ua' );

POE::Session->create(
	inline_states => {
		_start => sub {
			$_[KERNEL]->post(
				ua => request => response => GET 'http://www.yahoo.com/'
			);
		},
		response => sub {
			my $response = $_[ARG1][0];
			my $code = $response->code();
			ok( $code == 200, "request was successful" );
			ok( length($response->content()), "request has content" );
		},
		_stop => sub { },
	}
);

POE::Kernel->run();
exit;
