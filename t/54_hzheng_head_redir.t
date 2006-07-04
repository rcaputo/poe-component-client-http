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

POE::Component::Client::HTTP->spawn( Alias => 'no_redir' );
POE::Component::Client::HTTP->spawn( Alias => 'redir', FollowRedirects => 5 );

POE::Session->create(
	inline_states => {
		_start => sub {
			$_[KERNEL]->post(
				no_redir => request => manual => HEAD 'http://google.com/'
			);
		},
		manual => sub {
			my $response = $_[ARG1][0];

			my $code = $response->code();

			if ($code =~ /^3/) {
				$_[KERNEL]->post(
					no_redir => request => manual => HEAD $response->header("location")
				);
				return;
			}

			$_[HEAP]->{destination} = $_[ARG0][0]->header("host");

			$_[KERNEL]->post(
				redir => request => automatic => HEAD 'http://google.com/'
			);
		},
		automatic => sub {
			my $rsp = $_[ARG1][0];

			my $code = $rsp->code();
			ok( $code == 200, "got response code $code (wanted 200)" );

			my $rsp_host = $rsp->request->header("host");
			my $exp_host = $_[HEAP]->{destination};
			ok( $rsp_host eq $exp_host, "got response host $rsp_host (expected $exp_host)");
		},
		_stop => sub { },
	}
);

POE::Kernel->run();
exit;
