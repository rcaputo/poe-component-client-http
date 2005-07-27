#!/usr/bin/perl

# There are cases where POE::Component::Client::HTTP generates no
# responses.  This exercises some of them.

use warnings;
use strict;

use IO::Socket::INET;
use Socket '$CRLF';
use HTTP::Request::Common 'GET';

# The number of tests must match scalar(@responses).
use Test::More tests => 2;

use POE;
use POE::Component::Client::HTTP;
use POE::Component::Server::TCP;

my @server_ports;

my @responses = (
	# Content-Length > length of actual content.
	(
		"HTTP/1.1 200 OK$CRLF" .
		"Connection: close$CRLF" .
		"Content-Length: 8$CRLF" .
		"Content-type: text/plain$CRLF" .
		$CRLF .
		"Content"
	),
	# No Content-Length header at all.
	(
		"HTTP/1.1 200 OK$CRLF" .
		"Connection: close$CRLF" .
		"Content-type: text/plain$CRLF" .
		$CRLF .
		"Content"
	),
);

# Spawn one server per test response.
{
	foreach (@responses) {
		POE::Component::Server::TCP->new(
			Address             => "127.0.0.1",
			Port                => 0,
			Started             => \&register_port,
			ClientInputFilter   => "POE::Filter::Line",
			ClientOutputFilter  => "POE::Filter::Stream",
			ClientInput         => \&parse_next_request,
		);
	}

	sub register_port {
		push(
			@server_ports,
			(sockaddr_in($_[HEAP]->{listener}->getsockname()))[0]
		);
	}

	sub parse_next_request {
		my $input = $_[ARG0];

		diag "got line: [$input]";
		return if $input ne "";

		my $response = pop @responses;
		$_[HEAP]->{client}->put($response);

		$response =~ s/$CRLF/{CRLF}/g;
		diag "sending: [$response]";

		$_[KERNEL]->yield("shutdown");
	}
}

# Spawn the HTTP user-agent component.
POE::Component::Client::HTTP->spawn();

# Create a client session to drive the HTTP component.
POE::Session->create(
	inline_states => {
		_start => sub {
			foreach my $port (@server_ports) {
				$_[KERNEL]->post(
					weeble => request => response =>
					GET "http://127.0.0.1:${port}/"
				);
			}
		},
		response => sub {
			pass(
				"got a response, content = (" .$_[ARG1]->[0]->content() . ")"
			);
		},
		_stop => sub { exit },  # Nasty but expedient.
	}
);

POE::Kernel->run();
exit;
