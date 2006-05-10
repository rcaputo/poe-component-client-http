#!/usr/bin/perl
# vim: filetype=perl

# This tests cases where a socket it reused in spite of
# the entire response not having been read off the socket.

use warnings;
use strict;

use IO::Socket::INET;
use Socket '$CRLF';
use HTTP::Request::Common 'GET';

sub POE_ASSERT_DEFAULT () { 1 }
sub DEBUG () { 0 }

use Test::More tests => 9;

use POE;
use POE::Component::Client::HTTP;
use POE::Component::Server::TCP;

my $port;

my @responses;

my @cases = (
    [ 
      1,
      sub { [
        "HTTP/1.1 302 Moved$CRLF" .
        "Location: http://127.0.0.1:${port}/stuff$CRLF" .
        "Connection: close$CRLF" .
        "Content-type: text/plain$CRLF" . $CRLF .
        "Line 1 of the redirect",
        "Line 2 of the redirect",
        "Line 3 of the redirect",
        "", # keep the connection open, maybe
        "",
        "",
        "",
      ] },
    ],
    [ 
      2, 
      sub { [
        "HTTP/1.1 200 OK$CRLF" .
        "Connection: close$CRLF" .
        "Content-type: text/plain$CRLF$CRLF" .
        ( "Too Much" x 64 ),
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "should not appear",
        "should not appear",
        "should not appear",
        "should not appear",
        "should not appear"
      ] },
    ]  
);

my $case = shift @cases;
spawn_server();

sub set_responses {
  @responses = $case->[1]->();
}

my $server_alias;
sub spawn_server {
  $server_alias = "server$case";
  POE::Component::Server::TCP->new(
    Alias               => $server_alias,
    Address             => "127.0.0.1",
    Port                => 0,
    Started             => \&register_port,
    ClientConnected     => \&connected,
    ClientInputFilter   => "POE::Filter::Line",
    ClientOutputFilter  => "POE::Filter::Stream",
    ClientInput         => \&parse_next_request,
    Concurrency         => 1,
    InlineStates => {
      next_part => \&next_part
    },
  );
}
  
  sub connected {
    DEBUG and diag "new connection";
    $_[KERNEL]->post( $server_alias => 'shutdown' );
  }

  sub register_port {
    $port = (sockaddr_in($_[HEAP]->{listener}->getsockname()))[0];
    set_responses();
  }

  sub next_part {
    my $left = $_[ARG0];
    my $next = shift @$left;

    if (!$_[HEAP]->{client}) {
        $_[KERNEL]->yield('shutdown');
        return;
    }

    $_[HEAP]->{client}->put($next);

    $next =~ s/$CRLF/{CRLF}/g;

    DEBUG and warn "sent [$next]\n";
    
    if (@$left) {  
        $_[KERNEL]->delay(next_part => 0.1 => $left);
    } else {
        $_[KERNEL]->yield('shutdown');
    }
  }

  sub parse_next_request {
    my $input = $_[ARG0];

    DEBUG and diag "got line: [$input]";
    return if $input ne "";

    if (!$_[HEAP]->{in_progress}++) {
      my $response = pop @responses;
      $_[KERNEL]->yield(next_part => [ @$response ]);
    }
  }


# Spawn the HTTP user-agent component.
POE::Component::Client::HTTP->spawn(
    FollowRedirects => 3,
    MaxSize => 512,
);

# Create a client session to drive the HTTP component.
POE::Session->create(
  inline_states => {
    _start => sub { 
      $_[KERNEL]->call($_[SESSION] => 'begin');
    },
    begin => sub {
      $_[KERNEL]->post(
        weeble => request => response =>
        GET "http://127.0.0.1:${port}/"
      );
    },
    response => sub {
      my $response = $_[ARG1][0];
      my $content = $response->content();

      $content =~ s/\x0D/{CR}/g;
      $content =~ s/\x0A/{LF}/g;

      pass "got a response, content = ($content)";

      ok(defined $response->request, "response has corresponding request object set");

      if ($case->[0] == 1) {
        # last response should be non-OK in each set
        ok($response->code != 200, "response status is _not_ OK");
      } else {
        ok($response->code == 200, "response status is OK");
      }

      if (--$case->[0]) {
        DEBUG and diag "request left in this set";
        $_[KERNEL]->delay('begin' => 0.6);
      } elsif (@cases) {
        $case = shift @cases;
        spawn_server();
        $_[KERNEL]->yield('begin');
      }
    },
    _stop => sub { exit },  # Nasty but expedient.
  }
);

POE::Kernel->run();
exit;
