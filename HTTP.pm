# $Id$
# License and documentation are after __END__.

package POE::Component::Client::HTTP;

use strict;

sub DEBUG () { 0 };

use vars qw($VERSION);
$VERSION = '0.34';

use Carp qw(croak);
use POSIX;
use HTTP::Response;

use POE qw( Wheel::SocketFactory Wheel::ReadWrite
            Driver::SysRW Filter::Stream
          );

sub REQ_POSTBACK    () { 0 };
sub REQ_WHEEL       () { 1 };
sub REQ_REQUEST     () { 2 };
sub REQ_STATE       () { 3 };
sub REQ_RESPONSE    () { 4 };
sub REQ_BUFFER      () { 5 };
sub REQ_LAST_HEADER () { 6 };
sub REQ_OCTETS_GOT  () { 7 };

sub RS_CONNECT      () { 0x01 };
sub RS_SENDING      () { 0x02 };
sub RS_IN_STATUS    () { 0x04 };
sub RS_IN_HEADERS   () { 0x08 };
sub RS_IN_CONTENT   () { 0x10 };
sub RS_DONE         () { 0x20 };

#------------------------------------------------------------------------------
# Spawn a new PoCo::Client::HTTP session.  This basically is a
# constructor, but it isn't named "new" because it doesn't create a
# usable object.  Instead, it spawns the object off as a separate
# session.

sub spawn {
  my $type = shift;

  croak "$type requires an even number of parameters" if @_ % 2;

  my %params = @_;

  my $alias = delete $params{Alias};
  $alias = 'weeble' unless defined $alias and length $alias;

  my $timeout = delete $params{Timeout};
  $timeout = 180 unless defined $timeout and $timeout >= 0;

  my $agent = delete $params{Agent};
  $agent = sprintf( 'POE-Component-Client-HTTP/%.03f (perl; N; POE; en)',
                    $VERSION,
                  ) unless defined $agent and length $agent;

  my $protocol = delete $params{Protocol};
  $protocol = 'HTTP/1.0' unless defined $protocol and length $protocol;

  my $cookie_jar = delete $params{CookieJar};
  my $from       = delete $params{From};
  my $proxy      = delete $params{Proxy};
  my $no_proxy   = delete $params{NoProxy};

  croak( "$type doesn't know these parameters: ",
         join(', ', sort keys %params)
       ) if scalar keys %params;

  POE::Session->create
    ( inline_states =>
      { _start  => \&poco_weeble_start,
        _stop   => \&poco_weeble_stop,

        # Public interface.
        request => \&poco_weeble_request,

        # SocketFactory interface.
        got_connect_done  => \&poco_weeble_connect_ok,
        got_connect_error => \&poco_weeble_connect_error,

        # ReadWrite interface.
        got_socket_input  => \&poco_weeble_io_read,
        got_socket_flush  => \&poco_weeble_io_flushed,
        got_socket_error  => \&poco_weeble_io_error,

        # I/O timeout.
        got_timeout       => \&poco_weeble_timeout,
      },
      args => [ $alias,      # ARG0
                $timeout,    # ARG1
                $agent,      # ARG2
                $cookie_jar, # ARG3
                $from,       # ARG4
                $proxy,      # ARG5
                $no_proxy,   # ARG6
                $protocol,   # ARG7
              ],
    );

  undef;
}

#------------------------------------------------------------------------------

sub poco_weeble_start {
  my ( $kernel, $heap, $alias, $timeout, $agent, $cookie_jar, $from,
       $proxy, $no_proxy, $protocol
     ) = @_[KERNEL, HEAP, ARG0..ARG7];

  DEBUG and do {
    sub no_undef { (defined $_[0]) ? $_[0] : '(undef)' };
    warn ",--- starting a http client component ----\n";
    warn "| alias     : $alias\n";
    warn "| timeout   : $timeout\n";
    warn "| agent     : $agent\n";
    warn "| protocol  : $protocol\n";
    warn "| cookie_jar: ", &no_undef($cookie_jar), "\n";
    warn "| from      : ", &no_undef($from), "\n";
    warn "| proxy     : ", &no_undef($proxy), "\n";
    warn "| no_proxy  : ", &no_undef($no_proxy), "\n";
    warn "'-----------------------------------------\n";
  };
  
  $heap->{alias}      = $alias;
  $heap->{timeout}    = $timeout;
  $heap->{cookie_jar} = $cookie_jar;
  $heap->{proxy}      = $proxy;
  $heap->{no_proxy}   = $no_proxy;

  $heap->{agent}      = $agent;
  $heap->{from}       = $from;
  $heap->{protocol}   = $protocol;

  $kernel->alias_set($alias);
}

#------------------------------------------------------------------------------

sub poco_weeble_stop {
  my $heap = shift;
  delete $heap->{request};

  DEBUG and warn "weeble stopped.\n";
}

#------------------------------------------------------------------------------

sub poco_weeble_request {
  my ( $kernel, $heap, $sender, $response_event, $http_request
     ) = @_[KERNEL, HEAP, SENDER, ARG0, ARG1];

  # Add a protocol if one isn't included.
  $http_request->protocol( $heap->{protocol} )
    unless ( defined $http_request->protocol()
             and length $http_request->protocol()
           );

  # Add a host header if one isn't included.
  $http_request->header( Host =>
                         $http_request->uri->host . ':' .
                         $http_request->uri->port
                       )
    unless ( defined $http_request->header('Host')
             and length $http_request->header('Host')
           );

  # Add an agent header if one isn't included.
  $http_request->user_agent( $heap->{agent} )
    unless ( defined $http_request->user_agent
             and length $http_request->user_agent
           );

  # Add a from header if one isn't included.
  if (defined $heap->{from} and length $heap->{from}) {
    $http_request->from( $heap->{from} )
      unless ( defined $http_request->from
               and length $http_request->from
             );
  }

  DEBUG and warn "weeble got a request...\n";

  # Get the host and port from the request object.
  my $host = $http_request->uri()->host();
  my $port = $http_request->uri()->port();

  # Create a socket factory.
  my $socket_factory =
    POE::Wheel::SocketFactory->new
      ( RemoteAddress => $host,
        RemotePort    => $port,
        SuccessState  => 'got_connect_done',
        FailureState  => 'got_connect_error',
      );

  # Record information about the request; key it on the socket
  # factory's unique ID so we can match resulting events back to the
  # proper request record.
  $heap->{request}->{$socket_factory->ID} =
    [ $sender->postback( $response_event, $http_request ), # REQ_POSTBACK
      $socket_factory,                                     # REQ_WHEEL
      $http_request,                                       # REQ_REQUEST
      RS_CONNECT,                                          # REQ_STATE
      undef,                                               # REQ_RESPONSE
      '',                                                  # REQ_BUFFER
      '',                                                  # REQ_LAST_HEADER
      0,                                                   # REQ_OCTETS_GOT
    ];

  DEBUG and
    warn( "wheel ", $socket_factory->ID,
          " is connecting to $host : $port ...\n"
        );
}

#------------------------------------------------------------------------------

sub poco_weeble_connect_ok {
  my ($heap, $socket, $wheel_id) = @_[HEAP, ARG0, ARG3];

  DEBUG and warn "wheel $wheel_id connected ok...\n";

  # We'll be replacing the SocketFactory wheel with a ReadWrite wheel,
  # which will have a new ID.  Remove the request from the old ID.
  my $request = delete $heap->{request}->{$wheel_id};

  # Clear the old wheel, then create the new one.  It's important to
  # do this in this particular order.
  $request->[REQ_WHEEL] = undef;
  $request->[REQ_WHEEL] =
    POE::Wheel::ReadWrite->new
      ( Handle       => $socket,
        Driver       => POE::Driver::SysRW->new(),
        Filter       => POE::Filter::Stream->new(),
        InputState   => 'got_socket_input',
        FlushedState => 'got_socket_flush',
        ErrorState   => 'got_socket_error',
      );

  # Enter the request under the new wheel ID.
  $heap->{request}->{$request->[REQ_WHEEL]->ID} = $request;

  # We're now in a sending state.
  $heap->{request}->{$request->[REQ_WHEEL]->ID}->[REQ_STATE] = RS_SENDING;

  # Put the request.  HTTP::Request's as_string() method isn't quite
  # right.  It uses the full URL on the request line, so we have to
  # put the request in pieces.

  my $http_request = $request->[REQ_REQUEST];
  my $request_string =
    ( $http_request->method() . ' ' .
      $http_request->uri()->path() . ' ' .
      $http_request->protocol() . "\x0D\x0A" .
      $http_request->headers_as_string("\x0D\x0A") . "\x0D\x0A" .
      $http_request->content() # . "\x0D\x0A"
    );

  DEBUG and do {
    my $formatted_request_string = $request_string;
    $formatted_request_string =~ s/([^\n])$/$1\n/;
    $formatted_request_string =~ s/^/| /mg;
    print ",----- SENDING REQUEST ", '-' x 56, "\n";
    print $formatted_request_string;
    print "`", '-' x 78, "\n";
  };

  $request->[REQ_WHEEL]->put( $request_string );
}

#------------------------------------------------------------------------------

sub poco_weeble_connect_error {
  my ($heap, $operation, $errnum, $errstr, $wheel_id) = @_[HEAP, ARG0..ARG3];

  DEBUG and
    warn "wheel $wheel_id encountered $operation error $errnum: $errstr\n";

  # Drop the wheel.
  my $request = delete $heap->{request}->{$wheel_id};

  # Post an error response back to the requesting session.
  $request->[REQ_POSTBACK]->
    ( HTTP::Response->new( 400, "$operation error $errnum: $errstr" )
    );
}

#------------------------------------------------------------------------------

sub poco_weeble_io_flushed {
  my ($heap, $wheel_id) = @_[HEAP, ARG0];

  DEBUG and warn "wheel $wheel_id flushed its request...\n";

  # We sent the request.  Now we're looking for a response.  It may be
  # bad to assume we won't get a response until a request has flushed.
  $heap->{request}->{$wheel_id}->[REQ_STATE] = RS_IN_STATUS;
}

#------------------------------------------------------------------------------

sub poco_weeble_io_error {
  my ($heap, $operation, $errnum, $errstr, $wheel_id) = @_[HEAP, ARG0..ARG3];

  DEBUG and
    warn "wheel $wheel_id encountered $operation error $errnum: $errstr\n";

  # Drop the wheel.
  my $request = delete $heap->{request}->{$wheel_id};

  # If there was a non-zero error, then something bad happened.  Post
  # an error response back.
  if ($errnum) {
    $request->[REQ_POSTBACK]->
      ( HTTP::Response->new( 400, "$operation error $errnum: $errstr" )
      );
    return;
  }

  # Otherwise the remote end simply closed.  If we've built a
  # response, then post it back.
  if ($request->[REQ_STATE] & (RS_IN_CONTENT | RS_DONE)) {
    $request->[REQ_POSTBACK]->($request->[REQ_RESPONSE]);
    return;
  }

  # We haven't built a proper response.  Send back an error.
  $request->[REQ_POSTBACK]->
    ( HTTP::Response->new( 400, "incomplete response" )
    );
}

#------------------------------------------------------------------------------
# Read a chunk of response.  This code is directly adapted from Artur
# Bergman's nifty POE::Filter::HTTPD, which does pretty much the same
# in the other direction.

sub poco_weeble_io_read {
  my ($heap, $input, $wheel_id) = @_[HEAP, ARG0, ARG1];
  my $request = $heap->{request}->{$wheel_id};

  DEBUG and warn "wheel $wheel_id got input...\n";

  # Aggregate the new input.
  $request->[REQ_BUFFER] .= $input;

  # The very first line ought to be status.  If it's not, then it's
  # part of the content.
  if ($request->[REQ_STATE] & RS_IN_STATUS) {
    # Parse a status line. -><- Assumes proper network newlines. -><-
    # What happens if someone puts bogus headers in the content?
    if ( $request->[REQ_BUFFER] =~
         s/^(HTTP\/[0-9\.]+)\s*(\d+)\s*(.*?)\x0D\x0A//
       ) {
      DEBUG and
        warn "wheel $wheel_id got a status line... moving to headers.\n";

      $request->[REQ_RESPONSE] = HTTP::Response->new( $2, $3 );
      $request->[REQ_RESPONSE]->protocol( $1 );
      $request->[REQ_STATE] = RS_IN_HEADERS;
    }

    # No status line.  We go straight into content.  Since we don't
    # know the status, we don't purport to.
    else {
      DEBUG and warn "wheel $wheel_id got no status... moving to content.\n";

      $request->[REQ_RESPONSE] = HTTP::Response->new();
      $request->[REQ_STATE] = RS_IN_CONTENT;
    }
  }

  # Parse the input for headers.  This isn't in an else clause because
  # we may go from status to content in the same read.
  if ($request->[REQ_STATE] & RS_IN_HEADERS) {
    # Parse it by lines. -><- Assumes proper network newlines.
HEADER:
    while ($request->[REQ_BUFFER] =~ s/^(.*?)\x0D\x0A//) {
      # This line means something.
      if (length $1) {
        my $line = $1;

        # New header.
        if ($line =~ /^([\w\-]+)\s*\:\s*(.+)\s*$/) {
          DEBUG and warn "wheel $wheel_id got a new header: $1 ...\n";

          $request->[REQ_LAST_HEADER] = $1;
          $request->[REQ_RESPONSE]->push_header($1, $2);
        }

        # Continued header.
        elsif ($line =~ /^\s+(.+?)\s*$/) {
          DEBUG and
            warn( "wheel $wheel_id got a continuation for header ",
                  $request->[REQ_LAST_HEADER],
                  " ...\n"
                );

          $request->[REQ_RESPONSE]->push_header
            ( $request->[REQ_LAST_HEADER], $1
            );
        }

        # Dunno what.
        else {
          # -><- bad request?
          DEBUG and warn "wheel $wheel_id got strange header line: <$line>";
        }
      }

      # This line is empty; we eat it and switch to RS_GET_CONTENT.
      else {
        DEBUG and
          warn "wheel $wheel_id got a blank line... moving to content.\n";

        $request->[REQ_STATE] = RS_IN_CONTENT;
        last HEADER;
      }
    }
  }

  # We're in a content state.  This isn't an else clause because we
  # may go from header to content in the same read.
  if ($request->[REQ_STATE] & RS_IN_CONTENT) {

    # Count how many octets we've received.
    my $this_chunk_length = length($request->[REQ_BUFFER]);
    $request->[REQ_OCTETS_GOT] += $this_chunk_length;

    # Add the new octets to the response's content.  -><- This should
    # only add up to content-length.
    $request->[REQ_RESPONSE]->add_content( $request->[REQ_BUFFER] );
    $request->[REQ_BUFFER] = '';

    DEBUG and do {
      warn "wheel $wheel_id got $this_chunk_length octets of content...\n";
      warn( "wheel $wheel_id has $request->[REQ_OCTETS_GOT]",
            ( $request->[REQ_RESPONSE]->content_length()
              ? ( " out of " . $request->[REQ_RESPONSE]->content_length() )
              : ""
            ),
            " octets\n"
          );
    };

    # Stop reading when we have enough content.  -><- Should never be
    # greater than our content length.
    if ( $request->[REQ_RESPONSE]->content_length()
         and ( $request->[REQ_OCTETS_GOT] >=
               $request->[REQ_RESPONSE]->content_length()
             )
       )
    {
      DEBUG and
        warn "wheel $wheel_id has a full response... moving to done.\n";

      $request->[REQ_STATE] = RS_DONE;

      # -><- This assumes the server will now disconnect.  That will
      # give us an error 0 (socket's closed), and we will post the
      # response.
    }
  }
}

1;

__END__

=head1 NAME

POE::Component::Client::HTTP - a HTTP user-agent component

=head1 SYNOPSIS

  use POE qw(Component::Client::HTTP);

  POE::Component::Client::HTTP->spawn(
    Agent    => 'SpiffCrawler/0.90',    # defaults to something long
    Alias    => 'ua',                   # defaults to 'weeble'
    From     => 'spiffster@perl.org',   # defaults to undef (no header)
    Protocol => 'HTTP/0.9',             # defaults to 'HTTP/1.0'
    Timeout  => 60,                     # defaults to 180 seconds
  );

  $kernel->post( 'ua',        # posts to the 'ua' alias
                 'request',   # posts to ua's 'request' state
                 'response',  # which of our states will receive the response
                 $request,    # an HTTP::Request object
               );

  # This is the sub which is called when the session receives a
  # 'response' event.
  sub response_handler {
    my ($request_packet, $response_packet) = @_[ARG0, ARG1];
    my $request_object  = $request_packet->[0];  # HTTP::Request
    my $response_object = $response_packet->[0]; # HTTP::Response

    print "*" x 78, "\n";
    print "*** my request:\n";
    print "-' x 78, "\n";
    print $request_object->as_string();
    print "*" x 78, "\n";

    print "*" x 78, "\n";
    print "*** their response:\n";
    print "-' x 78, "\n";
    print $request_object->as_string();
    print "*" x 78, "\n";
  }

=head1 DESCRIPTION

POE::Component::Client::HTTP is an HTTP user-agent for POE.  It lets
other sessions run while HTTP transactions are being processed, and it
lets several HTTP transactions be processed in parallel.

HTTP client components are not proper objects.  Instead of being
created, as most objects are, they are "spawned" as separate sessions.
To avoid confusion (and hopefully not cause other confusion), they
must be spawned with a C<spawn> method, not created anew with a C<new>
one.

PoCo::Client::HTTP's C<spawn> method takes a few named parameters:

=over 2

=item Agent => $user_agent_string

C<Agent> defines the string that identifies the component to other
servers.  $user_agent_string is "POE-Component-Client-HTTP/$VERSION",
by default.  You may want to change this to help identify your own
programs instead.

=item Alias => $session_alias

C<Alias> sets the name by which the session will be known.  If no
alias is given, the component defaults to "weeble".  The alias lets
several sessions interact with HTTP components without keeping (or
even knowing) hard references to them.  It's possible to spawn several
HTTP components with different names.

=item From => $admin_address

C<From> holds an e-mail address where the client's administrator
and/or maintainer may be reached.  It defaults to undef, which means
no From header will be included in requests.

=item Protocol => $http_protocol_string

C<Protocol> advertises the protocol that the client wishes to see.
Under normal circumstances, it should be left to its default value:
"HTTP/1.0".

=item Timeout => $query_timeout

C<Timeout> specifies the amount of time a HTTP request will wait for
an answer.  This defaults to 180 seconds (three minutes).

=back

Sessions communicate asynchronously with PoCo::Client::HTTP.  They
post requests to it, and it posts responses back.

Requests are posted to the component's "request" state.  They include
an HTTP::Request object which defines the request.  For example:

  $kernel->post( 'ua', 'request',           # http session alias & state
                 'response',                # my state to receive responses
                 GET 'http://poe.perl.org', # a simple HTTP request
               );

Requests include the state to which responses will be posted.  In the
previous example, the handler for a 'response' state will be called
with each HTTP response.

HTTP responses come with two list references:

  my ($request_packet, $response_packet) = @_[ARG0, ARG1];

C<$request_packet> contains a reference to the original HTTP::Request
object.  This is useful for matching responses back to the requests
that generated them.

  my $http_request_object = $request_packet->[0];

C<$response_packet> contains a reference to the resulting
HTTP::Response object.

  my $http_response_object = $response_packet->[0];

Please see the HTTP::Request and HTTP::Response manpages for more
information.

=head1 SEE ALSO

This component is built upon HTTP::Request, HTTP::Response, and POE.
Please see its source code and the documentation for its foundation
modules to learn more.

Also see the test program, t/01_request.t, in the PoCo::Client::HTTP
distribution.

=head1 BUGS

HTTP/1.1 requests are not supported.

The following spawn() parameters are accepted but not yet implemented:
Timeout, CookieJar, Proxy, NoProxy.

=head1 AUTHOR & COPYRIGHTS

POE::Component::Client::HTTP is Copyright 1999-2000 by Rocco Caputo.
All rights are reserved.  POE::Component::Client::HTTP is free
software; you may redistribute it and/or modify it under the same
terms as Perl itself.

=cut
